"""Brainstorm spec parsing and coverage tracking primitives.

This module owns the shared parser, validation, canonical brainstorm agent
intents, and append-only JSONL coverage helpers used by Bug Bounty Harness and
other bounty tooling. Team-specific adapters live outside this file.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:  # pragma: no cover - exercised implicitly on POSIX CI/dev hosts.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback.
    fcntl = None  # type: ignore[assignment]


VALID_HYPOTHESIS_STATUSES = {"untested", "queued", "running", "tested", "blocked", "retired"}
VALID_PRIORITIES = {"critical", "high", "medium", "low"}

COVERAGE_STATUSES = {
    "untested",
    "queued",
    "running",
    "raw_finding_pending",
    "tested_no_finding",
    "tested_finding",
    "blocked",
    "retired",
}
COVERAGE_OUTCOMES = {
    "no_finding",
    "raw_finding",
    "raw_finding_pending",
    "timeout",
    "crash",
    "invalid_output",
    "duplicate_only",
    "review_rejected",
    "review_promoted",
}
COVERAGE_EVENTS = {
    "hypothesis_loaded",
    "agent_queued",
    "agent_spawned",
    "agent_completed_no_finding",
    "agent_completed_with_raw_findings",
    "agent_timeout",
    "agent_crashed",
    "agent_invalid_output",
    "agent_duplicate_only",
    "review_rejected",
    "review_promoted",
    "coverage_status_changed",
    # Backward-compatible event from the initial draft examples.
    "agent_completed",
}
MAX_SUGGESTED_AGENT_KEY_LENGTH = 64

_SECTION_RE = re.compile(r"^(#{2})\s+(.+?)\s*$")
_BLOCK_HEADING_RE = re.compile(r"^###\s+([A-Za-z]\d+)\s*(?:[-\u2013\u2014]\s*)?(.+?)\s*$")
_BULLET_FIELD_RE = re.compile(r"^-\s+([^:\n]+):\s*(.*)$")
_BULLET_ITEM_RE = re.compile(r"^\s{2,}-\s+(.+?)\s*$")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SUGGESTED_AGENT_KEY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$")


class BrainstormSpecError(ValueError):
    """Raised when a brainstorm markdown spec is malformed or unsafe to use."""


@dataclass
class BrainstormHypothesis:
    id: str
    title: str
    status: str
    priority: str
    surface: str
    entry_point: str
    expected_chain: str
    suggested_agents: list[str]
    focus_files_glob: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    freeform_text: str = ""
    extra_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class BrainstormAgentIntent:
    hypothesis_id: str
    hypothesis_title: str
    agent_key: str
    name: str
    description: str
    surface: str
    vuln_class: str
    priority: str
    expected_chain: str
    focus_files_glob: list[str]
    ignore_files_glob: list[str]
    tags: list[str]
    evidence: list[str]
    prompt_context: str
    source_spec_path: Path

    def finding_metadata(self) -> dict[str, Any]:
        return {
            "brainstorm_spec": str(self.source_spec_path),
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_title": self.hypothesis_title,
            "brainstorm_agent_key": self.agent_key,
            "brainstorm_surface": self.surface,
            "brainstorm_tags": list(self.tags),
        }


@dataclass
class BrainstormSpec:
    path: Path
    metadata: dict[str, str]
    mental_model: str
    impact_primitives: list[dict[str, str]]
    hypotheses: list[BrainstormHypothesis]


def parse_brainstorm_spec(
    path: str | Path,
    *,
    validate_paths: bool = True,
) -> BrainstormSpec:
    spec_path = Path(path).expanduser().resolve(strict=False)
    text = spec_path.read_text(encoding="utf-8")
    sections = _split_sections(text)

    metadata = _parse_metadata(sections.get("metadata", []))
    mental_model = _plain_section_text(sections.get("target mental model", []))
    impact_primitives = _parse_impact_primitives(sections.get("impact primitives", []))
    hypotheses = _parse_hypotheses(sections.get("hypotheses", []))

    spec = BrainstormSpec(
        path=spec_path,
        metadata=metadata,
        mental_model=mental_model,
        impact_primitives=impact_primitives,
        hypotheses=hypotheses,
    )
    validate_brainstorm_spec(spec, validate_paths=validate_paths)
    return spec


def validate_brainstorm_spec(
    spec: BrainstormSpec,
    *,
    validate_paths: bool = True,
) -> None:
    if not spec.hypotheses:
        raise BrainstormSpecError("brainstorm spec must contain at least one hypothesis")

    seen_ids: set[str] = set()
    active_agent_keys: dict[str, str] = {}
    required_fields = {
        "status",
        "priority",
        "surface",
        "entry_point",
        "expected_chain",
        "suggested_agents",
        "tags",
    }

    for hypothesis in spec.hypotheses:
        if hypothesis.id in seen_ids:
            raise BrainstormSpecError(f"duplicate hypothesis id: {hypothesis.id}")
        seen_ids.add(hypothesis.id)

        values = {
            "status": hypothesis.status,
            "priority": hypothesis.priority,
            "surface": hypothesis.surface,
            "entry_point": hypothesis.entry_point,
            "expected_chain": hypothesis.expected_chain,
            "suggested_agents": hypothesis.suggested_agents,
            "tags": hypothesis.tags,
        }
        missing = [
            name
            for name in sorted(required_fields)
            if not values[name] or values[name] == []
        ]
        if missing:
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} missing required field(s): {', '.join(missing)}"
            )
        if hypothesis.status not in VALID_HYPOTHESIS_STATUSES:
            expected = ", ".join(sorted(VALID_HYPOTHESIS_STATUSES))
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} has invalid status {hypothesis.status!r}; "
                f"expected one of: {expected}"
            )
        if hypothesis.priority not in VALID_PRIORITIES:
            expected = ", ".join(sorted(VALID_PRIORITIES))
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} has invalid priority {hypothesis.priority!r}; "
                f"expected one of: {expected}"
            )

        local_agent_keys: dict[str, str] = {}
        for agent_key in hypothesis.suggested_agents:
            normalized_agent_key = _validate_suggested_agent_key(agent_key, hypothesis.id)
            previous_local_key = local_agent_keys.get(normalized_agent_key)
            if previous_local_key is not None:
                raise BrainstormSpecError(
                    "duplicate suggested agent key "
                    f"{agent_key!r} conflicts with {previous_local_key!r} "
                    f"in hypothesis {hypothesis.id}"
                )
            local_agent_keys[normalized_agent_key] = agent_key

            if hypothesis.status == "retired":
                continue

            previous_id = active_agent_keys.get(normalized_agent_key)
            if previous_id and previous_id != hypothesis.id:
                raise BrainstormSpecError(
                    "duplicate suggested agent key "
                    f"{agent_key!r} across active hypotheses {previous_id} and {hypothesis.id}"
                )
            active_agent_keys[normalized_agent_key] = hypothesis.id

    if validate_paths:
        _validate_spec_paths(spec)


def hypothesis_to_agent_intents(
    spec: BrainstormSpec,
    hypothesis: BrainstormHypothesis,
    *,
    ignore_files_glob: list[str] | None = None,
) -> list[BrainstormAgentIntent]:
    ignore_globs = list(ignore_files_glob or ["**/*.map", "**/node_modules/**"])
    vuln_class = _infer_vuln_class(hypothesis.tags)
    context = _build_prompt_context(spec, hypothesis)

    intents: list[BrainstormAgentIntent] = []
    for agent_key in hypothesis.suggested_agents:
        name = _agent_name(agent_key)
        intents.append(
            BrainstormAgentIntent(
                hypothesis_id=hypothesis.id,
                hypothesis_title=hypothesis.title,
                agent_key=agent_key,
                name=name,
                description=(
                    f"Tests {hypothesis.id} from the brainstorm spec: {hypothesis.title}"
                ),
                surface=hypothesis.surface,
                vuln_class=vuln_class,
                priority=hypothesis.priority,
                expected_chain=hypothesis.expected_chain,
                focus_files_glob=list(hypothesis.focus_files_glob),
                ignore_files_glob=list(ignore_globs),
                tags=list(hypothesis.tags),
                evidence=list(hypothesis.evidence),
                prompt_context=context,
                source_spec_path=spec.path,
            )
        )
    return intents


def spec_to_agent_intents(
    spec: BrainstormSpec,
    *,
    statuses: set[str] | None = None,
) -> list[BrainstormAgentIntent]:
    selected_statuses = statuses or {"untested", "queued", "running"}
    intents: list[BrainstormAgentIntent] = []
    for hypothesis in spec.hypotheses:
        if hypothesis.status in selected_statuses:
            intents.extend(hypothesis_to_agent_intents(spec, hypothesis))
    return intents


def unresolved_hypotheses(spec: BrainstormSpec) -> list[BrainstormHypothesis]:
    return [
        hypothesis
        for hypothesis in spec.hypotheses
        if hypothesis.status in {"untested", "queued", "running", "blocked"}
    ]


def append_coverage(path: str | Path, event: dict[str, Any]) -> None:
    if not isinstance(event, dict):
        raise TypeError("coverage event must be a dict")
    _validate_coverage_event(event)

    coverage_path = Path(path).expanduser().resolve(strict=False)
    coverage_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(event)
    payload.setdefault("recorded_at", _timestamp_iso())

    with _locked_append_handle(coverage_path) as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()


def summarize_coverage(
    path: str | Path,
    *,
    spec: BrainstormSpec | None = None,
) -> dict[str, Any]:
    hypotheses: dict[str, dict[str, Any]] = {}
    if spec is not None:
        for hypothesis in spec.hypotheses:
            hypotheses[hypothesis.id] = _new_hypothesis_summary(
                status=_markdown_status_to_coverage_status(hypothesis.status),
                title=hypothesis.title,
            )

    invalid_lines = 0
    for event in _read_coverage_events(path):
        if event.get("_invalid_json"):
            invalid_lines += 1
            continue
        hypothesis_id = str(event.get("hypothesis_id") or "").strip()
        if not hypothesis_id:
            continue
        summary = hypotheses.setdefault(hypothesis_id, _new_hypothesis_summary())
        _apply_coverage_event(summary, event)

    for summary in hypotheses.values():
        _reconcile_hypothesis_status(summary)

    status_counts = Counter(
        summary["status"]
        for summary in hypotheses.values()
        if summary["status"] in COVERAGE_STATUSES
    )
    outcome_counts: Counter[str] = Counter()
    for summary in hypotheses.values():
        outcome_counts.update(summary["outcomes"])
        invalid_lines += int(summary.pop("_invalid_lines", 0))
        summary["outcomes"] = dict(summary["outcomes"])
        for agent in summary["agents"].values():
            agent["outcomes"] = dict(agent["outcomes"])

    return {
        "hypotheses": hypotheses,
        "counts_by_status": dict(status_counts),
        "counts_by_outcome": dict(outcome_counts),
        "invalid_line_count": invalid_lines,
    }


class BrainstormSpecStore:
    """Small facade matching the proposed shared-module API."""

    @staticmethod
    def load(path: str | Path) -> BrainstormSpec:
        return parse_brainstorm_spec(path)

    @staticmethod
    def generate_agent_intents(
        spec: BrainstormSpec,
        *,
        statuses: set[str] | None = None,
    ) -> list[BrainstormAgentIntent]:
        return spec_to_agent_intents(spec, statuses=statuses)

    @staticmethod
    def append_coverage(path: str | Path, event: dict[str, Any]) -> None:
        append_coverage(path, event)

    @staticmethod
    def coverage_summary(
        path: str | Path,
        *,
        spec: BrainstormSpec | None = None,
    ) -> dict[str, Any]:
        return summarize_coverage(path, spec=spec)

    @staticmethod
    def unresolved_hypotheses(spec: BrainstormSpec) -> list[BrainstormHypothesis]:
        return unresolved_hypotheses(spec)


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = _SECTION_RE.match(line)
        if match:
            current = match.group(2).strip().lower()
            sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)
    return sections


def _parse_metadata(lines: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in lines:
        match = _BULLET_FIELD_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        metadata[key] = _strip_inline_code(value)
    return metadata


def _plain_section_text(lines: list[str]) -> str:
    content: list[str] = []
    for line in lines:
        if line.startswith("### "):
            break
        content.append(line.rstrip())
    return "\n".join(content).strip()


def _parse_impact_primitives(lines: list[str]) -> list[dict[str, str]]:
    blocks = _split_subheading_blocks(lines)
    primitives: list[dict[str, str]] = []
    for primitive_id, title, body in blocks:
        fields = _parse_bullet_fields(body)
        primitive: dict[str, str] = {"id": primitive_id, "title": title}
        for key, value in fields.items():
            if isinstance(value, list):
                primitive[key] = ", ".join(str(item) for item in value)
            else:
                primitive[key] = str(value)
        primitives.append(primitive)
    return primitives


def _parse_hypotheses(lines: list[str]) -> list[BrainstormHypothesis]:
    blocks = _split_subheading_blocks(lines)
    hypotheses: list[BrainstormHypothesis] = []
    for hypothesis_id, title, body in blocks:
        fields = _parse_bullet_fields(body)
        known = {
            "status",
            "priority",
            "surface",
            "entry_point",
            "expected_chain",
            "suggested_agents",
            "focus_files",
            "tags",
            "evidence",
            "notes",
        }
        hypotheses.append(
            BrainstormHypothesis(
                id=hypothesis_id,
                title=title,
                status=str(fields.get("status", "")).strip().lower(),
                priority=str(fields.get("priority", "")).strip().lower(),
                surface=str(fields.get("surface", "")).strip(),
                entry_point=str(fields.get("entry_point", "")).strip(),
                expected_chain=str(fields.get("expected_chain", "")).strip(),
                suggested_agents=_as_list(fields.get("suggested_agents")),
                focus_files_glob=_as_list(fields.get("focus_files")),
                tags=[tag.lower() for tag in _as_list(fields.get("tags"))],
                evidence=_as_list(fields.get("evidence")),
                notes=str(fields.get("notes", "")).strip(),
                freeform_text=str(fields.get("__freeform_text", "")).strip(),
                extra_fields={
                    key: value
                    for key, value in fields.items()
                    if key not in known and key != "__freeform_text"
                },
            )
        )
    return hypotheses


def _split_subheading_blocks(lines: list[str]) -> list[tuple[str, str, list[str]]]:
    blocks: list[tuple[str, str, list[str]]] = []
    current_id: str | None = None
    current_title = ""
    current_body: list[str] = []

    for line in lines:
        match = _BLOCK_HEADING_RE.match(line)
        if match:
            if current_id is not None:
                blocks.append((current_id, current_title, current_body))
            current_id = match.group(1).strip()
            current_title = match.group(2).strip()
            current_body = []
            continue
        if current_id is not None:
            current_body.append(line)

    if current_id is not None:
        blocks.append((current_id, current_title, current_body))
    return blocks


def _parse_bullet_fields(lines: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    current_key: str | None = None
    preamble: list[str] = []
    list_fields = {"suggested_agents", "focus_files", "evidence", "tags"}
    for line in lines:
        field_match = _BULLET_FIELD_RE.match(line)
        if field_match:
            current_key = _normalize_field_name(field_match.group(1))
            value = _strip_inline_code(field_match.group(2).strip())
            if current_key in {"suggested_agents", "focus_files", "evidence"}:
                fields[current_key] = _split_list_value(value)
            elif current_key == "tags":
                fields[current_key] = _split_list_value(value, comma_split=True)
            else:
                fields[current_key] = value
            continue

        item_match = _BULLET_ITEM_RE.match(line)
        if item_match and current_key:
            item = _strip_inline_code(item_match.group(1).strip())
            if current_key not in list_fields:
                existing_text = str(fields.get(current_key, "")).strip()
                line_text = f"- {item}"
                fields[current_key] = f"{existing_text}\n{line_text}".strip()
                continue
            existing = fields.get(current_key)
            if not isinstance(existing, list):
                existing = _split_list_value(str(existing or ""))
            existing.extend(_split_list_value(item, comma_split=(current_key == "tags")))
            fields[current_key] = existing
            continue

        if current_key is None and line.strip():
            preamble.append(line.strip())
            continue

        if current_key and line.strip():
            existing = fields.get(current_key, "")
            if isinstance(existing, list):
                existing.append(_strip_inline_code(line.strip()))
            else:
                fields[current_key] = f"{existing}\n{line.strip()}".strip()

    if preamble:
        fields["__freeform_text"] = "\n".join(preamble).strip()
    return fields


def _normalize_field_name(label: str) -> str:
    cleaned = _NON_ALNUM_RE.sub("_", label.strip().lower()).strip("_")
    if cleaned == "focus_files_glob":
        return "focus_files"
    return cleaned


def _split_list_value(value: str, *, comma_split: bool = False) -> list[str]:
    value = _strip_inline_code(str(value or "").strip())
    if not value:
        return []
    if comma_split or "," in value:
        parts = value.split(",")
    else:
        parts = [value]
    return [_strip_inline_code(part.strip()) for part in parts if part.strip()]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_strip_inline_code(str(item).strip()) for item in value if str(item).strip()]
    return _split_list_value(str(value), comma_split=("," in str(value)))


def _strip_inline_code(value: str) -> str:
    if len(value) >= 2 and value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def _infer_vuln_class(tags: list[str]) -> str:
    known = {
        "xss",
        "ssrf",
        "sqli",
        "idor",
        "csrf",
        "open-redirect",
        "rce",
        "lfi",
        "path-traversal",
    }
    for tag in tags:
        if tag in known:
            return tag
    return tags[0] if tags else "brainstorm"


def _validate_suggested_agent_key(agent_key: str, hypothesis_id: str) -> str:
    key = str(agent_key or "").strip()
    label = f"suggested agent key {key!r} in hypothesis {hypothesis_id}"
    if not key:
        raise BrainstormSpecError(f"{label} must not be empty")
    if len(key) > MAX_SUGGESTED_AGENT_KEY_LENGTH:
        raise BrainstormSpecError(
            f"{label} exceeds {MAX_SUGGESTED_AGENT_KEY_LENGTH} characters"
        )
    if "/" in key or "\\" in key:
        raise BrainstormSpecError(f"{label} must not contain path separators")
    if not _SUGGESTED_AGENT_KEY_RE.fullmatch(key):
        raise BrainstormSpecError(
            f"{label} must use only ASCII letters, digits, hyphens, or underscores "
            "and must start and end with a letter or digit"
        )
    return key.casefold()


def _agent_name(agent_key: str) -> str:
    return " ".join(part for part in agent_key.replace("_", "-").split("-") if part).title()


def _build_prompt_context(spec: BrainstormSpec, hypothesis: BrainstormHypothesis) -> str:
    primitives = "\n".join(
        f"- {primitive.get('id', '')}: {primitive.get('title', '')} "
        f"{primitive.get('impact', '')}".strip()
        for primitive in spec.impact_primitives
    )
    return "\n".join(
        part
        for part in [
            f"Hypothesis {hypothesis.id}: {hypothesis.title}",
            f"Status: {hypothesis.status}",
            f"Priority: {hypothesis.priority}",
            f"Surface: {hypothesis.surface}",
            f"Entry point: {hypothesis.entry_point}",
            f"Expected chain: {hypothesis.expected_chain}",
            f"Tags: {', '.join(hypothesis.tags)}" if hypothesis.tags else "",
            f"Evidence: {', '.join(hypothesis.evidence)}" if hypothesis.evidence else "",
            f"Target mental model: {spec.mental_model}" if spec.mental_model else "",
            f"Impact primitives:\n{primitives}" if primitives else "",
        ]
        if part
    )


def _validate_spec_paths(spec: BrainstormSpec) -> None:
    lane_root = _lane_root_for_spec(spec.path)
    for key, value in spec.metadata.items():
        if _normalize_field_name(key) == "target_path":
            _ensure_path_within_lane(
                value,
                lane_root,
                f"metadata {key!r}",
                always_path=True,
            )

    for hypothesis in spec.hypotheses:
        for focus_file in hypothesis.focus_files_glob:
            _ensure_path_within_lane(
                focus_file,
                lane_root,
                f"hypothesis {hypothesis.id} focus_files",
                always_path=True,
            )
        for evidence in hypothesis.evidence:
            _ensure_path_within_lane(
                evidence,
                lane_root,
                f"hypothesis {hypothesis.id} evidence",
                always_path=False,
            )

    for primitive in spec.impact_primitives:
        evidence = primitive.get("evidence")
        if evidence:
            _ensure_path_within_lane(
                evidence,
                lane_root,
                f"impact primitive {primitive.get('id', '')} evidence",
                always_path=False,
            )


def _lane_root_for_spec(spec_path: Path) -> Path:
    if spec_path.name == "spec.md" and spec_path.parent.name == "brainstorm":
        return spec_path.parent.parent.resolve(strict=False)
    return spec_path.parent.resolve(strict=False)


def _ensure_path_within_lane(
    value: str,
    lane_root: Path,
    label: str,
    *,
    always_path: bool,
) -> None:
    raw = str(value or "").strip()
    if not raw or _URL_SCHEME_RE.match(raw):
        return
    if not always_path and not _looks_path_like(raw):
        return

    candidate = Path(raw).expanduser()
    resolved = (candidate if candidate.is_absolute() else lane_root / candidate).resolve(
        strict=False
    )
    if not resolved.is_relative_to(lane_root):
        raise BrainstormSpecError(
            f"{label} path {raw!r} resolves outside lane root {str(lane_root)!r}"
        )


def _looks_path_like(value: str) -> bool:
    if value.startswith(("/", "./", "../", "~")):
        return True
    return "/" in value or "\\" in value


def _validate_coverage_event(event: dict[str, Any]) -> None:
    event_type = str(event.get("event") or "").strip()
    if event_type not in COVERAGE_EVENTS:
        expected = ", ".join(sorted(COVERAGE_EVENTS))
        raise BrainstormSpecError(
            f"invalid coverage event {event_type!r}; expected one of: {expected}"
        )

    hypothesis_id = str(event.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise BrainstormSpecError("coverage event must include hypothesis_id")

    agent_events = {
        "agent_queued",
        "agent_spawned",
        "agent_completed_no_finding",
        "agent_completed_with_raw_findings",
        "agent_timeout",
        "agent_crashed",
        "agent_invalid_output",
        "agent_duplicate_only",
        "review_rejected",
        "review_promoted",
        "agent_completed",
    }
    if event_type in agent_events and not str(event.get("agent_key") or "").strip():
        raise BrainstormSpecError(f"{event_type} event must include agent_key")

    if event_type == "hypothesis_loaded" and "status" in event:
        status = str(event.get("status") or "").strip()
        if status not in VALID_HYPOTHESIS_STATUSES:
            expected = ", ".join(sorted(VALID_HYPOTHESIS_STATUSES))
            raise BrainstormSpecError(
                f"hypothesis_loaded event has invalid status {status!r}; "
                f"expected one of: {expected}"
            )

    if event_type == "coverage_status_changed":
        if agent_key := str(event.get("agent_key") or "").strip():
            raise BrainstormSpecError(
                "coverage_status_changed event must not include agent_key; "
                f"got {agent_key!r}"
            )
        status = str(event.get("status") or "").strip()
        if status not in COVERAGE_STATUSES:
            expected = ", ".join(sorted(COVERAGE_STATUSES))
            raise BrainstormSpecError(
                f"coverage_status_changed event has invalid status {status!r}; "
                f"expected one of: {expected}"
            )

    if event_type == "review_promoted" and not _nonempty_list(event.get("linked_fids")):
        raise BrainstormSpecError("review_promoted event must include linked_fids")

    if event_type == "agent_completed_with_raw_findings" and not (
        _nonempty_list(event.get("raw_finding_signatures"))
        or _nonempty_list(event.get("raw_findings"))
    ):
        raise BrainstormSpecError(
            "agent_completed_with_raw_findings event must include "
            "raw_finding_signatures or raw_findings"
        )


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and any(str(item).strip() for item in value)


@contextmanager
def _locked_append_handle(path: Path) -> Iterator[Any]:
    handle = path.open("a+", encoding="utf-8")
    try:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield handle
    finally:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _read_coverage_events(path: str | Path) -> Iterator[dict[str, Any]]:
    coverage_path = Path(path).expanduser().resolve(strict=False)
    if not coverage_path.exists():
        return
    with coverage_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                yield {"event": "__invalid_json__", "_invalid_json": True}
                continue
            if isinstance(event, dict):
                yield event


def _new_hypothesis_summary(status: str = "untested", title: str = "") -> dict[str, Any]:
    return {
        "title": title,
        "status": status,
        "agents": {},
        "outcomes": Counter(),
        "linked_fids": [],
        "raw_findings": [],
        "events": 0,
        "_invalid_lines": 0,
        "_explicit_hypothesis_status": False,
    }


def _apply_coverage_event(summary: dict[str, Any], event: dict[str, Any]) -> None:
    if event.get("_invalid_json"):
        summary["_invalid_lines"] += 1
        return

    summary["events"] += 1
    event_type = str(event.get("event") or "")
    agent_key = str(event.get("agent_key") or "").strip()
    if event_type == "coverage_status_changed" and agent_key:
        return
    if agent_key:
        agent = summary["agents"].setdefault(
            agent_key,
            {"status": "untested", "outcomes": Counter(), "linked_fids": []},
        )
    else:
        agent = None

    if event_type == "hypothesis_loaded":
        status = str(event.get("status") or "").strip()
        if status in VALID_HYPOTHESIS_STATUSES:
            summary["status"] = _markdown_status_to_coverage_status(status)
            summary["_explicit_hypothesis_status"] = False
    elif event_type == "agent_queued":
        _mark_status(summary, agent, "queued")
    elif event_type == "agent_spawned":
        _mark_status(summary, agent, "running")
    elif event_type == "agent_completed_no_finding":
        _mark_status(summary, agent, "tested_no_finding")
        _mark_outcome(summary, agent, "no_finding")
    elif event_type == "agent_completed_with_raw_findings":
        _mark_status(summary, agent, "raw_finding_pending")
        _mark_outcome(summary, agent, "raw_finding_pending")
        raw_findings = event.get("raw_findings") or event.get("raw_finding_signatures") or []
        summary["raw_findings"].extend(_string_list(raw_findings))
    elif event_type == "agent_timeout":
        _mark_status(summary, agent, "blocked")
        _mark_outcome(summary, agent, "timeout")
    elif event_type == "agent_crashed":
        _mark_status(summary, agent, "blocked")
        _mark_outcome(summary, agent, "crash")
    elif event_type == "agent_invalid_output":
        _mark_status(summary, agent, "blocked")
        _mark_outcome(summary, agent, "invalid_output")
    elif event_type == "agent_duplicate_only":
        _mark_status(summary, agent, "tested_no_finding")
        _mark_outcome(summary, agent, "duplicate_only")
    elif event_type == "review_rejected":
        _mark_status(summary, agent, "tested_no_finding")
        _mark_outcome(summary, agent, "review_rejected")
    elif event_type == "review_promoted":
        _mark_status(summary, agent, "tested_finding")
        _mark_outcome(summary, agent, "review_promoted")
        _extend_unique(summary["linked_fids"], _string_list(event.get("linked_fids") or []))
        if agent is not None:
            _extend_unique(agent["linked_fids"], _string_list(event.get("linked_fids") or []))
    elif event_type == "coverage_status_changed":
        status = str(event.get("status") or "").strip()
        if status in COVERAGE_STATUSES:
            _mark_status(
                summary,
                agent,
                status,
                explicit_hypothesis=(agent is None),
            )
    elif event_type == "agent_completed":
        _apply_legacy_completion(summary, agent, event)


def _apply_legacy_completion(
    summary: dict[str, Any],
    agent: dict[str, Any] | None,
    event: dict[str, Any],
) -> None:
    result = str(event.get("result") or "").strip()
    linked_fids = _string_list(event.get("linked_fids") or [])
    if linked_fids:
        _mark_status(summary, agent, "tested_finding")
        _mark_outcome(summary, agent, "review_promoted")
        _extend_unique(summary["linked_fids"], linked_fids)
        if agent is not None:
            _extend_unique(agent["linked_fids"], linked_fids)
    elif result == "finding":
        _mark_status(summary, agent, "raw_finding_pending")
        _mark_outcome(summary, agent, "raw_finding_pending")
    elif result == "no_finding":
        _mark_status(summary, agent, "tested_no_finding")
        _mark_outcome(summary, agent, "no_finding")


def _mark_status(
    summary: dict[str, Any],
    agent: dict[str, Any] | None,
    status: str,
    *,
    explicit_hypothesis: bool = False,
) -> None:
    if status not in COVERAGE_STATUSES:
        return
    summary["status"] = status
    summary["_explicit_hypothesis_status"] = explicit_hypothesis
    if agent is not None:
        agent["status"] = status


def _mark_outcome(
    summary: dict[str, Any],
    agent: dict[str, Any] | None,
    outcome: str,
) -> None:
    if outcome not in COVERAGE_OUTCOMES:
        return
    summary["outcomes"][outcome] += 1
    if agent is not None:
        agent["outcomes"][outcome] += 1


def _reconcile_hypothesis_status(summary: dict[str, Any]) -> None:
    if summary.pop("_explicit_hypothesis_status", False):
        return
    agent_statuses = [
        str(agent.get("status") or "")
        for agent in summary["agents"].values()
        if str(agent.get("status") or "")
    ]
    if not agent_statuses:
        return
    if "tested_finding" in agent_statuses:
        summary["status"] = "tested_finding"
    elif "raw_finding_pending" in agent_statuses:
        summary["status"] = "raw_finding_pending"
    elif all(status == "tested_no_finding" for status in agent_statuses):
        summary["status"] = "tested_no_finding"
    elif "running" in agent_statuses:
        summary["status"] = "running"
    elif "queued" in agent_statuses:
        summary["status"] = "queued"
    elif "blocked" in agent_statuses:
        summary["status"] = "blocked"


def _markdown_status_to_coverage_status(status: str) -> str:
    if status == "tested":
        return "tested_no_finding"
    if status in {"untested", "queued", "running", "blocked", "retired"}:
        return status
    return "untested"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _extend_unique(target: list[str], values: list[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def _timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
