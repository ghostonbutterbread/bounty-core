"""Canonical storage resolver for shared Ghost bug bounty workflows."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WEB_FAMILY = "web_bounty"
BINARIES_FAMILY = "binaries"
VALID_FAMILIES = {WEB_FAMILY, BINARIES_FAMILY}

DEFAULT_LANES: dict[str, set[str]] = {
    WEB_FAMILY: {"web", "api"},
    BINARIES_FAMILY: {"apk", "exe", "mac"},
}

REPORT_STATES = ("raw", "confirmed", "dormant", "novel", "complete", "archive")
NOTE_BUCKETS = ("faq", "hypotheses", "handoffs", "timeline")
VULN_TYPES = ("xss", "sqli", "ssrf", "idor", "auth", "bac", "fuzz", "recon", "chain")


@dataclass(slots=True)
class StorageLayout:
    program: str
    family: str
    lane: str
    root_mode: str
    base_root: Path
    family_root: Path
    program_root: Path
    lane_root: Path
    reports_root: Path
    ledgers_root: Path
    working_root: Path
    context_root: Path
    notes_root: Path
    shared_root: Path
    recon_root: Path | None = None
    input_root: Path | None = None
    allow_lane_autocreate: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "program": self.program,
            "family": self.family,
            "lane": self.lane,
            "root_mode": self.root_mode,
            "base_root": str(self.base_root),
            "family_root": str(self.family_root),
            "program_root": str(self.program_root),
            "canonical_root": str(self.lane_root),
            "reports_root": str(self.reports_root),
            "ledger_root": str(self.ledgers_root),
            "working_root": str(self.working_root),
            "context_root": str(self.context_root),
            "notes_root": str(self.notes_root),
            "shared_root": str(self.shared_root),
            "allow_lane_autocreate": self.allow_lane_autocreate,
            "report_states": list(REPORT_STATES),
        }
        if self.recon_root is not None:
            payload["recon_root"] = str(self.recon_root)
        if self.input_root is not None:
            payload["input_root"] = str(self.input_root)
        return payload


def normalize_program(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    if not cleaned:
        raise ValueError("program is required")
    return cleaned


def normalize_family(value: str) -> str:
    family = str(value or "").strip().lower()
    aliases = {
        "web": WEB_FAMILY,
        "web_bounty": WEB_FAMILY,
        "bounty_recon": WEB_FAMILY,
        "binaries": BINARIES_FAMILY,
        "binary": BINARIES_FAMILY,
    }
    normalized = aliases.get(family, family)
    if normalized not in VALID_FAMILIES:
        raise ValueError(f"unsupported family: {value!r}")
    return normalized


def normalize_lane(value: str) -> str:
    lane = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower())
    if not lane:
        raise ValueError("lane is required")
    return lane


def infer_family_from_lane(lane: str) -> str:
    normalized_lane = normalize_lane(lane)
    if normalized_lane in DEFAULT_LANES[WEB_FAMILY]:
        return WEB_FAMILY
    if normalized_lane in DEFAULT_LANES[BINARIES_FAMILY]:
        return BINARIES_FAMILY
    raise ValueError(f"could not infer family for custom lane {normalized_lane!r}; provide family explicitly")


def resolve_family_lane(
    *,
    family: str | None = None,
    lane: str | None = None,
    hunt_type: str | None = None,
) -> tuple[str, str]:
    if lane:
        normalized_lane = normalize_lane(lane)
        normalized_family = normalize_family(family) if family else infer_family_from_lane(normalized_lane)
        return normalized_family, normalized_lane

    normalized_hunt = str(hunt_type or "").strip().lower()
    hunt_mappings = {
        "web": (WEB_FAMILY, "web"),
        "api": (WEB_FAMILY, "api"),
        "apk": (BINARIES_FAMILY, "apk"),
        "source": (BINARIES_FAMILY, "apk"),
        "binary": (BINARIES_FAMILY, "apk"),
        "binaries": (BINARIES_FAMILY, "apk"),
        "0day_team": (WEB_FAMILY, "web"),
    }
    if normalized_hunt in hunt_mappings:
        return hunt_mappings[normalized_hunt]

    if family:
        normalized_family = normalize_family(family)
        default_lane = "web" if normalized_family == WEB_FAMILY else "apk"
        return normalized_family, default_lane

    raise ValueError("could not resolve family/lane; provide explicit family/lane or a supported hunt_type")


def build_me_context(layout: StorageLayout) -> str:
    lines = [
        f"Program: {layout.program}",
        f"Family: {layout.family}",
        f"Lane: {layout.lane}",
        f"Canonical root: {layout.lane_root}",
        f"Root mode: {layout.root_mode}",
        "",
        "Canonical write rules:",
        f"- Write raw reports to: {layout.reports_root / 'raw'}",
        f"- Promote reviewed findings to: {layout.reports_root}/{{confirmed,dormant,novel,complete,archive}}",
        f"- Write summary indexes under: {layout.reports_root / 'index'}",
        f"- Use ledger root: {layout.ledgers_root}",
        f"- Use context root: {layout.context_root}",
        f"- Use notes root: {layout.notes_root}",
        f"- Use working root for generated analysis artifacts: {layout.working_root}",
    ]
    if layout.recon_root is not None:
        lines.append(f"- Use recon root: {layout.recon_root}")
    if layout.input_root is not None:
        lines.append(f"- Use input root: {layout.input_root}")
    lines.extend([
        "",
        "Rules:",
        "- Do not treat cwd as canonical storage unless explicit local mode was requested.",
        "- Use /tmp or working/scratch for ephemeral scratch files.",
        "- Keep reports, ledgers, and context lane-specific.",
    ])
    return "\n".join(lines) + "\n"


def resolve_storage(
    program: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    allow_lane_autocreate: bool = True,
    create: bool = False,
) -> StorageLayout:
    normalized_program = normalize_program(program)
    normalized_lane = normalize_lane(lane)
    normalized_family = normalize_family(family) if family else infer_family_from_lane(normalized_lane)

    if normalized_lane not in DEFAULT_LANES.get(normalized_family, set()) and not allow_lane_autocreate:
        raise ValueError(f"lane {normalized_lane!r} is not a default lane for family {normalized_family!r}")

    if root_override is None:
        base_root = (Path.home() / "Shared").resolve(strict=False)
        root_mode = "shared-default"
        family_root = base_root / normalized_family
        program_root = family_root / normalized_program
    else:
        base_root = Path(root_override).expanduser().resolve(strict=False)
        root_mode = "explicit-local"
        family_root = base_root / normalized_family
        program_root = family_root / normalized_program

    lane_root = program_root / normalized_lane
    layout = StorageLayout(
        program=normalized_program,
        family=normalized_family,
        lane=normalized_lane,
        root_mode=root_mode,
        base_root=base_root,
        family_root=family_root,
        program_root=program_root,
        lane_root=lane_root,
        reports_root=lane_root / "reports",
        ledgers_root=lane_root / "ledgers",
        working_root=lane_root / "working",
        context_root=lane_root / "context",
        notes_root=lane_root / "notes",
        shared_root=program_root / "shared",
        recon_root=lane_root / "recon",
        input_root=(lane_root / "input") if normalized_family == BINARIES_FAMILY else None,
        allow_lane_autocreate=allow_lane_autocreate,
    )
    if create:
        ensure_layout(layout)
    return layout


def ensure_layout(layout: StorageLayout) -> None:
    for path in [
        layout.program_root,
        layout.lane_root,
        layout.reports_root,
        layout.ledgers_root,
        layout.working_root,
        layout.context_root,
        layout.notes_root,
        layout.shared_root,
    ]:
        path.mkdir(parents=True, exist_ok=True)

    for state in REPORT_STATES:
        (layout.reports_root / state).mkdir(parents=True, exist_ok=True)
        for vuln_type in VULN_TYPES:
            (layout.reports_root / state / vuln_type).mkdir(parents=True, exist_ok=True)
            index_path = layout.reports_root / state / vuln_type / "index.md"
            if not index_path.exists():
                index_path.write_text(f"# {state.title()} {vuln_type.upper()}\n\n", encoding="utf-8")

    (layout.reports_root / "index").mkdir(parents=True, exist_ok=True)
    for index_name in [*REPORT_STATES, *VULN_TYPES]:
        index_path = layout.reports_root / "index" / f"{index_name}.md"
        if not index_path.exists():
            index_path.write_text(f"# {index_name.replace('_', ' ').title()}\n\n", encoding="utf-8")

    for path in [
        layout.ledgers_root / "archive",
        layout.ledgers_root / "indexes" / "by_type",
        layout.ledgers_root / "indexes" / "by_status",
        layout.ledgers_root / "shared_brain",
        layout.ledgers_root / "traces",
        layout.working_root / "scratch",
    ]:
        path.mkdir(parents=True, exist_ok=True)

    if layout.recon_root is not None:
        for name in ("urls", "params", "js", "maps", "artifacts"):
            (layout.recon_root / name).mkdir(parents=True, exist_ok=True)
    if layout.input_root is not None:
        for name in ("original", "extracted", "metadata"):
            (layout.input_root / name).mkdir(parents=True, exist_ok=True)

    for name in NOTE_BUCKETS:
        (layout.notes_root / name).mkdir(parents=True, exist_ok=True)

    note_index = layout.notes_root / "index.md"
    if not note_index.exists():
        note_index.write_text("# Notes Index\n\nUse this file as the memory map for this target/lane.\n", encoding="utf-8")

    profile_path = layout.context_root / "target_profile.json"
    profile_path.write_text(json.dumps(layout.to_dict(), indent=2) + "\n", encoding="utf-8")
    me_context = layout.context_root / "me_context.md"
    if not me_context.exists():
        me_context.write_text(build_me_context(layout), encoding="utf-8")
