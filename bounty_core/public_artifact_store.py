"""Lane-scoped, append-only registry for owned public testing artifacts.

The registry stores non-secret account references and artifact URLs/IDs so an
agent can reuse one owned artifact, track its visibility, and prove cleanup.
It is deliberately a generic persistence primitive: publication authorization,
community selection, test design, and cleanup policy remain consumer concerns.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from .evidence import redact_event_value, utc_timestamp
from .provenance import AI_REVIEWED_BY_FIELD, merge_ai_reviewers
from .storage import normalize_family, normalize_lane, normalize_program, resolve_storage

SCHEMA_VERSION = 1
VALID_EVENTS = {"created", "updated", "visibility_changed", "cleanup_pending", "deleted", "cleanup_verified"}
VALID_VISIBILITIES = {"private", "unlisted", "community", "public", "unknown"}


class PublicArtifactStore:
    """Persist owned public-artifact lifecycle events and derive current records."""

    def __init__(
        self,
        program: str,
        *,
        family: str = "web_bounty",
        lane: str = "web",
        root_override: str | Path | None = None,
    ) -> None:
        self.program = normalize_program(program)
        self.family = normalize_family(family)
        self.lane = normalize_lane(lane)
        self._layout = resolve_storage(
            self.program, family=self.family, lane=self.lane, root_override=root_override, create=False
        )
        self.root = self._layout.lane_root / "public_artifacts"
        self.events_path = self.root / "events.jsonl"

    def record(
        self,
        *,
        event: str,
        producer: str,
        account_ref: str,
        artifact_kind: str,
        url: str,
        artifact_id: str | None = None,
        object_id: str | None = None,
        visibility: str = "unknown",
        purpose: str | None = None,
        cleanup_method: str | None = None,
        cleanup_verified: bool = False,
        details: Mapping[str, Any] | None = None,
        model_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a non-secret ownership pointer, never private evidence or payloads."""
        normalized_event = _choice(event, "event", VALID_EVENTS)
        normalized_visibility = _choice(visibility, "visibility", VALID_VISIBILITIES)
        supplied_artifact_id = _safe_text(artifact_id, "artifact_id")
        if not isinstance(cleanup_verified, bool):
            raise ValueError("cleanup_verified must be a boolean")
        if normalized_event != "created" and not supplied_artifact_id:
            raise ValueError("artifact_id is required for lifecycle events after creation")
        if normalized_event == "cleanup_verified" and not cleanup_verified:
            raise ValueError("cleanup_verified must be true for cleanup_verified events")
        if cleanup_verified and normalized_event not in {"deleted", "cleanup_verified"}:
            raise ValueError("cleanup_verified is only valid after deletion or cleanup verification")
        if details:
            raise ValueError("details are not supported in the public artifact registry")
        row = {
            "schema_version": SCHEMA_VERSION,
            "event_id": f"PAE-{uuid4().hex}",
            "artifact_id": supplied_artifact_id or f"PA-{uuid4().hex}",
            "timestamp": utc_timestamp(),
            "event": normalized_event,
            "producer": _safe_text(producer, "producer", required=True),
            "account_ref": _safe_text(account_ref, "account_ref", required=True),
            "artifact_kind": _safe_text(artifact_kind, "artifact_kind", required=True),
            "url": _canonical_url(_required(url, "url")),
            "object_id": _safe_text(object_id, "object_id"),
            "visibility": normalized_visibility,
            "purpose": _safe_text(purpose, "purpose"),
            "cleanup_method": _safe_text(cleanup_method, "cleanup_method"),
            "cleanup_verified": bool(cleanup_verified),
            "details": {},
        }
        reviewers = merge_ai_reviewers(agent_id=row["producer"], model_id=_safe_text(model_id, "model_id"))
        if reviewers:
            row[AI_REVIEWED_BY_FIELD] = reviewers
        self.root.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("ab", buffering=0) as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                latest = self._latest(supplied_artifact_id)
                _validate_transition(row, latest)
                if latest and not row["object_id"]:
                    row["object_id"] = latest.get("object_id")
                stored = redact_event_value(row)
                encoded = (json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                if handle.write(encoded) != len(encoded):
                    raise OSError("incomplete artifact event append; history requires reconciliation")
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return stored

    def _latest(self, artifact_id: str | None) -> dict[str, Any] | None:
        if not self.events_path.exists():
            return None
        latest: dict[str, Any] | None = None
        for row in _rows(self.events_path, strict=True):
            if row["artifact_id"] == artifact_id:
                if latest:
                    _validate_identity(row, latest)
                    if not row.get("object_id"):
                        row["object_id"] = latest.get("object_id")
                latest = row
        return latest

    def query(self, *, where: Mapping[str, Any] | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Return bounded valid events matching exact top-level fields."""
        if limit < 0:
            raise ValueError("limit must be non-negative")
        if limit == 0 or not self.events_path.exists():
            return []
        matches: list[dict[str, Any]] = []
        for row in _rows(self.events_path):
            if where and any(row.get(field) != value for field, value in where.items()):
                continue
            matches.append(row)
            if len(matches) >= limit:
                break
        return matches

    def current(self, *, include_cleaned: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        """Return latest lifecycle state per artifact, excluding pending cleanup by default."""
        if limit < 0:
            raise ValueError("limit must be non-negative")
        latest: dict[str, dict[str, Any]] = {}
        if not self.events_path.exists():
            return []
        for row in _rows(self.events_path):
            latest[row["artifact_id"]] = row
        records = list(latest.values())
        if not include_cleaned:
            records = [row for row in records if row["event"] not in {"cleanup_pending", "deleted", "cleanup_verified"}]
        return records[:limit]


def _validate_identity(row: Mapping[str, Any], latest: Mapping[str, Any]) -> None:
    for field in ("account_ref", "artifact_kind", "url", "object_id"):
        old, new = latest.get(field), row.get(field)
        if field == "object_id" and (not old or not new):
            continue
        if old != new:
            raise ValueError(f"artifact identity mismatch: {field}")


def _validate_transition(row: Mapping[str, Any], latest: Mapping[str, Any] | None) -> None:
    event, visibility = row["event"], row["visibility"]
    if event == "created":
        if latest is not None:
            raise ValueError("created events cannot reuse an existing artifact_id")
        return
    if latest is None:
        raise ValueError("lifecycle events require a prior created artifact")
    _validate_identity(row, latest)
    prior_event = str(latest["event"])
    if event in {"cleanup_pending", "deleted", "cleanup_verified"}:
        if visibility != "private" or latest["visibility"] != "private":
            raise ValueError("cleanup requires previously recorded private visibility")
        required_prior = {"deleted": "cleanup_pending", "cleanup_verified": "deleted"}.get(event)
        if required_prior and prior_event != required_prior:
            raise ValueError(f"{event} requires a prior {required_prior} event")
    elif event != "visibility_changed" and visibility != latest["visibility"]:
        raise ValueError("visibility changes require a visibility_changed event")
    if prior_event in {"deleted", "cleanup_verified"}:
        if event != "cleanup_verified" or prior_event != "deleted":
            raise ValueError(f"{prior_event} is terminal for this artifact")
        return
    if prior_event == "cleanup_pending":
        if event == "deleted":
            return
        raise ValueError("cleanup_pending permits only deletion")
    if event == "cleanup_verified":
        raise ValueError("cleanup_verified requires a prior deleted event for the artifact")


def _rows(path: Path, *, strict: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    if strict and text and not text.endswith("\n"):
        raise ValueError("artifact history has an incomplete final record")
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            if strict:
                raise ValueError("artifact history contains an invalid record") from None
            continue
        if isinstance(row, dict) and _is_valid(row):
            rows.append(row)
        elif strict:
            raise ValueError("artifact history contains an invalid record")
    return rows


def _required(value: str | None, name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{name} is required")
    return normalized


def _optional(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _choice(value: str, name: str, allowed: set[str]) -> str:
    normalized = _required(value, name).lower()
    if normalized not in allowed:
        raise ValueError(f"invalid {name}; use one of: {', '.join(sorted(allowed))}")
    return normalized


def _canonical_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port  # force validation of malformed ports
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or "@" in parsed.netloc or "?" in value or "#" in value
                or "\\" in value or "%" in parsed.netloc
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError
    except ValueError:
        raise ValueError("url must be an absolute canonical http(s) URL without credentials, query, or fragment") from None
    return value


def _safe_text(value: str | None, name: str, *, required: bool = False) -> str | None:
    text = _required(value, name) if required else _optional(value)
    if text is None:
        return None
    # These are short ownership labels, not a content or request archive.
    if (len(text) > 256 or not re.fullmatch(r"[\w .,@+/'-]+", text)
            or redact_event_value(text) != text
            or re.search(r"\b(?:password|secret|token|authorization|cookie|bearer)\b", text, re.I)):
        raise ValueError(f"{name} must be a non-secret short label")
    return text


def _is_valid(row: Mapping[str, Any]) -> bool:
    required = ("event_id", "artifact_id", "timestamp", "event", "producer", "account_ref", "artifact_kind", "url", "visibility")
    return (
        all(str(row.get(field) or "").strip() for field in required)
        and row.get("event") in VALID_EVENTS
        and row.get("visibility") in VALID_VISIBILITIES
    )
