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
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote_plus, urlsplit, urlunsplit
from uuid import uuid4

from .evidence import redact_event_value, utc_timestamp
from .storage import normalize_family, normalize_lane, normalize_program, resolve_storage

SCHEMA_VERSION = 1
VALID_EVENTS = {"created", "updated", "visibility_changed", "cleanup_pending", "deleted", "cleanup_verified"}
VALID_VISIBILITIES = {"private", "unlisted", "community", "public", "unknown"}
SENSITIVE_QUERY_KEYS = {"access_token", "api_key", "apikey", "client_secret", "code", "password", "secret", "token"}


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
    ) -> dict[str, Any]:
        """Append one redacted lifecycle event for an owned test artifact."""
        normalized_event = _choice(event, "event", VALID_EVENTS)
        normalized_visibility = _choice(visibility, "visibility", VALID_VISIBILITIES)
        supplied_artifact_id = _optional(artifact_id)
        if normalized_event != "created" and not supplied_artifact_id:
            raise ValueError("artifact_id is required for lifecycle events after creation")
        latest = self._latest(supplied_artifact_id)
        _validate_transition(normalized_event, normalized_visibility, latest)
        if normalized_event == "cleanup_verified" and not cleanup_verified:
            raise ValueError("cleanup_verified must be true for cleanup_verified events")
        if cleanup_verified and normalized_event not in {"deleted", "cleanup_verified"}:
            raise ValueError("cleanup_verified is only valid after deletion or cleanup verification")
        row = {
            "schema_version": SCHEMA_VERSION,
            "event_id": f"PAE-{uuid4().hex}",
            "artifact_id": supplied_artifact_id or f"PA-{uuid4().hex}",
            "timestamp": utc_timestamp(),
            "event": normalized_event,
            "producer": _required(producer, "producer"),
            "account_ref": _required(account_ref, "account_ref"),
            "artifact_kind": _required(artifact_kind, "artifact_kind"),
            "url": _redact_artifact_url(_required(url, "url")),
            "object_id": _optional(object_id),
            "visibility": normalized_visibility,
            "purpose": _optional(purpose),
            "cleanup_method": _optional(cleanup_method),
            "cleanup_verified": bool(cleanup_verified),
            "details": dict(details or {}),
        }
        stored = redact_event_value(row)
        self.root.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n"
        with self.events_path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return stored

    def _latest(self, artifact_id: str | None) -> dict[str, Any] | None:
        if not artifact_id or not self.events_path.exists():
            return None
        latest: dict[str, Any] | None = None
        for row in _rows(self.events_path):
            if row["artifact_id"] == artifact_id:
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


def _validate_transition(event: str, visibility: str, latest: Mapping[str, Any] | None) -> None:
    if event == "created":
        if latest is not None:
            raise ValueError("created events cannot reuse an existing artifact_id")
        return
    if latest is None:
        raise ValueError("lifecycle events require a prior created artifact")
    prior_event = str(latest["event"])
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


def _rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and _is_valid(row):
            rows.append(row)
    return rows


def _required(value: str, name: str) -> str:
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
        raise ValueError(f"invalid {name}: {value!r}; use one of: {', '.join(sorted(allowed))}")
    return normalized


def _redact_artifact_url(value: str) -> str:
    """Remove sensitive query values before a URL is persisted."""
    parsed = urlsplit(value)
    if not parsed.query:
        return value
    query_parts: list[str] = []
    for item in parsed.query.split("&"):
        key, separator, _raw_value = item.partition("=")
        decoded_key = unquote_plus(key).lower()
        base_key = decoded_key.split("[", 1)[0]
        if base_key in SENSITIVE_QUERY_KEYS:
            query_parts.append(f"{key}=REDACTED" if separator else key)
        else:
            query_parts.append(item)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "&".join(query_parts), parsed.fragment))


def _is_valid(row: Mapping[str, Any]) -> bool:
    required = ("event_id", "artifact_id", "timestamp", "event", "producer", "account_ref", "artifact_kind", "url", "visibility")
    return (
        all(str(row.get(field) or "").strip() for field in required)
        and row.get("event") in VALID_EVENTS
        and row.get("visibility") in VALID_VISIBILITIES
    )
