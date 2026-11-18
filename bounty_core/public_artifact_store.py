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
from urllib.parse import parse_qsl, urlsplit
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
            "url": _canonical_url(url),
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
                _validate_identity(stored, row)
                encoded = (json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                if handle.write(encoded) != len(encoded):
                    raise OSError("incomplete artifact event append; history requires reconciliation")
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return stored

    def recover_legacy_url(
        self, *, artifact_id: str, previous_url: str, canonical_url: str,
        producer: str, identity_confirmed: bool,
    ) -> dict[str, Any]:
        """Explicitly attest a safe replacement for an unusable historical URL.

        The caller must establish that both URLs identify the same owned object.
        Old bytes are retained, not sanitized. No legacy URL is copied to the new row.
        """
        if identity_confirmed is not True:
            raise ValueError("legacy recovery requires explicit identity confirmation")
        safe_artifact_id = _safe_text(artifact_id, "artifact_id", required=True)
        canonical_url = _canonical_url(canonical_url)
        safe_producer = _safe_text(producer, "producer", required=True)
        if not self.events_path.exists():
            raise ValueError("legacy recovery requires an existing artifact")
        with self.events_path.open("ab", buffering=0) as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                latest = self._latest(safe_artifact_id)
                if latest is None or latest.get("url") != previous_url:
                    raise ValueError("legacy recovery requires the exact latest historical URL")
                try:
                    _canonical_url(latest["url"])
                except ValueError:
                    pass
                else:
                    raise ValueError("legacy recovery requires a noncanonical historical URL")
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "event_id": f"PAE-{uuid4().hex}",
                    "artifact_id": safe_artifact_id,
                    "timestamp": utc_timestamp(),
                    "event": latest["event"],
                    "producer": safe_producer,
                    "account_ref": _safe_text(latest["account_ref"], "account_ref", required=True),
                    "artifact_kind": _safe_text(latest["artifact_kind"], "artifact_kind", required=True),
                    "url": canonical_url,
                    "object_id": _safe_text(latest.get("object_id"), "object_id"),
                    "visibility": latest["visibility"],
                    "purpose": None,
                    "cleanup_method": None,
                    "cleanup_verified": latest.get("cleanup_verified") is True,
                    "details": {},
                    "recovered_from_event_id": _safe_text(latest["event_id"], "event_id", required=True),
                }
                stored = redact_event_value(row)
                _validate_identity(stored, row)
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
                    recovery = row.get("recovered_from_event_id")
                    if recovery:
                        if (recovery != latest["event_id"] or row["event"] != latest["event"]
                                or row["visibility"] != latest["visibility"]
                                or row.get("cleanup_verified") != (latest.get("cleanup_verified") is True)):
                            raise ValueError("invalid legacy recovery record")
                        _validate_identity(row, latest, allow_url_change=True)
                    else:
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


def _validate_identity(row: Mapping[str, Any], latest: Mapping[str, Any], *, allow_url_change: bool = False) -> None:
    for field in ("account_ref", "artifact_kind", "url", "object_id"):
        if field == "url" and allow_url_change:
            continue
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
    if event == "cleanup_pending":
        if visibility != "private" or latest["visibility"] != "private":
            raise ValueError("cleanup requires previously recorded private visibility")
    elif event != "visibility_changed" and visibility != latest["visibility"]:
        raise ValueError("visibility changes require a visibility_changed event")
    if prior_event in {"deleted", "cleanup_verified"}:
        if event != "cleanup_verified" or prior_event != "deleted":
            raise ValueError(f"{prior_event} is terminal for this artifact")
        return
    if prior_event == "cleanup_pending":
        if event == "deleted":
            return
        if event == "cleanup_verified":
            raise ValueError("cleanup_verified requires a prior deleted event for the artifact")
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
        if not isinstance(value, str):
            raise ValueError
        parsed = urlsplit(value)
        _ = parsed.port  # force validation of malformed ports
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or "@" in parsed.netloc or "?" in value or "#" in value
                or "\\" in value or "%" in parsed.netloc
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
                or redact_event_value(value) != value):
            raise ValueError
    except ValueError:
        raise ValueError("url must be an absolute canonical http(s) URL without credentials, query, or fragment") from None
    return value


_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?<![\w-])(?:[a-z0-9]+[_-])*(?:password|secret|token|authorization|cookie|"
    r"session|bearer|api[_-]?key|apikey|csrf|nonce)(?:[_-][a-z0-9]+)*\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_LABEL_URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_CREDENTIAL_URL_KEY = re.compile(
    r"(?:^|[_\-\[])(?:password|secret|token|authorization|cookie|session|bearer|"
    r"api[_-]?key|apikey|key|csrf|nonce|state|code|share|sig|signature)(?:$|[_\-\[])|"
    r"^(?:api[_-]?key|apikey)$", re.IGNORECASE,
)


def _has_credential_url(text: str) -> bool:
    for match in _LABEL_URL.finditer(text):
        try:
            url = urlsplit(match.group())
            if "@" in url.netloc:
                return True
            for component in (url.query, url.fragment):
                if any(_CREDENTIAL_URL_KEY.search(key) for key, _ in parse_qsl(component, keep_blank_values=True)):
                    return True
        except ValueError:
            # urlsplit exceptions may include caller-controlled input.
            return True
    return False


def _safe_text(value: str | None, name: str, *, required: bool = False) -> str | None:
    text = _required(value, name) if required else _optional(value)
    if text is None:
        return None
    # Short labels are not an archive of markup, requests, or credentials.
    # Match key/value syntax, not isolated security words in normal prose.
    if (len(text) > 256 or not re.fullmatch(r"[\w .,@+/'():;!&\[\]%=?#-]+", text)
            or _CREDENTIAL_ASSIGNMENT.search(text) or _has_credential_url(text)
            or redact_event_value(text) != text):
        raise ValueError(f"{name} must be a non-secret short label")
    return text


def _is_valid(row: Mapping[str, Any]) -> bool:
    required = ("event_id", "artifact_id", "timestamp", "event", "producer", "account_ref", "artifact_kind", "url", "visibility")
    return (
        all(str(row.get(field) or "").strip() for field in required)
        and row.get("event") in VALID_EVENTS
        and row.get("visibility") in VALID_VISIBILITIES
    )
