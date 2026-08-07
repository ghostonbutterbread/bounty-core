"""Product-neutral append-only evidence event primitives.

Events are canonical JSONL rows.  Their ``vuln_class`` and ``details`` fields are
open-world so producers may record new observations without a class registry.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import uuid4

SCHEMA_VERSION = 1
REQUIRED_EVENT_FIELDS = ("timestamp", "producer", "subject", "outcome", "reason")
_SECRET_KEY_RE = re.compile(
    r"(?:authorization|cookie|token|secret|password|nonce|state|csrf|api(?:_|-)?key|apikey)",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_RE = re.compile(
    r"(?P<prefix>[?&](?:authorization|cookie|token|access_token|secret|password|session(?:_id)?|"
    r"api(?:_|-)?key|apikey|nonce|state|code|csrf)=)[^&#\s]+",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?P<prefix>\b(?:authorization|password|session(?:_id)?|cookie|(?:access_)?token|secret|api(?:_|-)?key|apikey)\s*(?:=|:)\s*)[^\s;,&\"']+",
    re.IGNORECASE,
)


def utc_timestamp() -> str:
    """Return the current UTC time in the portable ``Z`` representation."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def append_event(path: str | Path, event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and append one canonical evidence event, returning its stored row."""
    row = dict(event)
    _copy_alias(row, "producer", "tool")
    _copy_alias(row, "subject", "target")
    _copy_alias(row, "reason", "stop_reason")
    row.setdefault("schema_version", SCHEMA_VERSION)
    row.setdefault("attempt_id", f"A-{uuid4().hex}")
    row.setdefault("timestamp", utc_timestamp())
    validate_event(row)
    redacted = redact_event_value(row)

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(redacted, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with destination.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.write(encoded.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return redacted


def read_events(
    path: str | Path,
    *,
    where: Mapping[str, Any] | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read at most ``limit`` valid canonical events matching top-level fields.

    Blank, malformed, and invalid JSONL records are ignored so one damaged line
    does not prevent later canonical records from being materialized.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    destination = Path(path)
    if limit == 0 or not destination.exists():
        return []

    matches: list[dict[str, Any]] = []
    for line in destination.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                continue
            event = validate_event(event)
        except (json.JSONDecodeError, ValueError):
            continue
        if where and any(event.get(field) != value for field, value in where.items()):
            continue
        matches.append(event)
        if len(matches) >= limit:
            break
    return matches


def redact_event_value(value: Any, *, key: str = "") -> Any:
    """Return a JSON-safe recursive copy with common secret material redacted."""
    if _SECRET_KEY_RE.search(key):
        return "REDACTED"
    if isinstance(value, Mapping):
        return {str(item_key): redact_event_value(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_event_value(item) for item in value]
    if isinstance(value, str):
        value = _SENSITIVE_QUERY_RE.sub(lambda match: f"{match.group('prefix')}REDACTED", value)
        return _SENSITIVE_VALUE_RE.sub(lambda match: f"{match.group('prefix')}REDACTED", value)
    return value


def _copy_alias(event: dict[str, Any], canonical: str, alias: str) -> None:
    if canonical not in event and alias in event:
        event[canonical] = event[alias]


def validate_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a normalized event or reject missing generic attribution."""
    row = dict(event)
    _copy_alias(row, "producer", "tool")
    _copy_alias(row, "subject", "target")
    _copy_alias(row, "reason", "stop_reason")
    missing = [field for field in REQUIRED_EVENT_FIELDS if not _has_value(row.get(field))]
    if missing:
        raise ValueError(f"event missing required fields: {', '.join(missing)}")
    return row


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, Mapping):
        return bool(value)
    return bool(str(value).strip())
