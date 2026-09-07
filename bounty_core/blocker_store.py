"""Lane-scoped blocker evidence for prerequisites that invalidate coverage claims.

A blocker is not an error, attempt, target fact, or hypothesis.  It records the
smallest evidenced condition that stops a named test scope from being valid,
together with its explicit wake condition.  Events are append-only; active state
is derived from the latest event for each stable blocker key.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from .evidence import redact_event_value, utc_timestamp
from .storage import normalize_family, normalize_lane, normalize_program, resolve_storage

SCHEMA_VERSION = 1
VALID_TYPES = {
    "account-capability",
    "owned-fixture",
    "feature-access",
    "auth-state",
    "environment",
    "scope-policy",
    "observation",
}
VALID_STATES = {"open", "resolved", "superseded"}


class BlockerStore:
    """Persist redacted blocker events and derive currently open blockers."""

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
        self.root = self._layout.lane_root / "blockers"
        self.events_path = self.root / "events.jsonl"

    def record(
        self,
        *,
        producer: str,
        subject: str,
        test_scope: str,
        blocker_key: str,
        blocker_type: str,
        reason: str,
        state: str = "open",
        unblock_condition: str | None = None,
        account_refs: list[str] | tuple[str, ...] | None = None,
        capability: str | None = None,
        fixture: str | None = None,
        attempt_ref: str | None = None,
        artifact_ref: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one lifecycle event; open blockers require a concrete unblock."""
        normalized_state = _choice(state, "state", VALID_STATES)
        unblock = _optional(unblock_condition)
        if normalized_state == "open" and not unblock:
            raise ValueError("unblock_condition is required for open blockers")
        row = {
            "schema_version": SCHEMA_VERSION,
            "blocker_id": f"B-{uuid4().hex}",
            "timestamp": utc_timestamp(),
            "producer": _required(producer, "producer"),
            "subject": _required(subject, "subject"),
            "test_scope": _required(test_scope, "test_scope"),
            "blocker_key": _required(blocker_key, "blocker_key"),
            "blocker_type": _choice(blocker_type, "blocker_type", VALID_TYPES),
            "reason": _required(reason, "reason"),
            "lifecycle": normalized_state,
            "unblock_condition": unblock,
            "account_refs": _refs(account_refs),
            "capability": _optional(capability),
            "fixture": _optional(fixture),
            "attempt_ref": _optional(attempt_ref),
            "artifact_ref": _optional(artifact_ref),
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

    def query(self, *, where: Mapping[str, Any] | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        if limit == 0 or not self.events_path.exists():
            return []
        matches: list[dict[str, Any]] = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not _is_valid(row):
                continue
            if where and any(row.get(field) != value for field, value in where.items()):
                continue
            matches.append(row)
            if len(matches) >= limit:
                break
        return matches

    def active(self, *, subject: str | None = None, test_scope: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Return latest open event for each stable blocker key, bounded at read time."""
        if limit < 0:
            raise ValueError("limit must be non-negative")
        latest: dict[str, dict[str, Any]] = {}
        if not self.events_path.exists():
            return []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not _is_valid(row):
                continue
            if subject is not None and row["subject"] != subject:
                continue
            if test_scope is not None and row["test_scope"] != test_scope:
                continue
            latest[row["blocker_key"]] = row
        return [row for row in latest.values() if row["lifecycle"] == "open"][:limit]

    def coverage_gate(self, *, subject: str, test_scope: str) -> dict[str, Any]:
        """State whether the named coverage claim is currently blocked."""
        blockers = self.active(subject=subject, test_scope=test_scope)
        return {
            "subject": subject,
            "test_scope": test_scope,
            "coverage_state": "blocked" if blockers else "unblocked",
            "blockers": blockers,
        }


def _required(value: str, name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{name} is required")
    return normalized


def _optional(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _refs(values: list[str] | tuple[str, ...] | None) -> list[str]:
    return [_required(value, "account_refs item") for value in (values or [])]


def _choice(value: str, name: str, allowed: set[str]) -> str:
    normalized = _required(value, name).lower()
    if normalized not in allowed:
        raise ValueError(f"invalid {name}: {value!r}; use one of: {', '.join(sorted(allowed))}")
    return normalized


def _is_valid(row: Mapping[str, Any]) -> bool:
    required = ("blocker_id", "timestamp", "producer", "subject", "test_scope", "blocker_key", "blocker_type", "reason", "lifecycle")
    return (
        all(str(row.get(field) or "").strip() for field in required)
        and row.get("blocker_type") in VALID_TYPES
        and row.get("lifecycle") in VALID_STATES
    )
