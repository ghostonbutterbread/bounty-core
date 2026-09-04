"""Lane-scoped, append-only, redacted application error evidence."""

from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from .evidence import redact_event_value
from .storage import normalize_family, normalize_lane, normalize_program, resolve_storage

SCHEMA_VERSION = 1
VALID_LAYERS = {"edge", "server", "application", "dependency", "workflow", "client", "unknown"}
VALID_CHANNELS = {"http", "browser-console", "network", "async-job", "proxy", "unknown"}


class ErrorStore:
    """Persist observed error behavior without conflating it with attempts or findings."""

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
            self.program,
            family=self.family,
            lane=self.lane,
            root_override=root_override,
            create=False,
        )
        self.root = self._layout.lane_root / "errors"
        self.events_path = self.root / "events.jsonl"

    def record(
        self,
        *,
        producer: str,
        subject: str,
        reason: str,
        layer: str,
        channel: str,
        status_or_event: str,
        fingerprint: str,
        trigger_family: str,
        input_location: str | None = None,
        details: Mapping[str, Any] | None = None,
        actor_context: str = "unknown",
        reproducibility: str = "observed-once",
        attempt_ref: str | None = None,
        artifact_ref: str | None = None,
    ) -> dict[str, Any]:
        """Redact and atomically append a single observed error event."""
        normalized_layer = _choice(layer, "layer", VALID_LAYERS)
        normalized_channel = _choice(channel, "channel", VALID_CHANNELS)
        event = {
            "schema_version": SCHEMA_VERSION,
            "error_id": f"E-{uuid4().hex}",
            "timestamp": _utc_timestamp(),
            "producer": _required(producer, "producer"),
            "subject": _required(subject, "subject"),
            "reason": _required(reason, "reason"),
            "layer": normalized_layer,
            "channel": normalized_channel,
            "status_or_event": _required(status_or_event, "status_or_event"),
            "fingerprint": _required(fingerprint, "fingerprint"),
            "trigger_family": _required(trigger_family, "trigger_family"),
            "input_location": _optional(input_location),
            "actor_context": _required(actor_context, "actor_context"),
            "reproducibility": _required(reproducibility, "reproducibility"),
            "attempt_ref": _optional(attempt_ref),
            "artifact_ref": _optional(artifact_ref),
            "details": dict(details or {}),
        }
        stored = redact_event_value(event)
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
        """Return a bounded set of valid rows matching exact top-level fields."""
        if limit < 0:
            raise ValueError("limit must be non-negative")
        if limit == 0 or not self.events_path.exists():
            return []
        matches: list[dict[str, Any]] = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or not _is_valid_event(event):
                continue
            if where and any(event.get(field) != value for field, value in where.items()):
                continue
            matches.append(event)
            if len(matches) >= limit:
                break
        return matches

    def fingerprint_summary(self, *, where: Mapping[str, Any] | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        """Group bounded event history by fingerprint while retaining every event on disk."""
        grouped: dict[str, dict[str, Any]] = {}
        for event in self.query(where=where, limit=limit):
            fingerprint = str(event["fingerprint"])
            item = grouped.setdefault(
                fingerprint,
                {
                    "fingerprint": fingerprint,
                    "count": 0,
                    "first_seen": event["timestamp"],
                    "last_seen": event["timestamp"],
                    "layers": set(),
                    "channels": set(),
                },
            )
            item["count"] += 1
            item["last_seen"] = event["timestamp"]
            item["layers"].add(event["layer"])
            item["channels"].add(event["channel"])
        return [
            {
                "fingerprint": item["fingerprint"],
                "count": item["count"],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "layers": sorted(item["layers"]),
                "channels": sorted(item["channels"]),
            }
            for item in grouped.values()
        ]


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def _is_valid_event(event: Mapping[str, Any]) -> bool:
    required = ("error_id", "timestamp", "producer", "subject", "reason", "layer", "channel", "status_or_event", "fingerprint", "trigger_family")
    return all(str(event.get(field) or "").strip() for field in required)
