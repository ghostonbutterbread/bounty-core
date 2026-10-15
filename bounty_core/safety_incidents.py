"""Agent-reported safety incidents: durable record first, optional Discord alert second.

This is a reporting channel, not a request interceptor or a substitute for stopping
unsafe work.  No webhook credential or raw request is persisted in this store.
"""
from __future__ import annotations

import argparse
import fcntl
from http.client import IncompleteRead
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from .evidence import redact_event_value, utc_timestamp
from .storage import resolve_storage

WEBHOOK_ENV = "DISCORD_SAFETY_WEBHOOK_URL"
CATEGORIES = {"non-owned-mutation", "production-risk", "scope-violation", "sensitive-exposure", "other"}
OUTCOMES = {"occurred", "attempted", "uncertain"}
# The ordinary evidence redactor does not recognize opaque Discord webhook paths.
_WEBHOOK_RE = re.compile(
    r"(?:https?://)?(?:canary\.|ptb\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/[^\s\"'<>]+", re.I
)
_WEBHOOK_ENDPOINT_RE = re.compile(r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+\Z")
# Discord's edge rejected urllib's Python-urllib identity with Cloudflare 1010
# in a live delivery check; use a conventional browser-compatible identity.
WEBHOOK_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"


def _safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value]
    if isinstance(value, str):
        return _WEBHOOK_RE.sub("[REDACTED WEBHOOK]", value)
    return value


def _required(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _append(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Restrict new files even if the process umask is permissive. Shared storage
    # still requires sanitized fields; this is not a private secret store.
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            os.fchmod(handle.fileno(), 0o600)
            # An interrupted previous write may leave a partial JSONL line.
            # Preserve it as evidence, but separate the next complete record.
            size = os.fstat(handle.fileno()).st_size
            if size and os.pread(handle.fileno(), 1, size - 1) != b"\n":
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafetyIncidentStore:
    """Append-only lane-local incidents and notification attempts."""

    def __init__(self, program: str, *, family: str = "web_bounty", lane: str = "web", root_override: str | Path | None = None):
        layout = resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)
        self.program, self.family, self.lane = layout.program, layout.family, layout.lane
        self.root = layout.lane_root / "safety_incidents"
        self.events_path = self.root / "events.jsonl"
        self.notifications_path = self.root / "notifications.jsonl"

    def record(
        self, *, producer: str, run_id: str, category: str, action: str,
        subject: str, impact: str, containment: str, outcome: str = "uncertain",
        notify: bool = True,
    ) -> dict[str, Any]:
        """Persist immediately; never lose an incident because notification fails.

        The caller stops unsafe actions and handles containment independently.
        Return both the incident and the notification receipt.
        """
        if category not in CATEGORIES:
            raise ValueError(f"invalid category: {category!r}")
        if outcome not in OUTCOMES:
            raise ValueError(f"invalid outcome: {outcome!r}")
        event = {
            "schema_version": 1,
            "incident_id": f"SI-{uuid4().hex}",
            "timestamp": utc_timestamp(),
            "program": self.program,
            "family": self.family,
            "lane": self.lane,
            "producer": _required(producer, "producer"),
            "run_id": _required(run_id, "run_id"),
            "category": category,
            "outcome": outcome,
            "action": _required(action, "action"),
            "subject": _required(subject, "subject"),
            "impact": _required(impact, "impact"),
            "containment": _required(containment, "containment"),
        }
        stored = redact_event_value(_safe(event))
        _append(self.events_path, stored)
        try:
            receipt = self.notify(stored["incident_id"]) if notify else None
        except OSError:
            # The incident is already durable. Keep its ID visible to the caller
            # even if a receipt write fails before or after a network request.
            receipt = {"incident_id": stored["incident_id"], "state": "receipt-write-failed"}
        return {"incident": stored, "notification": receipt}

    def get(self, incident_id: str) -> dict[str, Any] | None:
        if not self.events_path.exists():
            return None
        for line in self.events_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("incident_id") == incident_id:
                return row
        return None

    def notify(self, incident_id: str) -> dict[str, Any]:
        """Make one bounded delivery attempt and persist its disposition.

        A timeout is ambiguous: delivery may have happened. Manual retry can
        produce a duplicate, identified by the same incident ID.
        """
        incident = self.get(incident_id)
        if incident is None:
            raise ValueError("incident not found in this program/lane")
        # An attempt receipt is fsynced before the network request. If a final
        # disposition cannot be written, operators can still see an unknown
        # delivery and must check the channel before retrying.
        _append(self.notifications_path, {"incident_id": incident_id, "timestamp": utc_timestamp(), "state": "pending"})
        url = os.environ.get(WEBHOOK_ENV, "")
        message_id = None
        if not url:
            state = "not-configured"
        elif not _WEBHOOK_ENDPOINT_RE.fullmatch(url):
            state = "invalid-configuration"
        else:
            content = (
                f"Safety incident {incident_id} | {self.program}/{self.lane} | "
                f"{incident['category']} ({incident['outcome']}). Stop/contain; review the lane-local record."
            )
            payload = json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode("utf-8")
            request = Request(url + "?wait=true", data=payload, headers={"Content-Type": "application/json", "User-Agent": WEBHOOK_USER_AGENT}, method="POST")
            try:
                with build_opener(_NoRedirect()).open(request, timeout=5) as response:
                    state = "sent" if response.status in (200, 204) else f"http-{response.status}"
                    if response.status == 200:
                        try:
                            body = json.load(response)
                        except (ValueError, OSError, UnicodeError, IncompleteRead):
                            body = {}
                        candidate = str(body.get("id", "")) if isinstance(body, dict) else ""
                        message_id = candidate if candidate.isdigit() else None
            except HTTPError as exc:
                state = f"http-{exc.code}"
            except (URLError, TimeoutError, OSError):
                state = "delivery-unknown"
        receipt = {"incident_id": incident_id, "timestamp": utc_timestamp(), "state": state}
        if message_id is not None:
            receipt["message_id"] = message_id
        _append(self.notifications_path, receipt)
        return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record an agent safety incident before attempting a Discord alert")
    parser.add_argument("--program", required=True)
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", required=True)
    parser.add_argument("--root", help="optional explicit storage root")
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    for field in ("producer", "run-id", "action", "subject", "impact", "containment"):
        record.add_argument("--" + field, required=True)
    record.add_argument("--category", required=True, choices=sorted(CATEGORIES))
    record.add_argument("--outcome", choices=sorted(OUTCOMES), default="uncertain")
    record.add_argument("--no-notify", action="store_true")
    notification = commands.add_parser("notify", help="manually retry one incident ID; may duplicate a timed-out delivery")
    notification.add_argument("incident_id")
    args = parser.parse_args(argv)
    try:
        store = SafetyIncidentStore(args.program, family=args.family, lane=args.lane, root_override=args.root)
        if args.command == "record":
            result = store.record(
                producer=args.producer, run_id=args.run_id, category=args.category,
                action=args.action, subject=args.subject, impact=args.impact,
                containment=args.containment, outcome=args.outcome, notify=not args.no_notify,
            )
        else:
            result = {"notification": store.notify(args.incident_id)}
    except (ValueError, OSError) as exc:
        # Do not print exception values: paths and malformed input can contain secrets.
        print(f"safety incident operation failed ({type(exc).__name__}); no delivery confirmed", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    state = (result.get("notification") or {}).get("state")
    return 0 if state in (None, "sent") else 1
