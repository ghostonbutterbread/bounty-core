from __future__ import annotations

import json

from bounty_core import ErrorStore


def test_record_appends_a_redacted_lane_scoped_error_event(tmp_path):
    store = ErrorStore("ticket-signal", family="web_bounty", lane="web", root_override=tmp_path)

    event = store.record(
        producer="error-intelligence",
        subject="https://tickets.example.test/api/tickets/1?token=do-not-store",
        reason="application returned an unexpected parser failure",
        layer="application",
        channel="http",
        status_or_event="500",
        fingerprint="json-parser-type-error",
        trigger_family="type",
        input_location="body.ticket_id",
        details={"headers": {"authorization": "Bearer do-not-store"}},
    )

    assert event["error_id"].startswith("E-")
    assert "attempt_id" not in event
    assert event["layer"] == "application"
    assert event["subject"] == "https://tickets.example.test/api/tickets/1?token=REDACTED"
    assert event["details"]["headers"]["authorization"] == "REDACTED"
    assert store.events_path == tmp_path / "web_bounty" / "ticket-signal" / "web" / "errors" / "events.jsonl"
    assert json.loads(store.events_path.read_text(encoding="utf-8")) == event


def test_fingerprint_summary_groups_repeated_observations_without_dropping_them(tmp_path):
    store = ErrorStore("ticket-signal", family="web_bounty", lane="web", root_override=tmp_path)
    for subject in ("https://tickets.example.test/api/tickets/1", "https://tickets.example.test/api/tickets/2"):
        store.record(
            producer="error-intelligence",
            subject=subject,
            reason="application returned an unexpected parser failure",
            layer="application",
            channel="http",
            status_or_event="500",
            fingerprint="json-parser-type-error",
            trigger_family="type",
        )

    summary = store.fingerprint_summary()

    assert len(store.query()) == 2
    assert summary == [{
        "fingerprint": "json-parser-type-error",
        "count": 2,
        "first_seen": summary[0]["first_seen"],
        "last_seen": summary[0]["last_seen"],
        "layers": ["application"],
        "channels": ["http"],
    }]
