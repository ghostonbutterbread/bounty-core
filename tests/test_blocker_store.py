from __future__ import annotations

import json

import pytest

from bounty_core import BlockerStore


def record_open(store: BlockerStore) -> dict:
    return store.record(
        producer="access-control",
        subject="https://ads.example.test/campaigns",
        test_scope="access-control:horizontal:campaign",
        blocker_key="ads-campaign-fixture:green-magenta",
        blocker_type="owned-fixture",
        reason="selected accounts have no owned ad campaign fixture",
        unblock_condition="create two owned campaigns under separate selected accounts",
        account_refs=["green", "magenta"],
        capability="ads-organization",
        fixture="campaign",
        details={"authorization": "Bearer do-not-store"},
    )


def test_open_blocker_is_redacted_lane_scoped_and_gates_coverage(tmp_path):
    store = BlockerStore("ad-signal", family="web_bounty", lane="web", root_override=tmp_path)

    event = record_open(store)

    assert event["blocker_id"].startswith("B-")
    assert event["details"]["authorization"] == "REDACTED"
    assert store.events_path == tmp_path / "web_bounty" / "ad-signal" / "web" / "blockers" / "events.jsonl"
    assert json.loads(store.events_path.read_text(encoding="utf-8")) == event
    gate = store.coverage_gate(subject=event["subject"], test_scope=event["test_scope"])
    assert gate["coverage_state"] == "blocked"
    assert gate["blockers"][0]["blocker_id"] == event["blocker_id"]


def test_latest_lifecycle_event_resolves_blocker_without_erasing_history(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    opened = record_open(store)
    resolved = store.record(
        producer="account-management",
        subject=opened["subject"],
        test_scope=opened["test_scope"],
        blocker_key=opened["blocker_key"],
        blocker_type="owned-fixture",
        reason="two owned campaigns were created and verified",
        state="resolved",
        account_refs=["green", "magenta"],
        fixture="campaign",
    )

    assert len(store.query()) == 2
    assert store.active(subject=opened["subject"], test_scope=opened["test_scope"]) == []
    assert store.coverage_gate(subject=opened["subject"], test_scope=opened["test_scope"])["coverage_state"] == "unblocked"
    assert resolved["lifecycle"] == "resolved"


def test_blocker_redacts_url_userinfo_in_all_persisted_free_text(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    event = store.record(
        producer="access-control",
        subject="https://alice:s3cr3t@example.test/campaigns",
        test_scope="access-control:horizontal:campaign",
        blocker_key="campaign-fixture",
        blocker_type="owned-fixture",
        reason="normal flow at https://alice:s3cr3t@example.test/ is unavailable",
        unblock_condition="create fixture",
        details={"observed": "https://alice:s3cr3t@example.test/details"},
    )

    persisted = store.events_path.read_text(encoding="utf-8")
    assert "alice:s3cr3t" not in persisted
    assert event["subject"] == "https://REDACTED@example.test/campaigns"
    assert event["details"]["observed"] == "https://REDACTED@example.test/details"


def test_active_scans_full_history_before_applying_result_limit(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    opened = record_open(store)
    resolved = store.record(
        producer="access-control", subject=opened["subject"], test_scope=opened["test_scope"],
        blocker_key=opened["blocker_key"], blocker_type="owned-fixture", reason="old fixture removed",
        state="resolved", fixture="campaign",
    )
    unrelated = {**resolved, "blocker_key": "unrelated", "lifecycle": "resolved"}
    encoded = json.dumps(unrelated, sort_keys=True, separators=(",", ":")) + "\n"
    with store.events_path.open("a", encoding="utf-8") as handle:
        handle.write(encoded * 100_000)
    reopened = store.record(
        producer="access-control", subject=opened["subject"], test_scope=opened["test_scope"],
        blocker_key=opened["blocker_key"], blocker_type="owned-fixture", reason="fixture absent again",
        unblock_condition="create fixture", fixture="campaign",
    )

    active = store.active(subject=opened["subject"], test_scope=opened["test_scope"])
    assert [row["blocker_id"] for row in active] == [reopened["blocker_id"]]


def test_open_blocker_requires_wake_condition_and_rejects_unknown_type(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    with pytest.raises(ValueError, match="unblock_condition"):
        store.record(
            producer="access-control", subject="subject", test_scope="access-control:horizontal",
            blocker_key="key", blocker_type="owned-fixture", reason="missing fixture",
        )
    with pytest.raises(ValueError, match="invalid blocker_type"):
        store.record(
            producer="access-control", subject="subject", test_scope="access-control:horizontal",
            blocker_key="key", blocker_type="made-up", reason="missing fixture",
            unblock_condition="create fixture",
        )
    assert not store.events_path.exists()
