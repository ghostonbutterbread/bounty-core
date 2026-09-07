from __future__ import annotations

import json

import pytest

from bounty_core import BlockerStore


def record_open(store: BlockerStore, *, run_id: str = "run-ads-fixture") -> dict:
    return store.record(
        producer="access-control", run_id=run_id,
        subject="https://ads.example.test/campaigns",
        test_scope="access-control:horizontal:campaign",
        blocker_key="ads-campaign-fixture:green-magenta",
        blocker_type="owned-fixture",
        reason="selected accounts have no owned ad campaign fixture",
        unblock_condition="create two owned campaigns under separate selected accounts",
        account_refs=["green", "magenta"], capability="ads-organization", fixture="campaign",
        details={"authorization": "Bearer do-not-store"},
    )


def test_open_blocker_is_redacted_and_lane_scoped(tmp_path):
    store = BlockerStore("ad-signal", family="web_bounty", lane="web", root_override=tmp_path)
    event = record_open(store)

    assert event["blocker_id"].startswith("B-")
    assert event["run_id"] == "run-ads-fixture"
    assert event["details"]["authorization"] == "REDACTED"
    assert store.events_path == tmp_path / "web_bounty" / "ad-signal" / "web" / "blockers" / "events.jsonl"
    assert json.loads(store.events_path.read_text(encoding="utf-8")) == event
    assert store.active(subject=event["subject"], test_scope=event["test_scope"])[0]["blocker_id"] == event["blocker_id"]


def test_completion_brief_only_lists_current_run_open_blockers(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    current = record_open(store, run_id="run-current")
    record_open(store, run_id="run-other")
    store.record(
        producer="account-management", run_id="run-resolution",
        subject=current["subject"], test_scope=current["test_scope"], blocker_key=current["blocker_key"],
        blocker_type="owned-fixture", reason="fixture created and verified", state="resolved",
    )
    current_open = store.record(
        producer="access-control", run_id="run-current", subject="https://ads.example.test/exports",
        test_scope="access-control:horizontal:export", blocker_key="export-fixture",
        blocker_type="owned-fixture", reason="no owned export", unblock_condition="create owned export",
    )

    brief = store.brief(run_id="run-current")
    assert brief["open_blocker_count"] == 1
    assert brief["open_blockers"][0]["blocker_id"] == current_open["blocker_id"]


def test_blocker_redacts_url_userinfo_in_all_persisted_free_text(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    event = store.record(
        producer="access-control", run_id="run-url-redaction",
        subject="https://alice:s3cr3t@example.test/campaigns", test_scope="access-control:horizontal:campaign",
        blocker_key="campaign-fixture", blocker_type="owned-fixture",
        reason="normal flow at https://alice:s3cr3t@example.test/ is unavailable",
        unblock_condition="create fixture", details={"observed": "https://alice:s3cr3t@example.test/details"},
    )

    persisted = store.events_path.read_text(encoding="utf-8")
    assert "alice:s3cr3t" not in persisted
    assert event["subject"] == "https://REDACTED@example.test/campaigns"
    assert event["details"]["observed"] == "https://REDACTED@example.test/details"


def test_active_scans_full_history_before_applying_result_limit(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    opened = record_open(store)
    resolved = store.record(
        producer="access-control", run_id="run-resolution", subject=opened["subject"], test_scope=opened["test_scope"],
        blocker_key=opened["blocker_key"], blocker_type="owned-fixture", reason="old fixture removed", state="resolved",
    )
    unrelated = {**resolved, "blocker_key": "unrelated", "lifecycle": "resolved"}
    with store.events_path.open("a", encoding="utf-8") as handle:
        handle.write((json.dumps(unrelated, sort_keys=True, separators=(",", ":")) + "\n") * 100_000)
    reopened = record_open(store, run_id="run-reopened")

    assert [row["blocker_id"] for row in store.active(subject=opened["subject"], test_scope=opened["test_scope"])] == [reopened["blocker_id"]]


def test_legacy_events_remain_visible_and_resolve_lifecycle(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    store.root.mkdir(parents=True)
    legacy_open = {
        "schema_version": 1, "blocker_id": "B-legacy-open", "timestamp": "2026-01-01T00:00:00Z",
        "producer": "access-control", "subject": "legacy-subject", "test_scope": "legacy-scope",
        "blocker_key": "legacy-key", "blocker_type": "owned-fixture", "reason": "missing fixture",
        "lifecycle": "open", "unblock_condition": "human setup", "account_refs": [], "details": {},
    }
    legacy_resolved = {**legacy_open, "blocker_id": "B-legacy-resolved", "timestamp": "2026-01-02T00:00:00Z", "lifecycle": "resolved", "reason": "fixture now exists", "unblock_condition": None}
    store.events_path.write_text(json.dumps(legacy_open) + "\n" + json.dumps(legacy_resolved) + "\n", encoding="utf-8")

    assert len(store.query()) == 2
    assert store.active(subject="legacy-subject", test_scope="legacy-scope") == []
    assert store.brief(run_id="new-run")["open_blockers"] == []


def test_open_blocker_requires_wake_condition_run_id_and_known_type(tmp_path):
    store = BlockerStore("ad-signal", root_override=tmp_path)
    with pytest.raises(TypeError):
        store.record(producer="access-control", subject="subject", test_scope="scope", blocker_key="key", blocker_type="owned-fixture", reason="missing fixture")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="unblock_condition"):
        store.record(producer="access-control", run_id="run", subject="subject", test_scope="scope", blocker_key="key", blocker_type="owned-fixture", reason="missing fixture")
    assert not store.events_path.exists()
