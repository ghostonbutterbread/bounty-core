from __future__ import annotations

import sqlite3

from bounty_core.hypothesis_ledger import HypothesisLedger


def test_private_hypotheses_remain_hidden_until_linked_lead_followup_after_owner_stales(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger(
        "demo",
        family="web_bounty",
        lane="web",
        root_override=tmp_path,
        now=lambda: now[0],
        ttl_seconds=2 * 60 * 60,
    )
    created = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Worker fetches signed export URL",
        url="https://App.Example/export/?b=2&a=1",
        surface="export",
        tags=["pdf", "worker", "signed-url"],
        lead_id="L-export",
    )

    assert ledger.list_visible(agent_id="agent-a", run_id="run-a") == [created]
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []

    now[0] += 2 * 60 * 60 + 1
    reclaimable = ledger.lead_followup(agent_id="agent-b", run_id="run-b", lead_id="L-export")
    assert [item["id"] for item in reclaimable] == [created["id"]]
    assert reclaimable[0]["visibility"] == "reclaimable"
    assert reclaimable[0]["url"] == "https://app.example/export?a=1&b=2"


def test_lead_followup_reveals_only_released_linked_context(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    released = ledger.create(agent_id="agent-a", run_id="run-a", title="Lead branch", surface="export", tags=["worker"], lead_id="L-export")
    ledger.create(agent_id="agent-a", run_id="run-a", title="Private branch", surface="export", tags=["worker"], lead_id="L-export")

    ledger.release(released["id"], agent_id="agent-a", run_id="run-a")

    visible = ledger.lead_followup(agent_id="agent-b", run_id="run-b", lead_id="L-export")
    assert [(item["id"], item["visibility"]) for item in visible] == [(released["id"], "released")]
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export") == []


def test_owner_heartbeat_keeps_untouched_private_backlog_private(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    created = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Cross-account export authorization",
        surface="export",
        tags=["auth", "export"],
    )

    now[0] += 9
    ledger.heartbeat(agent_id="agent-a", run_id="run-a")
    now[0] += 9

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []
    assert ledger.list_visible(agent_id="agent-a", run_id="run-a")[0]["id"] == created["id"]


def test_expired_hypothesis_can_be_reclaimed_and_becomes_private_to_new_owner(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    created = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Delayed PDF consumer",
        surface="export",
        tags=["pdf", "consumer"],
    )
    now[0] += 11

    reclaimed = ledger.reclaim(created["id"], agent_id="agent-b", run_id="run-b")

    assert reclaimed["owner_agent_id"] == "agent-b"
    assert ledger.list_visible(agent_id="agent-a", run_id="run-a") == []
    assert [item["id"] for item in ledger.list_visible(agent_id="agent-b", run_id="run-b")] == [created["id"]]


def test_owner_views_filter_by_normalized_url_and_tags_without_exposing_other_private_work(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    first = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Export worker reachability",
        url="https://app.example/export?z=2&a=1",
        surface="export",
        tags=["worker", "ssrf"],
    )
    ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Invoice IDOR",
        url="https://app.example/invoices/1",
        surface="billing",
        tags=["idor"],
    )
    ledger.create(
        agent_id="agent-b",
        run_id="run-b",
        title="Other agent private work",
        url="https://app.example/export?a=1&z=2",
        surface="export",
        tags=["worker"],
    )

    matches = ledger.list_visible(
        agent_id="agent-a",
        run_id="run-a",
        url="https://APP.EXAMPLE/export?a=1&z=2",
        tags=["worker"],
    )

    assert [item["id"] for item in matches] == [first["id"]]


def test_owner_can_delegate_a_private_branch_without_exposing_it_to_unrelated_agents(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    created = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Test the delayed PDF consumer",
        surface="export",
        tags=["pdf", "consumer"],
    )

    delegated = ledger.delegate(created["id"], agent_id="agent-a", run_id="run-a", child_agent_id="child-a", child_run_id="child-run")

    assert delegated["owner_agent_id"] == "child-a"
    assert ledger.list_visible(agent_id="agent-a", run_id="run-a") == []
    assert [item["id"] for item in ledger.list_visible(agent_id="child-a", run_id="child-run")] == [created["id"]]
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []


def test_non_owner_cannot_discover_stale_terminal_hypotheses_even_with_terminal_status_filter(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    created = ledger.create(agent_id="agent-a", run_id="run-a", title="Finished export path", surface="export", tags=["pdf"])
    ledger.complete(created["id"], agent_id="agent-a", run_id="run-a")
    now[0] += 11

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export", statuses=["completed"]) == []


def test_stale_owner_cannot_complete_a_reclaimable_hypothesis(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    created = ledger.create(agent_id="agent-a", run_id="run-a", title="Export worker", surface="export", tags=["worker"])
    now[0] += 11

    import pytest
    with pytest.raises(PermissionError, match="stale owners"):
        ledger.complete(created["id"], agent_id="agent-a", run_id="run-a")


def test_child_creation_requires_live_ownership_of_the_parent(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    parent = ledger.create(agent_id="agent-a", run_id="run-a", title="Parent", surface="export", tags=["pdf"])

    import pytest
    with pytest.raises(PermissionError, match="only a live parent owner"):
        ledger.create(agent_id="agent-b", run_id="run-b", title="Unauthorized child", surface="export", tags=["worker"], parent_id=parent["id"])


def test_non_owner_discovery_never_exposes_stale_hypotheses(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    ledger.create(agent_id="agent-a", run_id="run-a", title="Export worker", surface="export", tags=["worker"], lead_id="L-export")
    now[0] += 11

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export") == []


def test_fractional_ttl_is_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="positive integer"):
        HypothesisLedger("demo", root_override=tmp_path, ttl_seconds=0.5)


def test_legacy_hypothesis_heartbeats_migrate_to_the_core_namespace(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: 2_000.0)
    ledger.root.mkdir(parents=True)
    with sqlite3.connect(ledger.db_path) as conn:
        conn.execute(
            "CREATE TABLE agent_heartbeats (agent_id TEXT, run_id TEXT, heartbeat_at REAL, expires_at REAL)"
        )
        conn.execute("INSERT INTO agent_heartbeats VALUES (?, ?, ?, ?)", ("agent-a", "run-a", 1_000.0, 9_999.0))

    ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export")

    with sqlite3.connect(ledger.db_path) as conn:
        row = conn.execute(
            "SELECT namespace, subject_id, run_id, expires_at FROM core_heartbeats"
        ).fetchone()
        assert row == ("hypothesis-owner", "agent-a", "run-a", 9_999.0)
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_heartbeats'").fetchone() is None


def test_completion_checkpoint_reports_private_counts_without_injecting_hypothesis_content(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    ledger.create(agent_id="agent-a", run_id="run-a", title="First", surface="export", tags=["pdf"])
    ledger.create(agent_id="agent-a", run_id="run-a", title="Second", surface="export", tags=["auth"])

    checkpoint = ledger.continuation_state(agent_id="agent-a", run_id="run-a", surface="export")

    assert checkpoint == {"private_unresolved_count": 2, "active_count": 0, "surface": "export"}


def test_fresh_owner_can_mark_one_private_hypothesis_active(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    item = ledger.create(agent_id="agent-a", run_id="run-a", title="First", surface="export", tags=[])

    activated = ledger.transition(item["id"], agent_id="agent-a", run_id="run-a", status="active")

    assert activated["status"] == "active"
    assert ledger.continuation_state(agent_id="agent-a", run_id="run-a", surface="export")["active_count"] == 1
