from __future__ import annotations

from bounty_core.hypothesis_ledger import HypothesisLedger


def test_creator_private_hypotheses_are_hidden_until_owner_stales(tmp_path):
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
    )

    assert ledger.list_visible(agent_id="agent-a", run_id="run-a") == [created]
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []

    now[0] += 2 * 60 * 60 + 1
    reclaimable = ledger.list_visible(agent_id="agent-b", run_id="run-b")
    assert [item["id"] for item in reclaimable] == [created["id"]]
    assert reclaimable[0]["visibility"] == "reclaimable"
    assert reclaimable[0]["url"] == "https://app.example/export?a=1&b=2"


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


def test_completion_checkpoint_reports_private_counts_without_injecting_hypothesis_content(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    ledger.create(agent_id="agent-a", run_id="run-a", title="First", surface="export", tags=["pdf"])
    ledger.create(agent_id="agent-a", run_id="run-a", title="Second", surface="export", tags=["auth"])

    checkpoint = ledger.continuation_state(agent_id="agent-a", run_id="run-a", surface="export")

    assert checkpoint == {"private_unresolved_count": 2, "active_count": 0, "surface": "export"}
