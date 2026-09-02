from __future__ import annotations

import sqlite3

from bounty_core.hypothesis_ledger import HypothesisLedger, UNRESOLVED_STATUSES


def test_current_surface_review_requires_exact_scope_and_includes_active_peers_without_mutation(tmp_path):
    import pytest

    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0])
    mine = ledger.create(agent_id="agent-a", run_id="run-a", title="Mine", surface="export", url="https://app.example/export?a=1&b=2", tags=["pdf"])
    peer = ledger.create(agent_id="agent-b", run_id="run-b", title="Peer", surface="export", url="https://APP.example/export?b=2&a=1", tags=["pdf", "worker"])
    wrong_url = ledger.create(agent_id="agent-c", run_id="run-c", title="Wrong URL", surface="export", url="https://app.example/export?a=2", tags=["pdf"])
    terminal = ledger.create(agent_id="agent-d", run_id="run-d", title="Terminal", surface="export", url="https://app.example/export?a=1&b=2", tags=["pdf"])
    ledger.complete(terminal["id"], agent_id="agent-d", run_id="run-d")
    with sqlite3.connect(ledger.db_path) as conn:
        before = {row[0]: (row[1], row[2]) for row in conn.execute("SELECT id, status, updated_at FROM hypotheses")}

    with pytest.raises(ValueError, match="surface is required"):
        ledger.review_current_surface(viewer_agent_id="viewer", viewer_run_id="run", surface=" ", url="https://app.example/export", review_intent="current-surface-peer-history")
    with pytest.raises(ValueError, match="review_intent"):
        ledger.review_current_surface(viewer_agent_id="viewer", viewer_run_id="run", surface="export", url="https://app.example/export?a=1&b=2", review_intent="wrong")

    result = ledger.review_current_surface(viewer_agent_id="viewer", viewer_run_id="run", surface="export", url="https://APP.example/export?b=2&a=1", tags=["pdf"], review_intent="current-surface-peer-history")

    assert result["review_scope"] == "peer-current-surface"
    assert result["query"] == {"surface": "export", "url": "https://app.example/export?a=1&b=2", "tags": ["pdf"], "statuses": sorted(UNRESOLVED_STATUSES)}
    assert {item["id"] for item in result["results"]} == {mine["id"], peer["id"]}
    assert result["total_matching_count"] == result["returned_count"] == 2
    assert all(item["id"] not in {wrong_url["id"], terminal["id"]} for item in result["results"])
    with sqlite3.connect(ledger.db_path) as conn:
        after = {row[0]: (row[1], row[2]) for row in conn.execute("SELECT id, status, updated_at FROM hypotheses")}
        event, payload = conn.execute("SELECT event, payload_json FROM hypothesis_events ORDER BY sequence DESC LIMIT 1").fetchone()
    assert after == before
    assert event == "peer_surface_reviewed"
    assert "Mine" not in payload and "Peer" not in payload


def test_current_surface_review_pagination_is_stable_and_private_list_emits_no_review_event(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0])
    items = []
    for title in ("one", "two", "three"):
        now[0] += 1
        items.append(ledger.create(agent_id="peer", run_id=title, title=title, surface="export", url="https://app.example/export", tags=[]))
    ledger.list_visible(agent_id="peer", run_id="one")
    with sqlite3.connect(ledger.db_path) as conn:
        baseline = conn.execute("SELECT count(*) FROM hypothesis_events WHERE event='peer_surface_reviewed'").fetchone()[0]

    first = ledger.review_current_surface(viewer_agent_id="reviewer", viewer_run_id="review", surface="export", url="https://app.example/export", review_intent="current-surface-peer-history", limit=2)
    second = ledger.review_current_surface(viewer_agent_id="reviewer", viewer_run_id="review", surface="export", url="https://app.example/export", review_intent="current-surface-peer-history", limit=2, cursor=first["cursor"])

    assert [item["id"] for item in first["results"] + second["results"]] == [item["id"] for item in reversed(items)]
    assert first["has_more"] is True and second["has_more"] is False
    assert first["total_matching_count"] == second["total_matching_count"] == 3
    with sqlite3.connect(ledger.db_path) as conn:
        assert conn.execute("SELECT count(*) FROM hypothesis_events WHERE event='peer_surface_reviewed'").fetchone()[0] == baseline + 2


def test_operator_app_review_validates_marker_and_request_id_and_groups_paginated_peers(tmp_path):
    import pytest

    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0])
    first = ledger.create(agent_id="agent-a", run_id="run-a", title="Export", surface="export", url="https://app.example/export", tags=[])
    now[0] += 1
    second = ledger.create(agent_id="agent-b", run_id="run-b", title="Billing", surface="billing", url="https://app.example/billing", tags=[])
    done = ledger.create(agent_id="agent-c", run_id="run-c", title="Done", surface="billing", url="https://app.example/billing", tags=[])
    ledger.complete(done["id"], agent_id="agent-c", run_id="run-c")

    with pytest.raises(ValueError, match="operator_request_id is required"):
        ledger.operator_app_review(actor_agent_id="operator", actor_run_id="run", operator_request_id=" ", operator_intent="application-thinking-review")
    with pytest.raises(ValueError, match="operator_intent"):
        ledger.operator_app_review(actor_agent_id="operator", actor_run_id="run", operator_request_id="request-1", operator_intent="wrong")

    page = ledger.operator_app_review(actor_agent_id="operator", actor_run_id="run", operator_request_id="request-1", operator_intent="application-thinking-review", limit=1)
    tail = ledger.operator_app_review(actor_agent_id="operator", actor_run_id="run", operator_request_id="request-1", operator_intent="application-thinking-review", limit=1, cursor=page["cursor"])

    assert page["review_scope"] == "operator-app-wide"
    assert page["operator_request_id"] == "request-1"
    assert page["total_matching_count"] == tail["total_matching_count"] == 2
    assert [item["id"] for item in page["results"] + tail["results"]] == [second["id"], first["id"]]
    assert page["surface_counts"] == {"billing": 1, "export": 1}
    with sqlite3.connect(ledger.db_path) as conn:
        event, payload = conn.execute("SELECT event, payload_json FROM hypothesis_events ORDER BY sequence DESC LIMIT 1").fetchone()
    assert event == "operator_app_reviewed"
    assert "Export" not in payload and "Billing" not in payload


def test_review_indexes_migrate_legacy_hypotheses_without_data_loss(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    ledger.root.mkdir(parents=True)
    with sqlite3.connect(ledger.db_path) as conn:
        conn.executescript("""
            CREATE TABLE hypotheses (id TEXT PRIMARY KEY, parent_id TEXT, title TEXT NOT NULL, surface TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL, expected_chain TEXT, next_discriminator TEXT, evidence_refs_json TEXT NOT NULL, status TEXT NOT NULL, owner_agent_id TEXT NOT NULL, owner_run_id TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL, completed_at REAL);
            INSERT INTO hypotheses VALUES ('H-old', NULL, 'Legacy', 'export', 'https://app.example/export', '[]', NULL, NULL, '[]', 'candidate', 'a', 'r', 1, 1, NULL);
        """)

    result = ledger.review_current_surface(viewer_agent_id="viewer", viewer_run_id="run", surface="export", url="https://app.example/export", review_intent="current-surface-peer-history")

    assert [item["id"] for item in result["results"]] == ["H-old"]
    with sqlite3.connect(ledger.db_path) as conn:
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(hypotheses)")}
    assert {"idx_hypotheses_review_surface_url", "idx_hypotheses_review_status"} <= indexes


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


def test_release_rejects_unlinked_or_non_owner_hypotheses(tmp_path):
    import pytest

    ledger = HypothesisLedger("demo", root_override=tmp_path)
    unlinked = ledger.create(agent_id="agent-a", run_id="run-a", title="Unlinked", surface="export", tags=[])
    linked = ledger.create(agent_id="agent-a", run_id="run-a", title="Linked", surface="export", tags=[], lead_id="L-export")

    with pytest.raises(ValueError, match="lead-linked"):
        ledger.release(unlinked["id"], agent_id="agent-a", run_id="run-a")
    with pytest.raises(PermissionError, match="current owner"):
        ledger.release(linked["id"], agent_id="agent-b", run_id="run-b")


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


def test_non_owner_generic_discovery_excludes_stale_released_lead_context(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    released = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Released export lead context",
        surface="export",
        tags=["worker"],
        lead_id="L-export",
    )
    ledger.release(released["id"], agent_id="agent-a", run_id="run-a")
    now[0] += 11

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export") == []
    assert [item["id"] for item in ledger.lead_followup(agent_id="agent-b", run_id="run-b", lead_id="L-export")] == [released["id"]]


def test_non_owner_can_discover_stale_unresolved_hypotheses_only_with_a_scope_filter(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    created = ledger.create(
        agent_id="agent-a",
        run_id="run-a",
        title="Export worker",
        url="https://app.example/export?a=1&b=2",
        surface="export",
        tags=["worker"],
    )
    now[0] += 11

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []
    expected = [(created["id"], "reclaimable", False)]
    for visible in (
        ledger.list_visible(agent_id="agent-b", run_id="run-b", url="https://APP.EXAMPLE/export?b=2&a=1"),
        ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export"),
        ledger.list_visible(agent_id="agent-b", run_id="run-b", tags=["worker"]),
    ):
        assert [(item["id"], item["visibility"], item["owner_live"]) for item in visible] == expected


def test_non_owner_cannot_discover_active_peer_hypotheses_or_bypass_scope_with_status(tmp_path):
    now = [1_000.0]
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: now[0], ttl_seconds=10)
    ledger.create(agent_id="agent-a", run_id="run-a", title="Export worker", surface="export", tags=["worker"])

    assert ledger.list_visible(agent_id="agent-b", run_id="run-b") == []
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", surface="export") == []
    assert ledger.list_visible(agent_id="agent-b", run_id="run-b", statuses=["candidate"]) == []


def test_fractional_ttl_is_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="positive integer"):
        HypothesisLedger("demo", root_override=tmp_path, ttl_seconds=0.5)


def test_legacy_hypotheses_migrate_before_lead_index_creation_and_preserve_rows(tmp_path):
    ledger = HypothesisLedger("demo", root_override=tmp_path, now=lambda: 2_000.0)
    ledger.root.mkdir(parents=True)
    with sqlite3.connect(ledger.db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE hypotheses (
                id TEXT PRIMARY KEY,
                parent_id TEXT REFERENCES hypotheses(id),
                title TEXT NOT NULL,
                surface TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL,
                expected_chain TEXT,
                next_discriminator TEXT,
                evidence_refs_json TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_agent_id TEXT NOT NULL,
                owner_run_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                completed_at REAL
            );
            INSERT INTO hypotheses VALUES (
                'H-legacy', NULL, 'Legacy private branch', 'export', '', '[]', NULL,
                NULL, '[]', 'candidate', 'agent-a', 'run-a', 1.0, 1.0, NULL
            );
            """
        )

    visible = ledger.list_visible(agent_id="agent-a", run_id="run-a")

    assert [item["id"] for item in visible] == ["H-legacy"]
    assert visible[0]["lead_id"] is None
    assert visible[0]["context_state"] == "private"
    with sqlite3.connect(ledger.db_path) as conn:
        assert {row[1] for row in conn.execute("PRAGMA table_info(hypotheses)")} >= {"lead_id", "context_state"}
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_hypotheses_lead'").fetchone()

    assert ledger.list_visible(agent_id="agent-a", run_id="run-a")[0]["id"] == "H-legacy"


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
