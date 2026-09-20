from __future__ import annotations

import json
import sqlite3

from bounty_core import BlockerStore, ErrorStore, PublicArtifactStore, append_event, read_events
from bounty_core.hypothesis_ledger import HypothesisLedger
from bounty_core.provenance import AI_REVIEWED_BY_FIELD, merge_ai_reviewers


EXPECTED = [{"agent_id": "map-agent", "model_id": "openai/gpt-5.6"}]


def test_reviewer_tags_are_compact_deduplicated_and_require_both_identifiers() -> None:
    assert merge_ai_reviewers(agent_id="map-agent", model_id="openai/gpt-5.6") == EXPECTED
    assert merge_ai_reviewers(EXPECTED, agent_id="map-agent", model_id="openai/gpt-5.6") == EXPECTED
    assert merge_ai_reviewers(agent_id="map-agent") == []


def test_append_only_core_stores_persist_optional_reviewer_tags(tmp_path) -> None:
    event = append_event(tmp_path / "events.jsonl", {
        "producer": "map-agent", "subject": "https://app.example.test/", "outcome": "observed", "reason": "fixture",
        AI_REVIEWED_BY_FIELD: EXPECTED,
    })
    error = ErrorStore("demo", root_override=tmp_path).record(
        producer="map-agent", model_id="openai/gpt-5.6", subject="https://app.example.test/", reason="fixture",
        layer="application", channel="http", status_or_event="500", fingerprint="fixture", trigger_family="parser",
    )
    blocker = BlockerStore("demo", root_override=tmp_path).record(
        producer="map-agent", model_id="openai/gpt-5.6", run_id="run-1", subject="https://app.example.test/",
        test_scope="fixture", blocker_key="fixture", blocker_type="environment", reason="fixture", unblock_condition="fixture fixed",
    )
    artifact = PublicArtifactStore("demo", root_override=tmp_path).record(
        event="created", producer="map-agent", model_id="openai/gpt-5.6", account_ref="owned", artifact_kind="post",
        url="https://app.example.test/post/1", visibility="private",
    )

    assert read_events(tmp_path / "events.jsonl")[0][AI_REVIEWED_BY_FIELD] == EXPECTED
    assert ErrorStore("demo", root_override=tmp_path).query()[0][AI_REVIEWED_BY_FIELD] == EXPECTED
    assert BlockerStore("demo", root_override=tmp_path).query()[0][AI_REVIEWED_BY_FIELD] == EXPECTED
    assert PublicArtifactStore("demo", root_override=tmp_path).query()[0][AI_REVIEWED_BY_FIELD] == EXPECTED


def test_hypothesis_ledger_stores_optional_reviewer_tag_and_preserves_legacy_default(tmp_path) -> None:
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    tagged = ledger.create(agent_id="map-agent", model_id="openai/gpt-5.6", run_id="run-1", title="tagged", surface="api", tags=[])
    legacy = ledger.create(agent_id="legacy-agent", run_id="run-2", title="legacy", surface="api", tags=[])

    reloaded = HypothesisLedger("demo", root_override=tmp_path)
    visible = reloaded.list_visible(agent_id="map-agent", run_id="run-1", surface="api")
    assert visible[0]["id"] == tagged["id"]
    assert visible[0][AI_REVIEWED_BY_FIELD] == EXPECTED
    legacy_visible = reloaded.list_visible(agent_id="legacy-agent", run_id="run-2", surface="api")[0]
    assert legacy_visible["id"] == legacy["id"]
    assert AI_REVIEWED_BY_FIELD not in legacy_visible


def test_hypothesis_ledger_migrates_pre_attribution_database_without_backfill(tmp_path) -> None:
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    ledger.root.mkdir(parents=True)
    with sqlite3.connect(ledger.db_path) as conn:
        conn.executescript("""
            CREATE TABLE hypotheses (
                id TEXT PRIMARY KEY, parent_id TEXT, title TEXT NOT NULL, surface TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL, expected_chain TEXT,
                next_discriminator TEXT, evidence_refs_json TEXT NOT NULL, status TEXT NOT NULL,
                owner_agent_id TEXT NOT NULL, owner_run_id TEXT NOT NULL, created_at REAL NOT NULL,
                updated_at REAL NOT NULL, completed_at REAL, lead_id TEXT, context_state TEXT NOT NULL DEFAULT 'private'
            );
        """)
        conn.execute(
            "INSERT INTO hypotheses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("H-legacy", None, "legacy", "api", "", json.dumps([]), None, None, json.dumps([]), "candidate",
             "legacy-agent", "run-legacy", 1.0, 1.0, None, None, "private"),
        )

    migrated = HypothesisLedger("demo", root_override=tmp_path)
    visible = migrated.list_visible(agent_id="legacy-agent", run_id="run-legacy", surface="api")[0]
    assert AI_REVIEWED_BY_FIELD not in visible
    with sqlite3.connect(migrated.db_path) as conn:
        columns = {row[1]: row for row in conn.execute("PRAGMA table_info(hypotheses)")}
    assert columns["ai_reviewed_by_json"][4] == "'[]'"

    tagged = migrated.create(agent_id="map-agent", model_id="openai/gpt-5.6", run_id="run-1", title="tagged", surface="api", tags=[])
    reloaded = HypothesisLedger("demo", root_override=tmp_path)
    tagged_visible = next(item for item in reloaded.list_visible(agent_id="map-agent", run_id="run-1", surface="api") if item["id"] == tagged["id"])
    assert tagged_visible[AI_REVIEWED_BY_FIELD] == EXPECTED
