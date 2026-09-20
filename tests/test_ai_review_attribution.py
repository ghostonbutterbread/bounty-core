from __future__ import annotations

from bounty_core import BlockerStore, ErrorStore, PublicArtifactStore, append_event
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

    for row in (event, error, blocker, artifact):
        assert row[AI_REVIEWED_BY_FIELD] == EXPECTED


def test_hypothesis_ledger_stores_optional_reviewer_tag_and_preserves_legacy_default(tmp_path) -> None:
    ledger = HypothesisLedger("demo", root_override=tmp_path)
    tagged = ledger.create(agent_id="map-agent", model_id="openai/gpt-5.6", run_id="run-1", title="tagged", surface="api", tags=[])
    legacy = ledger.create(agent_id="legacy-agent", run_id="run-2", title="legacy", surface="api", tags=[])

    assert tagged[AI_REVIEWED_BY_FIELD] == EXPECTED
    assert legacy[AI_REVIEWED_BY_FIELD] == []
