from __future__ import annotations

import json

import pytest

from bounty_core import PublicArtifactStore


def create(store: PublicArtifactStore) -> dict:
    return store.record(
        event="created",
        producer="public-artifacts",
        account_ref="owned+community@example.test",
        artifact_kind="community-post",
        url="https://community.example.test/posts/42",
        object_id="42",
        visibility="public",
        purpose="owned renderer comparison",
        cleanup_method="delete",
        details={"authorization": "Bearer do-not-store"},
    )


def test_record_tracks_non_secret_account_and_artifact_url_in_lane_scoped_store(tmp_path):
    store = PublicArtifactStore("community-signal", family="web_bounty", lane="web", root_override=tmp_path)

    event = create(store)

    assert event["event_id"].startswith("PAE-")
    assert event["artifact_id"].startswith("PA-")
    assert event["account_ref"] == "owned+community@example.test"
    assert event["url"] == "https://community.example.test/posts/42"
    assert event["details"]["authorization"] == "REDACTED"
    assert store.events_path == tmp_path / "web_bounty" / "community-signal" / "web" / "public_artifacts" / "events.jsonl"
    assert json.loads(store.events_path.read_text(encoding="utf-8")) == event


def test_current_returns_one_latest_reusable_artifact_and_keeps_cleanup_history(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    created = create(store)
    changed = store.record(
        event="visibility_changed",
        producer="public-artifacts",
        artifact_id=created["artifact_id"],
        account_ref=created["account_ref"],
        artifact_kind=created["artifact_kind"],
        url=created["url"],
        visibility="private",
        purpose="reuse for a private comparison",
        cleanup_method="delete",
    )
    store.record(
        event="deleted",
        producer="public-artifacts",
        artifact_id=created["artifact_id"],
        account_ref=created["account_ref"],
        artifact_kind=created["artifact_kind"],
        url=created["url"],
        visibility="private",
        cleanup_method="delete",
    )
    store.record(
        event="cleanup_verified",
        producer="public-artifacts",
        artifact_id=created["artifact_id"],
        account_ref=created["account_ref"],
        artifact_kind=created["artifact_kind"],
        url=created["url"],
        visibility="private",
        cleanup_method="delete",
        cleanup_verified=True,
    )

    assert store.query(where={"artifact_id": created["artifact_id"]})[1]["event_id"] == changed["event_id"]
    assert store.current() == []
    assert store.current(include_cleaned=True)[0]["event"] == "cleanup_verified"


def test_cleanup_pending_is_not_reusable_and_cleanup_verification_requires_its_deleted_artifact(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    created = create(store)
    with pytest.raises(ValueError, match="artifact_id"):
        store.record(
            event="cleanup_verified", producer="public-artifacts", account_ref=created["account_ref"],
            artifact_kind=created["artifact_kind"], url=created["url"], cleanup_verified=True,
        )
    store.record(
        event="cleanup_pending", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"],
        visibility="public", cleanup_method="delete",
    )

    assert store.current() == []
    with pytest.raises(ValueError, match="prior deleted"):
        store.record(
            event="cleanup_verified", producer="public-artifacts", artifact_id=created["artifact_id"],
            account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"],
            cleanup_verified=True,
        )


def test_lifecycle_validation_rejects_unverified_cleanup_and_credential_bearing_values_are_redacted(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    with pytest.raises(ValueError, match="artifact_id"):
        store.record(
            event="cleanup_verified", producer="public-artifacts", account_ref="owner",
            artifact_kind="post", url="https://alice:secret@example.test/post/1",
        )

    event = store.record(
        event="created", producer="public-artifacts", account_ref="owner",
        artifact_kind="post", url="https://alice:secret@example.test/post/1?client_secret=do-not-store", visibility="private",
        purpose="Bearer do-not-store",
    )
    serialized = json.dumps(event)
    assert "alice" not in serialized
    assert "do-not-store" not in serialized
    assert event["url"] == "https://REDACTED@example.test/post/1?client_secret=REDACTED"
