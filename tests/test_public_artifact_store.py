from __future__ import annotations

import fcntl
import json
import multiprocessing
from typing import Any

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
    )


def _record_after_lock_gate(root, kwargs, ready, release, results):
    """Pause this writer immediately before it attempts the real flock."""
    import fcntl

    real_flock = fcntl.flock

    def gated_flock(fd, operation):
        if operation == fcntl.LOCK_EX:
            ready.set()
            if not release.wait(15):
                raise RuntimeError("parent did not release lock gate")
        return real_flock(fd, operation)

    fcntl.flock = gated_flock
    try:
        store = PublicArtifactStore("community-signal", root_override=root)
        try:
            store.record(**kwargs)
        except ValueError as exc:
            results.send(("rejected", str(exc)))
        except Exception as exc:
            results.send(("error", repr(exc)))
        else:
            results.send(("appended", ""))
    finally:
        fcntl.flock = real_flock
        results.close()


def _record_paused_after_read(root, kwargs, ready, release, results):
    store = PublicArtifactStore("community-signal", root_override=root)
    original_latest = store._latest

    def paused_latest(artifact_id):
        latest = original_latest(artifact_id)
        ready.set()
        if not release.wait(15):
            raise RuntimeError("parent did not release read gate")
        return latest

    store._latest = paused_latest
    try:
        results.send(store.record(**kwargs)["event"])
    finally:
        results.close()


def test_latest_read_holds_interprocess_append_lock(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    created = create(store)
    kwargs: dict[str, Any] = dict(
        event="updated", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"],
        url=created["url"], visibility="public",
    )
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    receive, send = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_record_paused_after_read, args=(tmp_path, kwargs, ready, release, send))
    process.start()
    send.close()
    try:
        assert ready.wait(15), "writer never read the latest state"
        with store.events_path.open("a", encoding="utf-8") as handle:
            with pytest.raises(BlockingIOError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        release.set()
        assert receive.poll(15), "writer did not finish"
        assert receive.recv() == "updated"
        process.join(15)
        assert process.exitcode == 0
        store.record(**{**kwargs, "event": "visibility_changed", "visibility": "private"})
        store.record(**{**kwargs, "event": "cleanup_pending", "visibility": "private"})
        assert [row["event"] for row in store.query()] == ["created", "updated", "visibility_changed", "cleanup_pending"]
        assert store.current() == []
    finally:
        release.set()
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(15)
        receive.close()


@pytest.mark.parametrize("scenario", ["cleanup_before_update", "duplicate_creation"])
def test_competing_process_revalidates_after_prior_commit(tmp_path, scenario):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    kwargs: dict[str, Any] = dict(
        producer="public-artifacts", artifact_id="PA-controlled", account_ref="owner",
        artifact_kind="post", url="https://example.test/post/1", visibility="private",
    )
    if scenario == "cleanup_before_update":
        store.record(event="created", **kwargs)
        competing_event, prior_event, rejection = "updated", "cleanup_pending", "cleanup_pending"
        expected_events = ["created", "cleanup_pending"]
    else:
        competing_event, prior_event, rejection = "created", "created", "existing artifact_id"
        expected_events = ["created"]

    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    receive, send = ctx.Pipe(duplex=False)
    process = ctx.Process(
        target=_record_after_lock_gate,
        args=(tmp_path, {**kwargs, "event": competing_event}, ready, release, send),
    )
    process.start()
    send.close()
    try:
        # On the unfixed implementation validation has read stale state here.
        assert ready.wait(15), "writer never reached the lock boundary"
        store.record(event=prior_event, **kwargs)
        release.set()
        assert receive.poll(15), "writer did not finish"
        outcome, detail = receive.recv()
        process.join(15)
        assert process.exitcode == 0
        assert outcome == "rejected", (outcome, detail)
        assert rejection in detail
        assert [row["event"] for row in store.query()] == expected_events
        if scenario == "cleanup_before_update":
            assert store.current() == []
    finally:
        release.set()
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(15)
        receive.close()


def test_record_tracks_non_secret_account_and_artifact_url_in_lane_scoped_store(tmp_path):
    store = PublicArtifactStore("community-signal", family="web_bounty", lane="web", root_override=tmp_path)

    event = create(store)

    assert event["event_id"].startswith("PAE-")
    assert event["artifact_id"].startswith("PA-")
    assert event["account_ref"] == "owned+community@example.test"
    assert event["url"] == "https://community.example.test/posts/42"
    assert event["details"] == {}
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
        event="cleanup_pending", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"],
        url=created["url"], visibility="private",
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
        event="visibility_changed", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"],
        visibility="private",
    )
    store.record(
        event="cleanup_pending", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"],
        visibility="private", cleanup_method="delete",
    )

    assert store.current() == []
    with pytest.raises(ValueError, match="prior deleted"):
        store.record(
            event="cleanup_verified", producer="public-artifacts", artifact_id=created["artifact_id"],
            account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"],
            visibility="private", cleanup_verified=True,
        )


def test_cleanup_state_cannot_be_revived_and_private_visibility_is_set_before_cleanup(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    created = create(store)
    private = store.record(
        event="visibility_changed", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility="private",
    )
    assert store.current() == [private]
    store.record(
        event="cleanup_pending", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility="private",
    )
    for event, visibility in (("updated", "private"), ("visibility_changed", "public")):
        with pytest.raises(ValueError, match="cleanup_pending"):
            store.record(
                event=event, producer="public-artifacts", artifact_id=created["artifact_id"],
                account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility=visibility,
            )
    deleted = store.record(
        event="deleted", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility="private",
    )
    store.record(
        event="cleanup_verified", producer="public-artifacts", artifact_id=created["artifact_id"],
        account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility="private",
        cleanup_verified=True,
    )
    with pytest.raises(ValueError, match="terminal"):
        store.record(
            event="visibility_changed", producer="public-artifacts", artifact_id=created["artifact_id"],
            account_ref=created["account_ref"], artifact_kind=created["artifact_kind"], url=created["url"], visibility="private",
        )
    assert deleted["event"] == "deleted"


def test_lifecycle_validation_rejects_unverified_cleanup_and_credential_bearing_urls(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)
    with pytest.raises(ValueError, match="artifact_id"):
        store.record(
            event="cleanup_verified", producer="public-artifacts", account_ref="owner",
            artifact_kind="post", url="https://alice:secret@example.test/post/1",
        )

    with pytest.raises(ValueError, match="canonical"):
        store.record(
            event="created", producer="public-artifacts", account_ref="owner",
            artifact_kind="post", url="https://alice:secret@example.test/post/1?client_secret=do-not-store", visibility="private",
        )


def test_rejects_bracketed_sensitive_query_keys(tmp_path):
    store = PublicArtifactStore("community-signal", root_override=tmp_path)

    with pytest.raises(ValueError, match="canonical"):
        store.record(
            event="created", producer="public-artifacts", account_ref="owner", artifact_kind="post",
            url="https://community.example.test/post/1?client_secret%5B%5D=review-secret&normal=value",
        )
