"""Regressions at the public-artifact persistence boundary."""
import multiprocessing
import os
from pathlib import Path

import pytest

from bounty_core import PublicArtifactStore


def args(**overrides):
    return {**dict(event="created", producer="public-artifacts", account_ref="owner",
                   artifact_kind="post", url="https://example.test/posts/42",
                   visibility="public"), **overrides}


@pytest.mark.parametrize("url", [
    "https://user:pass@example.test/posts/42", "https://@example.test/posts/42",
    "https://example.test/posts/42?share=opaque", "https://example.test/posts/42#opaque",
    "https://example.test/posts/42?", "https://example.test/posts/42#",
    "file:///posts/42", "https://example.test:bad/posts/42", "https://example.test/\npost",
    "https://example.test\\@other.test/post", "https://example.test%40other.test/post",
    "https://example.test/posts?client_secret%5B%5D=opaque",
])
def test_rejects_noncanonical_url_without_disclosing_input(tmp_path, url):
    store = PublicArtifactStore("program", root_override=tmp_path)
    with pytest.raises(ValueError) as exc:
        store.record(**args(url=url))
    assert url not in str(exc.value)
    assert not store.events_path.exists()


@pytest.mark.parametrize("details", [
    {"note": {"data": "arbitrary-private-body"}}, {"authorization": "Bearer opaque"},
    {"items": ["secret-value"]}, {"share_url": "https://example.test/?share=opaque"},
])
def test_rejects_unstructured_details_without_persisting(tmp_path, details):
    store = PublicArtifactStore("program", root_override=tmp_path)
    with pytest.raises(ValueError) as exc:
        store.record(**args(details=details))
    assert "opaque" not in str(exc.value)
    assert not store.events_path.exists()


@pytest.mark.parametrize("field,value", [
    ("purpose", "Bearer opaque"), ("account_ref", "password=opaque"),
    ("producer", "https://example.test/?key=opaque"),
    ("cleanup_method", "<script>payload</script>"), ("model_id", "token: opaque"),
    ("object_id", "private\nbody"),
])
def test_rejects_obvious_sensitive_or_content_fields_without_echo(tmp_path, field, value):
    store = PublicArtifactStore("program", root_override=tmp_path)
    with pytest.raises(ValueError) as exc:
        store.record(**args(**{field: value}))
    assert value not in str(exc.value)
    assert not store.events_path.exists()


@pytest.mark.parametrize("field,value", [
    ("url", "https://example.test/posts/other"), ("account_ref", "other"),
    ("artifact_kind", "listing"), ("object_id", "other"),
])
def test_rejects_identity_swap_without_losing_public_state(tmp_path, field, value):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args(object_id="42"))
    update = args(event="visibility_changed", artifact_id=created["artifact_id"],
                  visibility="private", **{field: value})
    with pytest.raises(ValueError, match="identity mismatch"):
        store.record(**update)
    assert store.current() == [created]
    assert store.query() == [created]


def test_cleanup_requires_recorded_private_transition_and_pending(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args(object_id="42"))
    common = dict(artifact_id=created["artifact_id"], visibility="private")
    for event in ("updated", "cleanup_pending", "deleted", "cleanup_verified"):
        with pytest.raises(ValueError):
            store.record(**args(event=event, cleanup_verified=event == "cleanup_verified", **common))
    assert store.current() == [created]
    private = store.record(**args(event="visibility_changed", **common))
    assert private["object_id"] == "42"
    with pytest.raises(ValueError, match="identity mismatch"):
        store.record(**args(event="cleanup_pending", object_id="wrong", **common))
    store.record(**args(event="cleanup_pending", **common))
    store.record(**args(event="deleted", **common))
    before = store.events_path.read_bytes()
    with pytest.raises(ValueError, match="identity mismatch"):
        store.record(**args(event="cleanup_verified", url="https://example.test/posts/other",
                            cleanup_verified=True, **common))
    assert store.events_path.read_bytes() == before
    verified = store.record(**args(event="cleanup_verified", cleanup_verified=True, **common))
    assert verified["object_id"] == "42"
    assert store.current(include_cleaned=True) == [verified]


@pytest.mark.parametrize("tail", [b'{"event":', b'{"event": 1}\n', b'{}'])
def test_corrupt_or_torn_history_blocks_all_writes(tmp_path, tail):
    store = PublicArtifactStore("program", root_override=tmp_path)
    store.record(**args())
    with store.events_path.open("ab") as handle:
        handle.write(tail)
    before = store.events_path.read_bytes()
    with pytest.raises(ValueError, match="history"):
        store.record(**args())
    assert store.events_path.read_bytes() == before


def test_fsync_failure_reports_uncertain_append_and_releases_lock(tmp_path, monkeypatch):
    store = PublicArtifactStore("program", root_override=tmp_path)
    original = os.fsync
    def fail(fd):
        raise OSError("injected sync failure")
    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="sync failure"):
        store.record(**args())
    monkeypatch.setattr(os, "fsync", original)
    # A complete row can survive an unacknowledged fsync; it is not claimed lost.
    assert len(store.query()) == 1
    store.record(**args(url="https://example.test/posts/43"))
    assert len(store.query()) == 2


def test_partial_append_blocks_future_writes_without_erasing_evidence(tmp_path, monkeypatch):
    store = PublicArtifactStore("program", root_override=tmp_path)
    store.record(**args())
    original_open = Path.open

    class ShortWriter:
        def __init__(self, file):
            self.file = file
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.file.close()
        def fileno(self):
            return self.file.fileno()
        def write(self, data):
            return self.file.write(data[:10])

    def short_open(path, *a, **kw):
        file = original_open(path, *a, **kw)
        if path == store.events_path and a and a[0] == "ab":
            return ShortWriter(file)
        return file

    monkeypatch.setattr(Path, "open", short_open)
    with pytest.raises(OSError, match="incomplete"):
        store.record(**args(url="https://example.test/posts/43"))
    monkeypatch.setattr(Path, "open", original_open)
    damaged = store.events_path.read_bytes()
    with pytest.raises(ValueError, match="incomplete"):
        store.record(**args(url="https://example.test/posts/44"))
    assert store.events_path.read_bytes() == damaged


def test_cleanup_verification_requires_a_literal_boolean(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    with pytest.raises(ValueError, match="boolean"):
        store.record(**args(cleanup_verified="false"))
    assert not store.events_path.exists()


def gated_identity_writer(root, kwargs, ready, release, conn):
    import fcntl
    old = fcntl.flock
    def gate(fd, op):
        if op == fcntl.LOCK_EX:
            ready.set()
            if not release.wait(15):
                raise RuntimeError("gate timeout")
        return old(fd, op)
    fcntl.flock = gate
    try:
        try:
            PublicArtifactStore("program", root_override=root).record(**kwargs)
        except ValueError as exc:
            conn.send(str(exc))
        else:
            conn.send("accepted")
    finally:
        conn.close()


def test_concurrent_identity_is_rechecked_after_competing_update(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args())
    common = dict(event="updated", artifact_id=created["artifact_id"])
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    recv, send = ctx.Pipe(duplex=False)
    child = ctx.Process(target=gated_identity_writer,
                        args=(tmp_path, args(object_id="other", **common), ready, release, send))
    child.start()
    send.close()
    try:
        assert ready.wait(15)
        store.record(**args(object_id="42", **common))
        release.set()
        assert recv.poll(15)
        assert "identity mismatch" in recv.recv()
        child.join(15)
        assert child.exitcode == 0
        assert [r["object_id"] for r in store.query()] == [None, "42"]
    finally:
        release.set()
        child.join(15)
        if child.is_alive():
            child.terminate()
            child.join(15)
        recv.close()
