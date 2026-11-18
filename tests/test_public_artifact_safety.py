"""Regressions at the public-artifact persistence boundary."""
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from bounty_core import PublicArtifactStore


def args(**overrides):
    return {**dict(event="created", producer="public-artifacts", account_ref="owner",
                   artifact_kind="post", url="https://example.test/posts/42",
                   visibility="public"), **overrides}


def test_redaction_cannot_change_an_accepted_url_identity(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    url = "https://example.test/posts/token:abc"
    with pytest.raises(ValueError, match="url"):
        store.record(**args(url=url))
    assert not store.events_path.exists()


def baseline_store(tmp_path, name):
    store = PublicArtifactStore("program", root_override=tmp_path)
    store.root.mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent / "fixtures" / "public_artifact_baseline" / f"{name}.jsonl", store.events_path)
    return store, store.current(include_cleaned=True)[0]


def test_legacy_public_pending_can_be_deleted_and_verified_without_claiming_private(tmp_path):
    store, pending = baseline_store(tmp_path, "public_pending")
    common = dict(artifact_id=pending["artifact_id"])
    deleted = store.record(**args(event="deleted", **common))
    assert deleted["visibility"] == "public"
    assert not deleted["cleanup_verified"]
    verified = store.record(**args(event="cleanup_verified", cleanup_verified=True, **common))
    assert verified["visibility"] == "public"
    assert store.current() == []
    assert store.current(include_cleaned=True) == [verified]


def test_direct_public_deletion_is_recorded_without_inventing_private_state(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args())
    common = dict(artifact_id=created["artifact_id"])
    deleted = store.record(**args(event="deleted", **common))
    assert deleted["visibility"] == "public" and not deleted["cleanup_verified"]
    assert store.current() == []
    verified = store.record(**args(event="cleanup_verified", cleanup_verified=True, **common))
    assert verified["visibility"] == "public"


def test_baseline_public_deletion_can_be_verified_without_inventing_private_state(tmp_path):
    store, deleted = baseline_store(tmp_path, "public_deleted")
    verified = store.record(**args(event="cleanup_verified", cleanup_verified=True,
                                   artifact_id=deleted["artifact_id"]))
    assert verified["visibility"] == "public"


def test_explicit_recovery_of_baseline_query_identity_preserves_history(tmp_path):
    store, legacy = baseline_store(tmp_path, "query_created")
    before = store.events_path.read_bytes()
    canonical = "https://example.test/posts/42"
    with pytest.raises(ValueError):
        store.record(**args(event="updated", artifact_id=legacy["artifact_id"], url=canonical))
    recovered = store.recover_legacy_url(artifact_id=legacy["artifact_id"],
        previous_url=legacy["url"], canonical_url=canonical, producer="public-artifacts", identity_confirmed=True)
    assert recovered["url"] == canonical
    assert recovered["recovered_from_event_id"] == legacy["event_id"]
    assert store.events_path.read_bytes().startswith(before)
    assert legacy["url"].encode() not in store.events_path.read_bytes()[len(before):]
    updated = store.record(**args(event="updated", artifact_id=legacy["artifact_id"], url=canonical))
    assert updated["url"] == canonical
    assert store.current() == [updated]


def test_legacy_recovery_rejects_wrong_or_unsafe_identity_without_writing(tmp_path):
    store, legacy = baseline_store(tmp_path, "query_created")
    before = store.events_path.read_bytes()
    for old, new in [("https://example.test/posts/43?view=thread", "https://example.test/posts/42"),
                     (legacy["url"], "https://example.test/posts/42?share=secret")]:
        with pytest.raises(ValueError) as error:
            store.recover_legacy_url(artifact_id=legacy["artifact_id"], previous_url=old,
                                     canonical_url=new, producer="public-artifacts", identity_confirmed=True)
        assert old not in str(error.value) and new not in str(error.value)
        assert store.events_path.read_bytes() == before
    with pytest.raises(ValueError, match="identity confirmation"):
        store.recover_legacy_url(artifact_id=legacy["artifact_id"], previous_url=legacy["url"],
                                 canonical_url="https://example.test/posts/42",
                                 producer="public-artifacts", identity_confirmed=False)
    assert store.events_path.read_bytes() == before


def test_recovery_does_not_allow_rebinding_an_already_canonical_url(tmp_path):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args())
    before = store.events_path.read_bytes()
    with pytest.raises(ValueError, match="noncanonical"):
        store.recover_legacy_url(artifact_id=created["artifact_id"], previous_url=created["url"],
                                 canonical_url="https://example.test/posts/43",
                                 producer="public-artifacts", identity_confirmed=True)
    assert store.events_path.read_bytes() == before


def test_legacy_query_pending_recovery_preserves_state_without_copying_old_secret(tmp_path):
    store, pending = baseline_store(tmp_path, "query_pending")
    before = store.events_path.read_bytes()
    recovered = store.recover_legacy_url(artifact_id=pending["artifact_id"], previous_url=pending["url"],
        canonical_url="https://example.test/posts/42", producer="public-artifacts", identity_confirmed=True)
    assert recovered["event"] == "cleanup_pending" and recovered["visibility"] == "public"
    assert b"EXAMPLE_PRIVATE_VALUE" not in store.events_path.read_bytes()[len(before):]
    assert store.current() == []
    deleted = store.record(**args(event="deleted", artifact_id=pending["artifact_id"]))
    assert deleted["visibility"] == "public"
    verified = store.record(**args(event="cleanup_verified", artifact_id=pending["artifact_id"],
                                   cleanup_verified=True))
    assert verified["cleanup_verified"] is True


@pytest.mark.parametrize("url", [
    "https://user:pass@example.test/posts/42", "https://@example.test/posts/42",
    "https://example.test/posts/42?share=opaque", "https://example.test/posts/42#opaque",
    "https://example.test/posts/42?", "https://example.test/posts/42#",
    "file:///posts/42", "https://example.test:bad/posts/42", "https://example.test/\npost",
    "https://example.test\\@other.test/post", "https://example.test%40other.test/post",
    "https://example.test/posts?client_secret%5B%5D=opaque",
    " https://example.test/posts/42", "https://example.test/posts/42 ",
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


@pytest.mark.parametrize("purpose", [
    "Test rendering: display name",
    "Compare renders (desktop & mobile): pass!",
    "Compare https://example.test/posts/42: display name",
])
def test_accepts_non_secret_purpose_prose_and_urls(tmp_path, purpose):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args(purpose=purpose))
    assert created["purpose"] == purpose
    assert store.current() == [created]


@pytest.mark.parametrize("purpose", [
    "Authorization: Bearer actual-value",
    "password: actual-value",
    "https://user:actual-value@example.test/posts/42",
    "https://example.test/posts/42?share=actual-value",
])
def test_rejects_credentials_and_sensitive_share_link_in_prose(tmp_path, purpose):
    store = PublicArtifactStore("program", root_override=tmp_path)
    with pytest.raises(ValueError) as exc:
        store.record(**args(purpose=purpose))
    assert "actual-value" not in str(exc.value)
    assert not store.events_path.exists()


def test_published_bbh_cli_accepts_original_purpose(tmp_path):
    cli = os.environ.get("BBH_PUBLIC_ARTIFACT_CLI")
    if not cli:
        pytest.skip("set BBH_PUBLIC_ARTIFACT_CLI to the published BBH CLI source")
    assert cli is not None
    result = subprocess.run(
        [sys.executable, cli, "--root", str(tmp_path), "record", "--program", "program",
         "--event", "created", "--account-ref", "owner", "--artifact-kind", "post",
         "--url", "https://example.test/posts/42", "--visibility", "public",
         "--purpose", "Test rendering: display name"],
        capture_output=True, text=True, env=os.environ.copy(), check=True,
    )
    event = json.loads(result.stdout)
    assert event["purpose"] == "Test rendering: display name"
    assert PublicArtifactStore("program", root_override=tmp_path).current() == [event]


@pytest.mark.parametrize("label", [
    "client_secret: synthetic-example-value", "client-secret=synthetic-example-value",
    "CLIENT_SECRET = synthetic-example-value", "client-secret: synthetic-example-value",
    "x_api_key: synthetic-example-value", "x-api-key=synthetic-example-value",
    "X_API_KEY = synthetic-example-value", "x-api-key: synthetic-example-value",
])
@pytest.mark.parametrize("field", ["purpose", "cleanup_method", "account_ref", "object_id", "model_id"])
def test_rejects_labeled_credentials_without_echo_or_write(tmp_path, field, label):
    store = PublicArtifactStore("program", root_override=tmp_path)
    created = store.record(**args())
    before = store.events_path.read_bytes()
    with pytest.raises(ValueError) as exc:
        store.record(**args(event="updated", artifact_id=created["artifact_id"], **{field: label}))
    assert label not in str(exc.value) and "synthetic-example-value" not in str(exc.value)
    assert store.events_path.read_bytes() == before


@pytest.mark.parametrize("purpose", [
    "Test password reset rendering", "Review session cookie display",
    "Test rendering [desktop] at 75%", "Compare value = expected [100%]",
    "Test rendering: display name",
])
def test_cli_accepts_harmless_descriptions(tmp_path, purpose):
    cli = os.environ.get("BBH_PUBLIC_ARTIFACT_CLI")
    if not cli:
        pytest.skip("set BBH_PUBLIC_ARTIFACT_CLI to the published BBH CLI source")
    assert cli is not None
    result = subprocess.run(
        [sys.executable, cli, "--root", str(tmp_path), "record", "--program", "program",
         "--event", "created", "--account-ref", "owner", "--artifact-kind", "post",
         "--url", "https://example.test/posts/42", "--visibility", "public", "--purpose", purpose],
        capture_output=True, text=True, env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stderr
    event = json.loads(result.stdout)
    assert event["purpose"] == purpose
    assert PublicArtifactStore("program", root_override=tmp_path).current() == [event]


@pytest.mark.parametrize("purpose", [
    "client_secret: synthetic-example-value", "client_secret=synthetic-example-value",
    "client-secret: synthetic-example-value", "client-secret=synthetic-example-value",
    "x_api_key: synthetic-example-value", "x_api_key=synthetic-example-value",
    "x-api-key: synthetic-example-value", "x-api-key=synthetic-example-value",
    "https://user:synthetic-example-value@example.test/posts/42",
    "https://example.test/posts/42?share=synthetic-example-value",
])
def test_cli_rejects_sensitive_purpose_without_echo_or_write(tmp_path, purpose):
    cli = os.environ.get("BBH_PUBLIC_ARTIFACT_CLI")
    if not cli:
        pytest.skip("set BBH_PUBLIC_ARTIFACT_CLI to the published BBH CLI source")
    assert cli is not None
    store = PublicArtifactStore("program", root_override=tmp_path)
    store.record(**args())
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = subprocess.run(
        [sys.executable, cli, "--root", str(tmp_path), "record", "--program", "program",
         "--event", "created", "--account-ref", "owner", "--artifact-kind", "post",
         "--url", "https://example.test/posts/42", "--visibility", "public", "--purpose", purpose],
        capture_output=True, text=True, env=os.environ.copy(),
    )
    assert result.returncode != 0
    assert "synthetic-example-value" not in result.stdout + result.stderr
    assert purpose not in result.stdout + result.stderr
    assert {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


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
