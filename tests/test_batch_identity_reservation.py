import json
import multiprocessing
from collections import UserDict
from unittest.mock import patch

import pytest

from bounty_core.ledger import VersionedFindingsLedger


def make_ledger(tmp_path):
    return VersionedFindingsLedger(
        "synthetic", target_root=tmp_path, root_override=tmp_path,
        family="binaries", lane="apk", snapshot_identity={"snapshot_id": "s1", "version_label": "v1"},
        run_id="r1", agent="test",
    )


def candidate(name, fid=None):
    result = {"file": f"src/{name}.py", "line": 1, "class_name": "idor", "type": name}
    if fid is not None:
        result["fid"] = fid
    return result


def test_late_existing_fid_conflict_leaves_bytes_unchanged(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("existing", "D06"))
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="finding FID already assigned: D06"):
        ledger.reserve_batch([candidate("first", "D07"), candidate("other", "D06")])
    assert ledger.path.read_bytes() == before


def test_within_batch_conflict_leaves_bytes_unchanged(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("seed", "D01"))
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="finding FID already assigned: D08"):
        ledger.reserve_batch([candidate("first", "D08"), candidate("other", "D08")])
    assert ledger.path.read_bytes() == before


def test_duplicate_precedes_explicit_fid_conflict_and_generated_ids_follow_order(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("existing", "D06"))
    duplicate = candidate("existing", "D07")
    results = ledger.reserve_batch([candidate("new"), duplicate, candidate("third"), candidate("new", "D06")])
    assert [(exists, fid) for exists, fid, _ in results] == [
        (False, "D07"), (True, "D06"), (False, "D08"), (True, "D07")
    ]
    assert [row["fid"] for row in json.loads(ledger.path.read_text())["findings"]] == ["D06", "D07", "D08"]
    assert results[0][2]["run_id"] == "r1"
    assert results[1][2]["file"] == "src/existing.py"


def test_missing_line_and_type_uses_legacy_loose_duplicate_lookup(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("existing", "D06"))
    results = ledger.reserve_batch([{"file": "src/existing.py", "class_name": "idor", "fid": "D99"}])
    assert results[0][:2] == (True, "D06")


def test_success_uses_one_atomic_replacement_and_preserves_order(tmp_path):
    import bounty_core.ledger as module
    ledger = make_ledger(tmp_path)
    with patch.object(module, "_write_json_atomic", wraps=module._write_json_atomic) as write:
        results = ledger.reserve_batch([candidate("a"), candidate("b")])
    assert write.call_count == 1
    assert [result[:2] for result in results] == [(False, "D01"), (False, "D02")]
    assert [row["fid"] for row in json.loads(ledger.path.read_text())["findings"]] == ["D01", "D02"]


def test_late_invalid_fid_does_not_write(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("seed", "D01"))
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="unsafe finding FID"):
        ledger.reserve_batch([candidate("first", "D02"), candidate("bad", "../unsafe")])
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("invalid", [[], [("file", "src/fabricated.py")], (), None, "bad", UserDict({"file": "src/x.py"})])
def test_late_non_dict_candidate_does_not_write(tmp_path, invalid):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("seed", "D01"))
    before = ledger.path.read_bytes()
    first = candidate("first", "D02")
    with patch("bounty_core.ledger._write_json_atomic") as write:
        with pytest.raises(ValueError, match=r"candidate at index 1 must be a dictionary"):
            ledger.reserve_batch([first, invalid])
    write.assert_not_called()
    assert ledger.path.read_bytes() == before
    assert first == candidate("first", "D02")


def test_batch_accepts_dict_subclasses_without_mutating_input(tmp_path):
    import copy

    class Finding(dict):
        pass

    first = Finding(candidate("first"), tags=["original"])
    second = candidate("first", "D99")
    incoming = [first, second, candidate("last")]
    before = copy.deepcopy(incoming)
    results = make_ledger(tmp_path).reserve_batch(incoming)
    assert [(exists, fid) for exists, fid, _ in results] == [
        (False, "D01"), (True, "D01"), (False, "D02")
    ]
    assert incoming == before


def test_write_failure_propagates_and_original_ledger_survives(tmp_path):
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("seed", "D01"))
    before = ledger.path.read_bytes()
    with patch("bounty_core.ledger.Path.replace", side_effect=OSError("injected replace failure")):
        with pytest.raises(OSError, match="injected replace failure"):
            ledger.reserve_batch([candidate("new", "D02")])
    assert ledger.path.read_bytes() == before


def test_single_check_regression_and_batch_bounds(tmp_path):
    ledger = make_ledger(tmp_path)
    assert ledger.check(candidate("single"))[:2] == (False, "D01")
    assert ledger.check(candidate("single", "D99"))[:2] == (True, "D01")
    before = ledger.path.read_bytes()
    assert ledger.reserve_batch([]) == []
    with pytest.raises(ValueError, match="at most 1000"):
        ledger.reserve_batch([candidate("single")] * 1001)
    assert ledger.path.read_bytes() == before


def _batch_writer(root, phase, entered, release, output):
    import bounty_core.ledger as module
    ledger = make_ledger(root)
    original_write = module._write_json_atomic
    original_lookup = module._find_existing

    def wait_for_release():
        entered.set()
        if not release.wait(10):
            raise RuntimeError("test release timeout")

    def paused_write(path, payload):
        if phase == "pre-replace":
            wait_for_release()
        return original_write(path, payload)

    def paused_lookup(findings, finding):
        if phase == "validation" and finding.get("file") == "src/second.py":
            assert any(item.get("fid") == "D07" for item in findings)
            wait_for_release()
        return original_lookup(findings, finding)

    try:
        with patch.object(module, "_write_json_atomic", paused_write), patch.object(module, "_find_existing", paused_lookup):
            output.put(("batch", ledger.reserve_batch([candidate("first", "D07"), candidate("second", "D08")])))
    except Exception as exc:
        output.put(("batch-error", repr(exc)))


def _competing_writer(root, blocked, done, output):
    import fcntl
    import bounty_core.ledger as module
    ledger = make_ledger(root)
    original_flock = module.fcntl.flock

    def prove_contention(fd, operation):
        if operation == fcntl.LOCK_SH:
            try:
                original_flock(fd, operation | fcntl.LOCK_NB)
            except BlockingIOError:
                blocked.set()
            else:
                raise AssertionError("competing acquisition succeeded while batch was paused")
        return original_flock(fd, operation)

    try:
        with patch.object(module.fcntl, "flock", prove_contention):
            output.put(("competitor", ledger.check(candidate("other", "D08"))[:2]))
    except Exception as exc:
        output.put(("competitor-error", repr(exc)))
    finally:
        done.set()


@pytest.mark.parametrize("phase", ["validation", "pre-replace"])
def test_competing_writer_waits_for_entire_batch(tmp_path, phase):
    ctx = multiprocessing.get_context("fork")
    entered, release, blocked, done = (ctx.Event() for _ in range(4))
    output = ctx.Queue()
    ledger = make_ledger(tmp_path)
    ledger.check(candidate("seed", "D01"))
    batch = ctx.Process(target=_batch_writer, args=(tmp_path, phase, entered, release, output))
    competitor = ctx.Process(target=_competing_writer, args=(tmp_path, blocked, done, output))
    batch.start()
    try:
        assert entered.wait(10), "batch failed to reach pause"
        competitor.start()
        assert blocked.wait(10), "competitor never observed a nonblocking flock failure"
        assert not done.is_set(), "competitor finished while batch held the lock"
    finally:
        release.set()
        batch.join(15)
        if competitor.pid:
            competitor.join(15)
        for proc in (batch, competitor):
            if proc.pid and proc.is_alive():
                proc.terminate()
                proc.join()
    assert batch.exitcode == 0 and competitor.exitcode == 0
    results = dict(output.get(timeout=5) for _ in range(2))
    assert [item[:2] for item in results["batch"]] == [(False, "D07"), (False, "D08")]
    assert "finding FID already assigned: D08" in results["competitor-error"]
    assert [row["fid"] for row in json.loads(ledger.path.read_text())["findings"]] == ["D01", "D07", "D08"]
