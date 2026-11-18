"""Synthetic provider contract for atomic report imports."""
import json
import multiprocessing
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from bounty_core.ledger import VersionedFindingsLedger


def ledger(tmp_path):
    return VersionedFindingsLedger(
        'acme', target_root=tmp_path, root_override=tmp_path,
        family='web_bounty', lane='web',
        snapshot_identity={'snapshot_id': 's1', 'version_label': 'v1'},
        run_id='r1', agent='sync-reports')


def candidate():
    return {'file': 'src/app.js', 'line': 12, 'type': 'XSS',
            'class_name': 'xss', 'title': 'XSS', 'description': 'test'}


@pytest.mark.parametrize('mode', ['evidence_only', 'legacy'])
def test_atomic_import_rejects_known_raw_then_retry_succeeds(tmp_path, mode):
    subject = ledger(tmp_path)
    subject.path.parent.mkdir(parents=True)
    baseline = Path(__file__).parent / 'fixtures' / 'baseline_raw_ledger.json'
    subject.path.write_bytes(baseline.read_bytes())
    before = subject.path.read_bytes()
    raw = subject.storage.reports_root / 'raw'
    raw.mkdir(parents=True)
    intake = raw / 'finding.md'
    intake.write_text('original')
    with pytest.raises(ValueError, match='reports/raw'):
        subject.import_finding(candidate(), packet_mode=mode)
    assert subject.path.read_bytes() == before
    assert intake.read_text() == 'original'
    payload = json.loads(before)
    payload['findings'] = []
    subject.path.write_text(json.dumps(payload))
    duplicate, fid, finding = subject.import_finding(candidate(), packet_mode=mode)
    assert not duplicate and fid == 'D01'
    assert Path(finding['evidence_path' if mode == 'evidence_only' else 'report_path']).is_file()
    before = subject.path.read_bytes()
    duplicate, fid, _ = subject.import_finding(candidate(), packet_mode=mode)
    assert duplicate and fid == 'D01'
    assert subject.path.read_bytes() == before
    assert intake.read_text() == 'original'


@pytest.mark.parametrize('mode', ['evidence_only', 'legacy'])
def test_interrupted_materialization_is_resumed_not_skipped(tmp_path, mode):
    subject = ledger(tmp_path)
    with patch('bounty_core.ledger.refresh_indexes', side_effect=OSError('injected failure')):
        with pytest.raises(OSError, match='injected failure'):
            subject.import_finding(candidate(), packet_mode=mode)
    pending = json.loads(subject.path.read_text())['findings'][0]
    assert pending['_atomic_import_pending'] == mode
    assert pending['fid'] == 'D01'
    duplicate, fid, finding = subject.import_finding(candidate(), packet_mode=mode)
    assert not duplicate and fid == 'D01'
    assert '_atomic_import_pending' not in finding
    assert Path(finding['evidence_path' if mode == 'evidence_only' else 'report_path']).is_file()
    assert subject.import_finding(candidate(), packet_mode=mode)[:2] == (True, 'D01')


def test_pending_rejects_wrong_mode_and_retries_after_final_write_failure(tmp_path):
    import bounty_core.ledger as module
    subject = ledger(tmp_path)
    original = module._write_json_atomic
    calls = []
    def fail_final(path, payload):
        calls.append(1)
        if len(calls) == 2:
            raise OSError('final commit failed')
        return original(path, payload)
    with patch.object(module, '_write_json_atomic', side_effect=fail_final):
        with pytest.raises(OSError, match='final commit failed'):
            subject.import_finding(candidate())
    before = subject.path.read_bytes()
    with pytest.raises(ValueError, match='original mode'):
        subject.import_finding(candidate(), packet_mode='legacy')
    assert subject.path.read_bytes() == before
    assert subject.import_finding(candidate())[:2] == (False, 'D01')
    assert subject.import_finding(candidate())[:2] == (True, 'D01')


def test_existing_fid_conflict_is_not_imported(tmp_path):
    subject = ledger(tmp_path)
    assert subject.import_finding(dict(candidate(), fid='D12'))[:2] == (False, 'D12')
    before = subject.path.read_bytes()
    with pytest.raises(ValueError, match='FID already assigned'):
        subject.import_finding(dict(candidate(), fid='D12', file='different.js'))
    assert subject.path.read_bytes() == before


def _competing_raw(root, blocked, queue):
    import fcntl
    from bounty_core.ledger import ledger_add
    original = fcntl.flock
    def observed(fd, operation):
        if operation == fcntl.LOCK_EX:
            try:
                original(fd, operation | fcntl.LOCK_NB)
            except BlockingIOError:
                blocked.set()
                return original(fd, operation)
            else:
                return None
        return original(fd, operation)
    fcntl.flock = observed
    try:
        queue.put(ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3,
                             'type': 'xss', 'class_name': 'xss'}, 's', 'v', 'r', 'a',
                             family='web_bounty', lane='web', root_override=root))
    finally:
        fcntl.flock = original


def _import_before_lock(root, waiting, release, queue):
    import fcntl
    original = fcntl.flock
    def gated(fd, operation):
        if operation == fcntl.LOCK_EX:
            waiting.set()
            if not release.wait(10):
                raise TimeoutError('lock gate not released')
        return original(fd, operation)
    fcntl.flock = gated
    try:
        ledger(root).import_finding(candidate())
        queue.put('success')
    except Exception as exc:
        queue.put((type(exc).__name__, str(exc)))
    finally:
        fcntl.flock = original


def test_competing_raw_before_lock_rejects_without_reservation(tmp_path):
    from bounty_core.ledger import ledger_add
    subject = ledger(tmp_path)
    raw = subject.storage.reports_root / 'raw'
    raw.mkdir(parents=True)
    intake = raw / 'finding.md'
    intake.write_text('intact')
    ctx = multiprocessing.get_context('spawn')
    waiting, release, queue = ctx.Event(), ctx.Event(), ctx.Queue()
    process = ctx.Process(target=_import_before_lock, args=(tmp_path, waiting, release, queue))
    process.start()
    try:
        assert waiting.wait(10)
        assert ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3,
                          'type': 'xss', 'class_name': 'xss'}, 's', 'v', 'r', 'a',
                          family='web_bounty', lane='web', root_override=tmp_path) == (True, 'raw')
        before = subject.path.read_bytes()
        release.set()
        process.join(10)
        assert process.exitcode == 0
        kind, message = queue.get(timeout=5)
        assert kind == 'ValueError' and 'reports/raw' in message
        assert subject.path.read_bytes() == before
        assert intake.read_text() == 'intact'
    finally:
        release.set()
        if process.is_alive():
            process.terminate()
        process.join(10)
        queue.close()


def test_lock_spans_preflight_and_materialization(tmp_path, monkeypatch):
    import bounty_core.ledger as module
    subject = ledger(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = module.ensure_finding_evidence_packet
    outcome = []
    def paused(*args):
        entered.set()
        if not release.wait(10):
            raise TimeoutError('materialization gate not released')
        return original(*args)
    def importer():
        try:
            outcome.append(subject.import_finding(candidate()))
        except Exception as exc:
            outcome.append(exc)
    monkeypatch.setattr(module, 'ensure_finding_evidence_packet', paused)
    thread = threading.Thread(target=importer)
    thread.start()
    ctx = multiprocessing.get_context('spawn')
    queue = ctx.Queue()
    blocked = ctx.Event()
    process = ctx.Process(target=_competing_raw, args=(tmp_path, blocked, queue))
    try:
        assert entered.wait(10)
        process.start()
        assert blocked.wait(10), 'competing writer never observed the held lock'
        assert process.is_alive()
        release.set()
        thread.join(10)
        process.join(10)
        assert process.exitcode == 0 and queue.get(timeout=5) == (True, 'raw')
    finally:
        release.set()
        if process.pid and process.is_alive():
            process.terminate()
            process.join(10)
        thread.join(10)
        queue.close()
    assert not thread.is_alive()
    assert len(outcome) == 1 and outcome[0][:2] == (False, 'D01')
    rows = json.loads(subject.path.read_text())['findings']
    assert [row['fid'] for row in rows] == ['D01', 'raw']
    assert '_atomic_import_pending' not in rows[0]
    assert Path(rows[0]['evidence_path']).is_file()
