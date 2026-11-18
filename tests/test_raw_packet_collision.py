"""Raw intake is never a finding packet, even for historic raw FIDs."""
import json
import multiprocessing
import shutil
from pathlib import Path

import pytest

from bounty_core import add_finding, get_finding, patch_finding_by_fid, resolve_storage, update_finding
from bounty_core.ledger import ledger_add, ledger_get
from bounty_core.reports import (ensure_finding_evidence_packet,
                                 refresh_report_navigation_from_ledger,
                                 write_finding_report)


def layout(root):
    return resolve_storage('acme', family='web_bounty', lane='web', root_override=root)


def snapshot(root):
    result = {}
    # The advisory-lock inode and its containing directory may be created even
    # for rejected operations; never unlink it while another writer may wait.
    lock = layout(root).ledgers_root / 'ledger.lock'
    for p in root.rglob('*'):
        if (p == lock and not p.is_symlink() and p.is_file() and not p.read_bytes()) or (p == lock.parent and p.is_dir() and not p.is_symlink()):
            continue
        relative = str(p.relative_to(root))
        if p.is_symlink():
            result[relative] = ('symlink', str(p.readlink()))
        elif p.is_dir():
            result[relative] = ('directory',)
        elif p.is_file():
            result[relative] = ('file', p.read_bytes())
    return result


@pytest.mark.parametrize('source', [False, True])
@pytest.mark.parametrize('mode', ['legacy', 'evidence_only'])
def test_raw_packet_rejected_without_effects(tmp_path, source, mode):
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'EVIDENCE.md').write_text('intake evidence, not a packet')
    row = {'program': 'acme', 'fid': 'raw', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
    if source:
        row.update(file='new.js', class_name='xss', line=7)
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        add_finding(row, root_override=tmp_path, packet_mode=mode)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('source', [False, True])
def test_unrelated_add_preserves_historical_raw_before_effects(tmp_path, source):
    target = layout(tmp_path)
    target.ledgers_root.mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent / 'fixtures' / 'baseline_raw_ledger.json', target.ledgers_root / 'ledger.json')
    raw = target.reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original raw input')
    row: dict = {'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
    if source:
        row.update(file='new.js', class_name='xss', line=7)
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        add_finding(row, root_override=tmp_path, packet_mode='evidence_only')
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('writer', [write_finding_report, ensure_finding_evidence_packet])
def test_direct_writer_rejects_raw_packet(tmp_path, writer):
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'REPORT.md').write_text('raw input')
    before = snapshot(tmp_path)
    finding = {'fid': 'raw', 'title': 'Bug'}
    with pytest.raises(ValueError, match='raw|collision'):
        writer(layout(tmp_path), finding)
    assert finding == {'fid': 'raw', 'title': 'Bug'}
    assert snapshot(tmp_path) == before


def test_distinct_descriptive_raw_packet_is_allowed(tmp_path):
    finding = {'fid': 'raw', 'title': 'Bug'}
    evidence = ensure_finding_evidence_packet(layout(tmp_path), finding)
    assert evidence == layout(tmp_path).reports_root / 'raw-bug' / 'EVIDENCE.md'
    assert evidence.is_file()
    assert not (layout(tmp_path).reports_root / 'raw').exists()


def test_reserved_descriptive_raw_packet_coexists_with_raw_intake(tmp_path):
    target = layout(tmp_path)
    raw = target.reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original intake')
    packet = target.reports_root / 'raw-bug'
    finding = {'fid': 'raw', 'title': 'Bug', 'report_dir': str(packet)}
    assert ensure_finding_evidence_packet(target, finding) == packet / 'EVIDENCE.md'
    assert (raw / 'input.md').read_text() == 'original intake'


def test_ledger_only_raw_is_supported(tmp_path):
    created, fid = ledger_add('acme', {'fid': 'raw', 'file': 'a.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
                              'snapshot', 'v1', 'run', 'agent', family='web_bounty', lane='web', root_override=tmp_path)
    assert created and fid == 'raw'
    assert ledger_get('acme', 'raw', family='web_bounty', lane='web', root_override=tmp_path)['fid'] == 'raw'


def test_refresh_with_historical_raw_fails_before_any_effect(tmp_path):
    ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
               'snapshot', 'v1', 'run', 'agent', family='web_bounty', lane='web', root_override=tmp_path)
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original input')
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode='evidence_only')
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('mode', ['legacy', 'evidence_only'])
def test_refresh_preflights_later_ambiguous_raw_before_first_packet(tmp_path, mode):
    target = layout(tmp_path)
    target.ledgers_root.mkdir(parents=True)
    payload = json.loads((Path(__file__).parent / 'fixtures' / 'baseline_raw_ledger.json').read_text())
    safe = dict(payload['findings'][0], fid='D01', file='safe.js')
    payload['findings'].insert(0, safe)
    (target.ledgers_root / 'ledger.json').write_text(json.dumps(payload))
    # A legacy store can have a ledger but no lock. Never remove a lock after
    # acquiring it: another waiter could already hold its inode open.
    raw = target.reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original intake')
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        refresh_report_navigation_from_ledger(target, packet_mode=mode)
    assert snapshot(tmp_path) == before


def _gated_add(root, waiting, release, result, source, mode):
    import fcntl
    original = fcntl.flock
    gated = False

    def gate(fd, operation):
        nonlocal gated
        if operation == fcntl.LOCK_EX and not gated:
            gated = True
            waiting.set()
            if not release.wait(10):
                raise TimeoutError('lock gate not released')
        return original(fd, operation)

    fcntl.flock = gate
    try:
        row: dict = {'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
        if source:
            row.update(file='new.js', class_name='xss', line=7)
        add_finding(row, root_override=root, packet_mode=mode)
    except Exception as exc:
        result.put((type(exc).__name__, str(exc)))
    else:
        result.put(('success', ''))
    finally:
        fcntl.flock = original


@pytest.mark.parametrize('source', [False, True])
@pytest.mark.parametrize('mode', ['legacy', 'evidence_only'])
def test_concurrent_raw_ledger_claim_is_rechecked_under_lock(tmp_path, source, mode):
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original intake')
    ctx = multiprocessing.get_context('spawn')
    waiting, release, result = ctx.Event(), ctx.Event(), ctx.Queue()
    process = ctx.Process(target=_gated_add, args=(tmp_path, waiting, release, result, source, mode))
    process.start()
    try:
        assert waiting.wait(10), 'writer never reached the ledger flock'
        ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3,
                            'type': 'xss', 'class_name': 'xss'},
                   'snapshot', 'v1', 'run', 'agent', family='web_bounty',
                   lane='web', root_override=tmp_path)
        before = snapshot(tmp_path)
        release.set()
        process.join(10)
        assert not process.is_alive(), 'writer did not finish'
        assert process.exitcode == 0
        kind, message = result.get(timeout=5)
        assert kind == 'ValueError' and ('raw' in message or 'collision' in message)
        assert snapshot(tmp_path) == before
    finally:
        release.set()
        if process.is_alive():
            process.terminate()
        process.join(10)
        result.close()


def _paused_after_preflight(root, validated, release, result, source, mode):
    import bounty_core.ledger as module
    original = module.preflight_finding_packets

    def pause(*args, **kwargs):
        original(*args, **kwargs)
        if not args[1]:
            return
        validated.set()
        if not release.wait(10):
            raise TimeoutError('preflight gate not released')

    module.preflight_finding_packets = pause
    try:
        row: dict = {'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
        if source:
            row.update(file='new.js', class_name='xss', line=7)
        add_finding(row, root_override=root, packet_mode=mode, refresh=False)
        result.put('success')
    except Exception as exc:
        result.put(repr(exc))


@pytest.mark.parametrize('source', [False, True])
@pytest.mark.parametrize('mode', ['legacy', 'evidence_only'])
def test_validation_holds_ledger_lock_through_reservation(tmp_path, source, mode):
    import fcntl
    ctx = multiprocessing.get_context('spawn')
    validated, release, result = ctx.Event(), ctx.Event(), ctx.Queue()
    process = ctx.Process(target=_paused_after_preflight, args=(tmp_path, validated, release, result, source, mode))
    process.start()
    try:
        assert validated.wait(10), 'writer never completed preflight'
        lock = layout(tmp_path).ledgers_root / 'ledger.lock'
        with lock.open('a+') as handle:
            with pytest.raises(BlockingIOError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not (layout(tmp_path).ledgers_root / 'ledger.json').exists()
        release.set()
        process.join(10)
        assert process.exitcode == 0
        assert result.get(timeout=5) == 'success'
        stored = ledger_get('acme', 'D01', family='web_bounty', lane='web', root_override=tmp_path)
        assert stored is not None
        assert stored['report_dir']
    finally:
        release.set()
        if process.is_alive():
            process.terminate()
        process.join(10)
        result.close()


@pytest.mark.parametrize('key', ['report_dir', 'report_path', 'evidence_path'])
def test_historical_raw_pointer_is_not_silently_reassigned(tmp_path, key):
    target = layout(tmp_path)
    target.ledgers_root.mkdir(parents=True)
    payload = json.loads((Path(__file__).parent / 'fixtures' / 'baseline_raw_ledger.json').read_text())
    payload['findings'][0][key] = str(target.reports_root / 'raw' / ('EVIDENCE.md' if key != 'report_dir' else ''))
    (target.ledgers_root / 'ledger.json').write_text(json.dumps(payload))
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        refresh_report_navigation_from_ledger(target, packet_mode='evidence_only')
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('method', ['patch', 'update'])
def test_update_does_not_touch_safe_packet_before_historical_collision(tmp_path, method):
    added = add_finding({'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'},
                        root_override=tmp_path, packet_mode='evidence_only', refresh=False)['finding']
    ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
               'snapshot', 'v1', 'run', 'agent', family='web_bounty', lane='web', root_override=tmp_path)
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original intake')
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match='raw|collision'):
        if method == 'patch':
            patch_finding_by_fid('acme', 'D01', {'status': 'confirmed'}, family='web_bounty', lane='web',
                                 root_override=tmp_path, packet_mode='evidence_only', refresh=True)
        else:
            update_finding(added['identity'], {'status': 'confirmed'}, 'acme', 'web_bounty', 'web',
                           root_override=tmp_path, packet_mode='evidence_only', refresh=True)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('source', [False, True])
@pytest.mark.parametrize('mode', ['legacy', 'evidence_only'])
def test_normal_raw_intake_coexists_with_add_and_lookup(tmp_path, source, mode):
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    intake = raw / 'import.md'
    intake.write_text('# Raw source\n')
    row: dict = {'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
    if source:
        row.update(file='new.js', class_name='xss', line=7)
    added = add_finding(row, root_override=tmp_path, packet_mode=mode)['finding']
    found = get_finding(identity=added['identity'], program='acme', family='web_bounty', lane='web', root_override=tmp_path)
    assert found is not None and found['fid'] == 'D01'
    assert Path(added['report_dir']).parent == raw.parent
    assert Path(added['report_dir']) != raw
    assert Path(added['evidence_path'] if mode == 'evidence_only' else added['report_path']).is_file()
    assert intake.read_text() == '# Raw source\n'
    assert not (raw / 'EVIDENCE.md').exists()
