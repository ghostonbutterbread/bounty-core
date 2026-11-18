"""Raw intake is never a finding packet, even for historic raw FIDs."""
import json
import multiprocessing
import shutil
from pathlib import Path

import pytest

from bounty_core import add_finding, resolve_storage
from bounty_core.ledger import ledger_add, ledger_get
from bounty_core.reports import (ensure_finding_evidence_packet,
                                 refresh_report_navigation_from_ledger,
                                 write_finding_report)


def layout(root):
    return resolve_storage('acme', family='web_bounty', lane='web', root_override=root)


def snapshot(root):
    result = {}
    for p in root.rglob('*'):
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
    row = {'program': 'acme', 'fid': 'D01', 'title': 'Bug', 'type': 'xss', 'asset': 'example.test'}
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


def _gated_add(root, waiting, release, result):
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
        add_finding({'program': 'acme', 'fid': 'D01', 'title': 'Bug',
                     'type': 'xss', 'asset': 'example.test'},
                    root_override=root, packet_mode='evidence_only')
    except Exception as exc:
        result.put((type(exc).__name__, str(exc)))
    else:
        result.put(('success', ''))
    finally:
        fcntl.flock = original


def test_concurrent_raw_ledger_claim_is_rechecked_under_lock(tmp_path):
    raw = layout(tmp_path).reports_root / 'raw'
    raw.mkdir(parents=True)
    (raw / 'input.md').write_text('original intake')
    ctx = multiprocessing.get_context('spawn')
    waiting, release, result = ctx.Event(), ctx.Event(), ctx.Queue()
    process = ctx.Process(target=_gated_add, args=(tmp_path, waiting, release, result))
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
