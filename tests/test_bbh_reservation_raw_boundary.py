"""Offline cross-repository regression against an explicitly supplied BBH snapshot.

Set BBH_TEST_ROOT to an extracted, immutable BBH revision. Core must be first on
PYTHONPATH; BBH's declared Core pin is not used by this integration probe.
"""
import importlib
import json
import multiprocessing
import os
import threading
from pathlib import Path

import pytest

from bounty_core import resolve_storage
from bounty_core.ledger import ledger_add


@pytest.fixture
def bbh(monkeypatch):
    root = os.environ.get('BBH_TEST_ROOT')
    if not root:
        pytest.skip('set BBH_TEST_ROOT to an isolated immutable BBH snapshot')
    root = Path(root).resolve()
    assert (root / 'agents' / 'sync_reports.py').is_file()
    monkeypatch.syspath_prepend(str(root))
    module = importlib.import_module('agents.sync_reports')
    assert Path(module.__file__).resolve().is_relative_to(root)
    return module


def fixture(tmp_path, *, legacy):
    storage = tmp_path / 'store'
    source = tmp_path / 'source'
    source.mkdir()
    layout = resolve_storage('acme', family='web_bounty', lane='web', root_override=storage)
    raw = layout.reports_root / 'raw'
    raw.mkdir(parents=True)
    intake = raw / 'finding.md'
    intake.write_text('# Test finding\n\nFile: src/app.js:12\nClass: xss\nReview Tier: CONFIRMED\nDescription: Reproduced test finding.\n')
    if legacy:
        layout.ledgers_root.mkdir(parents=True, exist_ok=True)
        baseline = Path(__file__).parent / 'fixtures' / 'baseline_raw_ledger.json'
        (layout.ledgers_root / 'ledger.json').write_text(baseline.read_text())
    return storage, source, layout, intake


def run_import(bbh, storage, source):
    return bbh.sync_reports_main('acme', lane='web', family='web_bounty',
                                 storage_root=storage, source_root=source)


def entries(layout):
    path = layout.ledgers_root / 'ledger.json'
    return json.loads(path.read_text())['findings'] if path.exists() else []


def insert_raw_in_process(storage, output):
    try:
        output.put(ledger_add('acme', {'fid': 'raw', 'file': 'old.js', 'line': 3,
                                       'type': 'xss', 'class_name': 'xss'},
                              'snapshot', 'v1', 'run', 'agent', family='web_bounty',
                              lane='web', root_override=storage))
    except Exception as exc:
        output.put((type(exc).__name__, str(exc)))


def test_bbh_normal_import_and_duplicate_are_unchanged(tmp_path, bbh, capsys):
    storage, source, layout, intake = fixture(tmp_path, legacy=False)
    before = intake.read_bytes()
    assert run_import(bbh, storage, source) == 0
    assert len(entries(layout)) == 1
    assert entries(layout)[0]['fid'] == 'D01'
    assert run_import(bbh, storage, source) == 0
    assert len(entries(layout)) == 1
    assert 'already exists, skipped' in capsys.readouterr().out
    assert intake.read_bytes() == before


def test_bbh_legacy_collision_must_not_reserve_then_retry(tmp_path, bbh, capsys):
    storage, source, layout, intake = fixture(tmp_path, legacy=True)
    before_intake = intake.read_bytes()
    before_ledger = (layout.ledgers_root / 'ledger.json').read_bytes()
    try:
        result = run_import(bbh, storage, source)
    except ValueError:
        result = 1
    after_collision = (layout.ledgers_root / 'ledger.json').read_bytes()
    # Remove only the synthetic legacy row, not the candidate reservation.
    payload = json.loads(after_collision)
    payload['findings'] = [row for row in payload['findings'] if row['fid'] != 'raw']
    (layout.ledgers_root / 'ledger.json').write_text(json.dumps(payload))
    retry = run_import(bbh, storage, source)
    output = capsys.readouterr().out
    assert result != 0
    assert intake.read_bytes() == before_intake
    if after_collision != before_ledger:
        assert [row['fid'] for row in json.loads(after_collision)['findings']] == ['raw', 'D01']
        assert retry == 0 and 'D01 already exists, skipped' in output
        pytest.xfail('Core check committed D01 before BBH refresh; retry falsely skipped')
    assert after_collision == before_ledger, f'collision left a reservation; retry output: {output}'
    assert retry == 0 and 'ADDED D01' in output
    assert [row['fid'] for row in entries(layout)] == ['D01']
    assert intake.read_bytes() == before_intake


@pytest.mark.parametrize('packet_mode', ['legacy', 'evidence_only'])
def test_simulated_preflight_sees_competing_row_before_lock(tmp_path, bbh, monkeypatch, capsys, packet_mode):
    import bounty_core.ledger as core_ledger
    storage, source, layout, intake = fixture(tmp_path, legacy=False)
    before_intake = intake.read_bytes()
    original_reserve = core_ledger._reserve_in_payload
    original_candidate = core_ledger._reserve_candidate
    waiting, proceed = threading.Event(), threading.Event()
    results = []

    def gated_candidate(*args, **kwargs):
        waiting.set()
        if not proceed.wait(10):
            raise TimeoutError('reservation gate not released')
        return original_candidate(*args, **kwargs)

    def preflight_then_reserve(payload, *args, **kwargs):
        rows, finding = payload.get('findings', []), args[0]
        proposed = dict(finding, fid=finding.get('fid') or
                        core_ledger._next_fid(rows, core_ledger._fid_prefix_for(finding)))
        core_ledger.preflight_finding_packets(layout, [*rows, proposed], packet_mode=packet_mode)
        return original_reserve(payload, *args, **kwargs)

    def importer():
        try:
            results.append(run_import(bbh, storage, source))
        except Exception as exc:
            results.append(exc)

    monkeypatch.setattr(core_ledger, '_reserve_candidate', gated_candidate)
    monkeypatch.setattr(core_ledger, '_reserve_in_payload', preflight_then_reserve)
    worker = threading.Thread(target=importer)
    worker.start()
    ctx = multiprocessing.get_context('spawn')
    queue = ctx.Queue()
    competitor = ctx.Process(target=insert_raw_in_process, args=(storage, queue))
    try:
        assert waiting.wait(10), 'importer did not reach reservation boundary'
        competitor.start()
        competitor.join(10)
        assert competitor.exitcode == 0
        assert queue.get(timeout=5) == (True, 'raw')
    finally:
        if competitor.pid and competitor.is_alive():
            competitor.terminate()
            competitor.join(10)
        queue.close()
        proceed.set()
        worker.join(10)
    assert not worker.is_alive()
    assert len(results) == 1
    assert isinstance(results[0], ValueError) or results[0] == 1
    assert [row['fid'] for row in entries(layout)] == ['raw']
    assert intake.read_bytes() == before_intake
    # Resolve only the synthetic legacy row and retry through the entrypoint.
    path = layout.ledgers_root / 'ledger.json'
    payload = json.loads(path.read_text())
    payload['findings'] = []
    path.write_text(json.dumps(payload))
    assert run_import(bbh, storage, source) == 0
    assert 'ADDED D01' in capsys.readouterr().out
    assert [row['fid'] for row in entries(layout)] == ['D01']
    assert intake.read_bytes() == before_intake


@pytest.mark.parametrize('packet_mode', ['legacy', 'evidence_only'])
def test_bbh_competitor_after_preflight_must_not_leave_reservation(tmp_path, bbh, monkeypatch, capsys, packet_mode):
    # Model the proposed Core-only check preflight while retaining the real
    # two-call importer. The later writer obeys the same ledger lock.
    import bounty_core.ledger as core_ledger
    storage, source, layout, intake = fixture(tmp_path, legacy=False)
    before_intake = intake.read_bytes()
    original_reserve = core_ledger._reserve_in_payload
    original_update = bbh.update_team_finding
    checked = threading.Event()
    proceed = threading.Event()
    results = []

    def preflight_then_reserve(payload, *args, **kwargs):
        import fcntl
        finding = args[0]
        rows = payload.get('findings', [])
        proposed = dict(finding, fid=finding.get('fid') or
                        core_ledger._next_fid(rows, core_ledger._fid_prefix_for(finding)))
        # Demonstrate that this *full-set* preflight is inside the actual lock.
        with (layout.ledgers_root / 'ledger.lock').open('a+') as lock:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        core_ledger.preflight_finding_packets(layout, [*rows, proposed], packet_mode=packet_mode)
        return original_reserve(payload, *args, **kwargs)

    def paused_update(*args, **kwargs):
        checked.set()
        if not proceed.wait(10):
            raise TimeoutError('test failed to release update')
        return original_update(*args, **kwargs)

    def importer():
        try:
            results.append(run_import(bbh, storage, source))
        except Exception as exc:
            results.append(exc)

    monkeypatch.setattr(core_ledger, '_reserve_in_payload', preflight_then_reserve)
    monkeypatch.setattr(bbh, 'update_team_finding', paused_update)
    worker = threading.Thread(target=importer)
    worker.start()
    ctx = multiprocessing.get_context('spawn')
    queue = ctx.Queue()
    competitor = ctx.Process(target=insert_raw_in_process, args=(storage, queue))
    try:
        assert checked.wait(10), 'importer did not reach update after check'
        competitor.start()
        competitor.join(10)
        assert not competitor.is_alive(), 'competing writer did not acquire lock'
        assert competitor.exitcode == 0
        assert queue.get(timeout=5) == (True, 'raw')
    finally:
        if competitor.pid and competitor.is_alive():
            competitor.terminate()
            competitor.join(10)
        queue.close()
        proceed.set()
        worker.join(10)
    assert not worker.is_alive()
    assert len(results) == 1
    assert intake.read_bytes() == before_intake
    after_collision = [row['fid'] for row in entries(layout)]
    path = layout.ledgers_root / 'ledger.json'
    payload = json.loads(path.read_text())
    payload['findings'] = [row for row in payload['findings'] if row['fid'] != 'raw']
    path.write_text(json.dumps(payload))
    retry = run_import(bbh, storage, source)
    output = capsys.readouterr().out
    if after_collision != ['raw']:
        assert after_collision == ['D01', 'raw']
        assert isinstance(results[0], ValueError) and 'raw' in str(results[0])
        assert retry == 0 and 'D01 already exists, skipped' in output
        pytest.xfail('check preflight released its lock before refresh; retry falsely skipped')
    assert after_collision == ['raw'], (
        'even a preflight under the check lock cannot exclude a raw row committed before update; '
        f'import result={results!r}; persisted={after_collision}; retry output={output}')
    assert retry == 0 and 'ADDED D01' in output
