"""Raw intake is never a finding packet, even for historic raw FIDs."""
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
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.name.endswith('.lock')}


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
