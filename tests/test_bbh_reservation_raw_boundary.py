"""Offline contract probe: BBH archive with only its import call adapted.

Set BBH_TEST_REPO to a local BBH Git repository containing BBH_REVISION. This is
NOT a test of an installed or published consumer; the archive is a synthetic
consumer adaptation and its dependency pin is deliberately overridden by Core.
"""
import importlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from bounty_core import resolve_storage

BBH_REVISION = '4ba241ce9859e7ee4964566e54976aeb032336fd'


@pytest.fixture(scope='session')
def bbh(tmp_path_factory):
    repo = os.environ.get('BBH_TEST_REPO')
    if not repo:
        pytest.skip('set BBH_TEST_REPO to the local BBH Git repository')
    root = tmp_path_factory.mktemp('bbh-archive')
    archive = root / 'bbh.tar'
    with archive.open('wb') as output:
        subprocess.run(['git', '-C', repo, 'archive', BBH_REVISION], stdout=output, check=True)
    with tarfile.open(archive) as tar:
        tar.extractall(root, filter='data')
    archive.unlink()
    path = root / 'agents' / 'sync_reports.py'
    text = path.read_text()
    old = 'is_duplicate, existing_fid, finding = hunter.ledger.check(candidate)'
    new = "is_duplicate, existing_fid, finding = hunter.ledger.import_finding(candidate, packet_mode='evidence_only')"
    assert text.count(old) == 1
    text = text.replace(old, new)
    start = text.index('            finding = update_team_finding(\n', text.index(new))
    end = text.index('            evidence_output = ', start)
    text = text[:start] + text[end:]
    path.write_text(text)
    sys.path.insert(0, str(root))
    module = importlib.import_module('agents.sync_reports')
    assert Path(module.__file__).resolve().is_relative_to(root)
    yield module
    sys.path.remove(str(root))


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
        (layout.ledgers_root / 'ledger.json').write_bytes(baseline.read_bytes())
    return storage, source, layout, intake


def run_import(bbh, storage, source):
    return bbh.sync_reports_main('acme', lane='web', family='web_bounty',
                                 storage_root=storage, source_root=source)


def entries(layout):
    path = layout.ledgers_root / 'ledger.json'
    return json.loads(path.read_text())['findings'] if path.exists() else []


def test_adapted_bbh_import_then_unchanged_duplicate(tmp_path, bbh, capsys):
    storage, source, layout, intake = fixture(tmp_path, legacy=False)
    before = intake.read_bytes()
    assert run_import(bbh, storage, source) == 0
    rows = entries(layout)
    assert len(rows) == 1 and rows[0]['fid'] == 'D01'
    assert rows[0]['file'] == 'src/app.js' and rows[0]['line'] == 12
    assert len(rows[0]['sightings']) == 1
    assert Path(rows[0]['evidence_path']).is_file()
    before_ledger = (layout.ledgers_root / 'ledger.json').read_bytes()
    assert run_import(bbh, storage, source) == 0
    assert (layout.ledgers_root / 'ledger.json').read_bytes() == before_ledger
    assert 'D01 already exists, skipped' in capsys.readouterr().out
    assert intake.read_bytes() == before


def test_adapted_bbh_collision_does_not_reserve_and_retry_imports(tmp_path, bbh, capsys):
    storage, source, layout, intake = fixture(tmp_path, legacy=True)
    before_intake = intake.read_bytes()
    path = layout.ledgers_root / 'ledger.json'
    before_ledger = path.read_bytes()
    assert run_import(bbh, storage, source) == 1
    assert path.read_bytes() == before_ledger
    assert intake.read_bytes() == before_intake
    assert [row['fid'] for row in entries(layout)] == ['raw']
    payload = json.loads(before_ledger)
    payload['findings'] = []
    path.write_text(json.dumps(payload))
    assert run_import(bbh, storage, source) == 0
    assert 'ADDED D01' in capsys.readouterr().out
    assert [row['fid'] for row in entries(layout)] == ['D01']
    assert intake.read_bytes() == before_intake


def test_adapted_bbh_retry_finishes_interrupted_import(tmp_path, bbh, capsys):
    storage, source, layout, intake = fixture(tmp_path, legacy=False)
    before = intake.read_bytes()
    with patch('bounty_core.ledger.refresh_indexes', side_effect=OSError('injected failure')):
        with pytest.raises(OSError, match='injected failure'):
            run_import(bbh, storage, source)
    assert entries(layout)[0]['_atomic_import_pending'] == 'evidence_only'
    assert run_import(bbh, storage, source) == 0
    assert 'ADDED D01' in capsys.readouterr().out
    assert len(entries(layout)) == 1 and '_atomic_import_pending' not in entries(layout)[0]
    assert intake.read_bytes() == before
