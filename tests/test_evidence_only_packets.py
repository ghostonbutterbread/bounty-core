"""Evidence-only BBH route and legacy coexistence contract."""
import json
from pathlib import Path

import pytest

from bounty_core import add_finding, patch_finding_by_fid, record_final_finding_report, resolve_storage, update_finding
from bounty_core.ledger import ledger_get, ledger_path
from bounty_core.reports import refresh_report_navigation_from_ledger, refresh_report_indexes


def _source(fid=None):
    row = {"program": "acme", "family": "web_bounty", "lane": "web", "type": "XSS", "class_name": "xss", "file": "app.js", "line": 7, "severity": "HIGH", "evidence": ["Authorization: secret"]}
    if fid:
        row["fid"] = fid
    return row


def _layout(root):
    return resolve_storage("acme", family="web_bounty", lane="web", root_override=root)


def _assert_evidence_link(layout, fid):
    target = layout.reports_root / fid / "EVIDENCE.md"
    assert target.is_file()
    active = layout.reports_root / "active.md"
    assert f"[[{fid}/EVIDENCE|{fid}]]" in active.read_text()
    links = list((layout.reports_root / "categories").glob(f"*/{fid}.md"))
    assert len(links) == 1
    assert links[0].exists()
    assert links[0].resolve() == target.resolve()
    daily = list((layout.reports_root / "daily").glob("*/active.md"))
    assert daily and f"[[../../{fid}/EVIDENCE|{fid}]]" in daily[0].read_text()
    severity = layout.reports_root / "severity" / "high" / "index.md"
    assert f"[[../../{fid}/EVIDENCE|{fid}]]" in severity.read_text()


def test_source_add_patch_and_final_report_navigation(tmp_path):
    added = add_finding(_source(), root_override=tmp_path, packet_mode="evidence_only")
    fid = added["finding"]["fid"]
    layout = _layout(tmp_path)
    packet = layout.reports_root / fid
    assert "report_path" not in added["finding"]
    assert Path(added["finding"]["evidence_path"]) == packet / "EVIDENCE.md"
    assert not (packet / "REPORT.md").exists()
    assert not (packet / "SUBMISSION.md").exists()
    _assert_evidence_link(layout, fid)
    evidence = packet / "EVIDENCE.md"
    evidence.write_text("# Reviewed evidence\n")
    patched = patch_finding_by_fid("acme", fid, {"title": "Edited", "status": "confirmed"}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", write_report=True, refresh=True, update_current=True)
    assert patched["evidence_path"] == str(evidence)
    assert evidence.read_text() == "# Reviewed evidence\n"
    assert not (packet / "REPORT.md").exists()
    assert f"[[{fid}/EVIDENCE|{fid}]]" in (layout.reports_root / "confirmed.md").read_text()

    final = packet / f"acme-xss-{fid}.md"
    with pytest.raises(ValueError):
        record_final_finding_report("acme", fid, final, family="web_bounty", lane="web", root_override=tmp_path)
    final.write_text("# Bunny final report\n")
    with pytest.raises(ValueError):
        record_final_finding_report("acme", fid, evidence, family="web_bounty", lane="web", root_override=tmp_path)
    patched = record_final_finding_report("acme", fid, final, family="web_bounty", lane="web", root_override=tmp_path)
    assert patched is not None
    patched = patch_finding_by_fid("acme", fid, {"submission_status": "submitted"}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert patched is not None
    assert patched["report_path"] == str(final)
    assert f"[[{fid}/{final.stem}|{fid}]]" in (layout.reports_root / "confirmed.md").read_text()
    assert next((layout.reports_root / "categories").glob(f"*/{fid}.md")).resolve() == final.resolve()
    refresh_report_navigation_from_ledger(layout, packet_mode="evidence_only")
    assert ledger_get("acme", fid, family="web_bounty", lane="web", root_override=tmp_path)["report_path"] == str(final)
    assert final.read_text() == "# Bunny final report\n"
    assert evidence.read_text() == "# Reviewed evidence\n"
    assert not (packet / "REPORT.md").exists()


def test_normalized_add_and_edit_use_evidence_only(tmp_path):
    row = {"program": "acme", "title": "Endpoint issue", "type": "xss", "asset": "https://example.test/x", "source_tool": "bbh", "source_repo": "owned"}
    added = add_finding(row, root_override=tmp_path, packet_mode="evidence_only", refresh=False)
    fid = added["finding"]["fid"]
    identity = added["finding"]["identity"]
    updated = update_finding(identity, {"status": "confirmed"}, "acme", "web_bounty", "web", root_override=tmp_path, packet_mode="evidence_only")
    assert updated["ok"]
    assert "report_path" not in updated["finding"]
    assert Path(updated["finding"]["evidence_path"]).is_file()
    assert not (_layout(tmp_path).reports_root / fid / "REPORT.md").exists()


def test_repeated_refresh_keeps_legacy_files_and_report_pointer(tmp_path):
    layout = _layout(tmp_path)
    legacy = add_finding(_source("L01"), root_override=tmp_path, refresh=False)["finding"]
    report = Path(legacy["report_path"])
    submission = report.parent / "SUBMISSION.md"
    report.write_text("# Legacy manually edited\n")
    submission.write_text("# Submitted\n")
    fresh = add_finding({**_source("N02"), "file": "other.js"}, root_override=tmp_path, packet_mode="evidence_only", refresh=False)["finding"]
    evidence = Path(fresh["evidence_path"])
    evidence.write_text("# Manually populated\n")
    for _ in range(3):
        refresh_report_navigation_from_ledger(layout, packet_mode="evidence_only")
        assert report.read_text() == "# Legacy manually edited\n"
        assert submission.read_text() == "# Submitted\n"
        assert evidence.read_text() == "# Manually populated\n"
        assert not (evidence.parent / "REPORT.md").exists()
        rows = json.loads(ledger_path("acme", family="web_bounty", lane="web", root_override=tmp_path).read_text())["findings"]
        assert next(row for row in rows if row["fid"] == "L01")["report_path"] == str(report)
        assert "report_path" not in next(row for row in rows if row["fid"] == "N02")
        active = (layout.reports_root / "active.md").read_text()
        assert "[[L01/REPORT|L01]]" in active
        assert "[[N02/EVIDENCE|N02]]" in active
        assert next((layout.reports_root / "categories").glob("*/L01.md")).resolve() == report.resolve()


def test_explicit_index_refresh_creates_link_targets_and_validates_mode(tmp_path):
    layout = _layout(tmp_path)
    rows = [_source("D01"), {**_source("D02"), "file": "other.js"}]
    refresh_report_indexes(layout, rows, packet_mode="evidence_only")
    for row in rows:
        assert (layout.reports_root / row["fid"] / "EVIDENCE.md").exists()
        assert not (layout.reports_root / row["fid"] / "REPORT.md").exists()
    assert "[[D01/EVIDENCE|D01]]" in (layout.reports_root / "active.md").read_text()
    with pytest.raises(ValueError):
        add_finding(_source(), root_override=tmp_path, packet_mode="unexpected")


def test_missing_report_pointer_falls_back_to_existing_evidence(tmp_path):
    layout = _layout(tmp_path)
    add_finding(_source("D11"), root_override=tmp_path, packet_mode="evidence_only", refresh=False)
    missing = layout.reports_root / "D11" / "acme-xss-D11.md"
    patched = patch_finding_by_fid("acme", "D11", {"report_path": str(missing)}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert patched is not None and patched["report_path"] == str(missing)
    _assert_evidence_link(layout, "D11")
