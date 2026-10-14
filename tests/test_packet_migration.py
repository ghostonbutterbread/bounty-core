"""Provider contract for new descriptive packets and read-only legacy coexistence."""
from contextlib import contextmanager
import json
from pathlib import Path
import pytest
import bounty_core.ledger as ledger_module
import bounty_core.reports as reports_module

from bounty_core import add_finding, patch_finding_by_fid, record_final_finding_report, resolve_storage
from bounty_core.ledger import ledger_get, ledger_list, migrate_legacy_finding
from bounty_core.reports import refresh_report_navigation_from_ledger


def row(**changes):
    value = {"program": "acme", "family": "web_bounty", "lane": "web", "fid": "D01", "type": "View Only Documents Authorization", "class_name": "idor", "file": "app.js", "line": 7, "severity": "HIGH"}
    value.update(changes)
    return value


def layout(root, program="acme"):
    return resolve_storage(program, family="web_bounty", lane="web", root_override=root)


def test_legacy_row_migration_preserves_frozen_packet_pointer(tmp_path):
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    evidence = packet / "EVIDENCE.md"
    final = packet / "acme-xss-D01.md"
    migrated = migrate_legacy_finding({"fid": "D01", "type": "Owned XSS", "report_dir": str(packet),
                                       "evidence_path": str(evidence), "report_path": str(final)})
    assert migrated["report_dir"] == str(packet)
    assert migrated["evidence_path"] == str(evidence)
    assert migrated["report_path"] == str(final)


def test_normalized_intake_rejects_duplicate_explicit_fid(tmp_path):
    first = {"program": "acme", "fid": "D01", "title": "Owned XSS", "type": "xss", "asset": "first.example"}
    second = {**first, "title": "Owned SSRF", "asset": "second.example"}
    add_finding(first, root_override=tmp_path, packet_mode="evidence_only")
    with pytest.raises(ValueError, match="FID already assigned"):
        add_finding(second, root_override=tmp_path, packet_mode="evidence_only")
    assert len(ledger_list("acme", family="web_bounty", lane="web", root_override=tmp_path)) == 1
    assert not (layout(tmp_path).reports_root / "D01-owned-ssrf").exists()


def test_new_packet_rejects_preexisting_descriptive_directory(tmp_path):
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    packet.mkdir(parents=True)
    evidence = packet / "EVIDENCE.md"
    evidence.write_text("# Unrelated prior evidence\n")
    with pytest.raises(ValueError, match="already exists|collision"):
        add_finding(row(title="Owned XSS"), root_override=tmp_path, packet_mode="evidence_only")
    assert evidence.read_text() == "# Unrelated prior evidence\n"
    assert ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path) is None


def test_ledger_write_failure_does_not_strand_new_source_packet(tmp_path, monkeypatch):
    original = ledger_module._write_json_atomic
    attempts = 0

    def fail_once(path, payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic ledger write interruption")
        return original(path, payload)

    monkeypatch.setattr(ledger_module, "_write_json_atomic", fail_once)
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    with pytest.raises(OSError, match="synthetic ledger write interruption"):
        add_finding(row(title="Owned XSS"), root_override=tmp_path, packet_mode="evidence_only")
    assert not packet.exists()
    assert ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path) is None
    retried = add_finding(row(title="Owned XSS"), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert retried["report_dir"] == str(packet)
    assert (packet / "EVIDENCE.md").is_file()


def test_normalized_ledger_write_failure_does_not_strand_new_packet(tmp_path, monkeypatch):
    original = ledger_module._write_json_atomic
    attempts = 0

    def fail_once(path, payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic normalized ledger write interruption")
        return original(path, payload)

    monkeypatch.setattr(ledger_module, "_write_json_atomic", fail_once)
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    finding = {"program": "acme", "fid": "D01", "title": "Owned XSS", "type": "xss", "asset": "first.example"}
    with pytest.raises(OSError, match="synthetic normalized ledger write interruption"):
        add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")
    assert not packet.exists()
    assert ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path) is None
    retried = add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert retried["report_dir"] == str(packet)
    assert (packet / "EVIDENCE.md").is_file()


def test_packet_phase_ledger_write_failure_is_retryable(tmp_path, monkeypatch):
    original = ledger_module._write_json_atomic
    attempts = 0

    def fail_second(path, payload):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise OSError("synthetic packet phase interruption")
        return original(path, payload)

    monkeypatch.setattr(ledger_module, "_write_json_atomic", fail_second)
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    finding = {"program": "acme", "fid": "D01", "title": "Owned XSS", "type": "xss", "asset": "first.example"}
    with pytest.raises(OSError, match="synthetic packet phase interruption"):
        add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")
    stored = ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None
    assert stored["report_dir"] == str(packet)
    retried = add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert retried["report_dir"] == str(packet)
    assert (packet / "EVIDENCE.md").is_file()


def test_bulk_refresh_commits_packet_pointer_before_creating_packet(tmp_path, monkeypatch):
    add_finding(row(title="Owned XSS"), root_override=tmp_path, packet_mode="legacy", write_report=False, refresh=False)
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    original = ledger_module._write_json_atomic
    attempts = 0

    def fail_once(path, payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic bulk ledger write interruption")
        return original(path, payload)

    monkeypatch.setattr(ledger_module, "_write_json_atomic", fail_once)
    with pytest.raises(OSError, match="synthetic bulk ledger write interruption"):
        refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    assert not packet.exists()
    stored = ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None and not stored.get("report_dir")
    refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    stored = ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None and stored["report_dir"] == str(packet)
    assert (packet / "EVIDENCE.md").is_file()


@pytest.mark.parametrize("finding", [row(title="Owned XSS"),
                                    {"program": "acme", "fid": "D01", "title": "Owned XSS", "type": "xss", "asset": "first.example"}])
def test_interrupted_evidence_publish_retries_without_empty_file(tmp_path, monkeypatch, finding):
    original = reports_module.os.link
    attempts = 0

    def fail_once(source, target, *args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic evidence publish interruption")
        return original(source, target, *args, **kwargs)

    monkeypatch.setattr(reports_module.os, "link", fail_once)
    packet = layout(tmp_path).reports_root / "D01-owned-xss"
    with pytest.raises(OSError, match="synthetic evidence publish interruption"):
        add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")
    stored = ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None and stored["report_dir"] == str(packet)
    assert not (packet / "EVIDENCE.md").exists()
    assert list(packet.glob(".EVIDENCE.md.*.tmp")) == []
    retried = add_finding(finding, root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert retried["report_dir"] == str(packet)
    assert (packet / "EVIDENCE.md").read_text(encoding="utf-8").startswith("# D01 — evidence")


def test_bulk_refresh_never_materializes_row_inserted_between_lock_phases(tmp_path, monkeypatch):
    add_finding(row(title="Owned XSS"), root_override=tmp_path, packet_mode="legacy", write_report=False, refresh=False)
    d02_packet = layout(tmp_path).reports_root / "D02-new-arrival"
    original_lock = ledger_module._locked_payload
    original_write = ledger_module._write_json_atomic
    injected = False

    @contextmanager
    def inject_after_first_unlock(*args, **kwargs):
        nonlocal injected
        with original_lock(*args, **kwargs) as payload:
            yield payload
        if not injected:
            injected = True
            add_finding(row(fid="D02", title="New arrival", type="New arrival", file="new.js", line=8),
                        root_override=tmp_path, packet_mode="legacy", write_report=False, refresh=False)

    def reject_uncommitted_packet(path, payload):
        committed = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        existing = next((r for r in committed.get("findings", []) if r.get("fid") == "D02"), None)
        incoming = next((r for r in payload.get("findings", []) if r.get("fid") == "D02"), None)
        if existing and not existing.get("report_dir") and incoming and incoming.get("report_dir") and d02_packet.exists():
            raise OSError("would strand a concurrent packet")
        return original_write(path, payload)

    monkeypatch.setattr(ledger_module, "_locked_payload", inject_after_first_unlock)
    monkeypatch.setattr(ledger_module, "_write_json_atomic", reject_uncommitted_packet)
    refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    assert injected
    stored = ledger_get("acme", "D02", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None and not stored.get("report_dir")
    assert not d02_packet.exists()
    refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    stored = ledger_get("acme", "D02", family="web_bounty", lane="web", root_override=tmp_path)
    assert stored is not None and stored["report_dir"] == str(d02_packet)
    assert (d02_packet / "EVIDENCE.md").is_file()


def test_new_packet_freezes_descriptive_slug_and_uses_final_in_views(tmp_path):
    created = add_finding(row(), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    packet = layout(tmp_path).reports_root / "D01-view-only-documents-authorization"
    assert Path(created["report_dir"]) == packet
    assert Path(created["evidence_path"]) == packet / "EVIDENCE.md"
    edited = patch_finding_by_fid("acme", "D01", {"title": "Renamed", "type": "changed", "status": "confirmed", "severity": "LOW"}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert edited["report_dir"] == str(packet)
    assert not (layout(tmp_path).reports_root / "D01-changed").exists()
    final = packet / "acme-idor-D01.md"
    final.write_text("# Authored\n")
    record_final_finding_report("acme", "D01", final, family="web_bounty", lane="web", root_override=tmp_path)
    assert "[[../../D01-view-only-documents-authorization/acme-idor-D01|D01]]" in (layout(tmp_path).reports_root / "severity/low/index.md").read_text()
    assert "acme-idor-D01" in (layout(tmp_path).reports_root / "categories/idor/index.md").read_text()
    assert final.read_text() == "# Authored\n"


def test_submission_view_reversible_and_no_eager_legacy_navigation(tmp_path):
    created = add_finding(row(), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    root = layout(tmp_path).reports_root
    assert not (root / "daily").exists()
    assert not (root / "index").exists()
    assert not (root / "raw").exists()
    assert not (root / "submitted").exists()
    patch_finding_by_fid("acme", "D01", {"submission": {"state": "submitted"}}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert "D01-view-only-documents-authorization/EVIDENCE" in (root / "submitted/index.md").read_text()
    patch_finding_by_fid("acme", "D01", {"submission": {"state": "dropped"}}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert not (root / "submitted/index.md").exists()
    assert not (root / "submitted").exists()
    assert Path(created["report_dir"]).exists()


def test_existing_fid_packet_remains_at_original_path(tmp_path):
    root = layout(tmp_path).reports_root
    packet = root / "D01"
    packet.mkdir(parents=True)
    (packet / "EVIDENCE.md").write_text("# Historic evidence\n")
    added = add_finding(row(), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert added["report_dir"] == str(packet)
    assert not (root / "D01-view-only-documents-authorization").exists()
    refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    assert (packet / "EVIDENCE.md").read_text() == "# Historic evidence\n"


def test_packet_pointer_rejects_cross_fid_prefix_and_symlink(tmp_path):
    created = add_finding(row(), root_override=tmp_path, packet_mode="evidence_only", refresh=False)["finding"]
    root = layout(tmp_path).reports_root
    foreign = root / "D010-other"
    foreign.mkdir()
    (foreign / "acme-D01.md").write_text("foreign\n")
    with pytest.raises(ValueError):
        record_final_finding_report("acme", "D01", foreign / "acme-D01.md", family="web_bounty", lane="web", root_override=tmp_path)
    with pytest.raises(ValueError):
        patch_finding_by_fid("acme", "D01", {"report_dir": str(foreign)}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only")
    external = tmp_path / "external"
    external.mkdir()
    packet = Path(created["report_dir"])
    packet.rename(root / "saved")
    packet.symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError):
        patch_finding_by_fid("acme", "D01", {"status": "confirmed"}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only")
    assert not (external / "EVIDENCE.md").exists()


def test_program_isolation_and_default_legacy_mode(tmp_path):
    first = add_finding(row(), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    second = add_finding(row(program="other"), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    assert first["fid"] == second["fid"] == "D01"
    assert first["report_dir"] != second["report_dir"]
    legacy = add_finding(row(fid="D02", file="other.js"), root_override=tmp_path)["finding"]
    assert Path(legacy["report_path"]).is_file()


@pytest.mark.parametrize("title,expected", [
    ("Owned XSS", "D01-owned-xss"),
    ("SQLite injection via exposed IPC port", "D01-sqlite-injection-via-exposed-ipc-port"),
])
def test_consumer_title_contract_and_submitted_final_link(tmp_path, title, expected):
    finding = add_finding(row(title=title), root_override=tmp_path, packet_mode="evidence_only")["finding"]
    packet = layout(tmp_path).reports_root / expected
    assert finding["report_dir"] == str(packet)
    assert ledger_get("acme", "D01", family="web_bounty", lane="web", root_override=tmp_path)["report_dir"] == str(packet)
    final = packet / "acme-issue-D01.md"
    final.write_text("# Final\n")
    record_final_finding_report("acme", "D01", final, family="web_bounty", lane="web", root_override=tmp_path)
    patch_finding_by_fid("acme", "D01", {"submission": {"state": "submitted"}}, family="web_bounty", lane="web", root_override=tmp_path, packet_mode="evidence_only", refresh=True)
    assert f"[[../{expected}/acme-issue-D01|D01]]" in (packet.parent / "submitted/index.md").read_text()
    assert not (packet.parent / "daily").exists()
    assert not (packet.parent / "raw").exists()


def test_historical_navigation_and_authored_packet_survive_refresh(tmp_path):
    root = layout(tmp_path).reports_root
    historical = root / "raw" / "xss" / "index.md"
    historical.parent.mkdir(parents=True)
    historical.write_text("# Historical review notes\n")
    packet = root / "D01"
    packet.mkdir()
    (packet / "EVIDENCE.md").write_text("# Investigator notes\n")
    add_finding(row(), root_override=tmp_path, packet_mode="evidence_only")
    refresh_report_navigation_from_ledger(layout(tmp_path), packet_mode="evidence_only")
    assert historical.read_text() == "# Historical review notes\n"
    assert (packet / "EVIDENCE.md").read_text() == "# Investigator notes\n"
    assert not (root / "D01-view-only-documents-authorization").exists()


def test_reject_unsafe_exact_fid_before_packet_write(tmp_path):
    with pytest.raises(ValueError):
        add_finding(row(fid="D01/../../outside"), root_override=tmp_path, packet_mode="evidence_only", refresh=False)
    assert not (tmp_path / "outside").exists()
    assert ledger_get("acme", "D01/../../outside", family="web_bounty", lane="web", root_override=tmp_path) is None
