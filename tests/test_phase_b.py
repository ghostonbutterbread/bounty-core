import json
from pathlib import Path

import pytest

from bounty_core import add_finding, get_finding, list_findings, resolve_storage, start_run, update_finding, write_manifest
from bounty_core.indexes import refresh_indexes


def _finding(program="acme"):
    return {
        "program": program,
        "family": "web_bounty",
        "lane": "web",
        "type": "xss",
        "status": "raw",
        "severity": "LOW",
        "title": "Reflected XSS on search",
        "asset": "https://example.com/search",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "source_tool": "test",
        "source_repo": "bounty-core-tests",
        "provenance": {"source": "unit-test"},
    }


def test_list_and_get_after_add_finding(tmp_path):
    result = add_finding(_finding(), root_override=tmp_path)
    identity = result["finding"]["identity"]

    findings = list_findings(program="acme", family="web_bounty", lane="web", root_override=tmp_path)

    assert [finding["identity"] for finding in findings] == [identity]
    assert get_finding(identity=identity, program="acme", family="web_bounty", lane="web", root_override=tmp_path)["title"] == "Reflected XSS on search"


def test_update_finding_preserves_observation_metadata_and_refreshes(tmp_path):
    added = add_finding(_finding(), root_override=tmp_path)
    original = added["finding"]
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path)
    jsonl_path = layout.ledgers_root / "findings.jsonl"
    original_event_count = len(jsonl_path.read_text(encoding="utf-8").splitlines())
    old_report_path = Path(original["report_path"])

    updated = update_finding(
        original["identity"],
        {"status": "confirmed", "severity": "P2", "notes": "Confirmed manually."},
        "acme",
        "web_bounty",
        "web",
        root_override=tmp_path,
    )

    finding = updated["finding"]
    assert updated["ok"] is True
    assert finding["status"] == "confirmed"
    assert finding["severity"] == "HIGH"
    assert finding["notes"] == "Confirmed manually."
    assert finding["created_at"] == original["created_at"]
    assert finding["sightings"] == original["sightings"]
    assert finding["provenance"] == original["provenance"]

    events = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == original_event_count + 1
    assert events[-1]["event"] == "finding_updated"
    assert events[-1]["identity"] == original["identity"]

    assert not (layout.ledgers_root / "indexes" / "by_status" / "raw.json").exists()
    assert (layout.ledgers_root / "indexes" / "by_status" / "confirmed.json").exists()
    assert Path(finding["report_path"]) == layout.reports_root / finding["fid"] / "REPORT.md"
    assert Path(finding["report_dir"]) == layout.reports_root / finding["fid"]
    assert Path(finding["report_path"]).exists()
    assert (Path(finding["report_dir"]) / "poc").is_dir()
    assert (Path(finding["report_dir"]) / "evidence").is_dir()
    assert "Reflected XSS on search" in (layout.reports_root / "index" / "confirmed.md").read_text(encoding="utf-8")
    assert "Reflected XSS on search" not in (layout.reports_root / "index" / "raw.md").read_text(encoding="utf-8")
    assert "Reflected XSS on search" in (layout.reports_root / "confirmed" / "xss" / "index.md").read_text(encoding="utf-8")
    assert "Reflected XSS on search" not in (layout.reports_root / "raw" / "xss" / "index.md").read_text(encoding="utf-8")


def test_unsafe_identity_uses_safe_report_filename_without_changing_identity(tmp_path):
    finding = _finding()
    finding["identity"] = "../../../../escape"

    result = add_finding(finding, root_override=tmp_path)
    stored = result["finding"]
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path)
    report_path = Path(stored["report_path"])

    assert stored["identity"] == "../../../../escape"
    assert report_path == layout.reports_root / stored["fid"] / "REPORT.md"
    assert Path(stored["report_dir"]) == report_path.parent
    assert report_path.resolve(strict=False).is_relative_to(layout.reports_root.resolve(strict=False))
    assert not (layout.lane_root / "escape-reflected-xss-on-search.md").exists()


def test_update_finding_does_not_delete_report_path_outside_reports_root(tmp_path):
    added = add_finding(_finding(), root_override=tmp_path)
    identity = added["finding"]["identity"]
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path)
    outside_report = tmp_path / "outside-report.md"
    outside_report.write_text("keep me\n", encoding="utf-8")

    ledger_path = layout.ledgers_root / "ledger.json"
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    payload["findings"][0]["report_path"] = str(outside_report)
    ledger_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    updated = update_finding(identity, {"status": "confirmed"}, "acme", "web_bounty", "web", root_override=tmp_path)

    assert updated["ok"] is True
    assert outside_report.read_text(encoding="utf-8") == "keep me\n"
    assert Path(updated["finding"]["report_path"]) == layout.reports_root / updated["finding"]["fid"] / "REPORT.md"


def test_get_by_report_path(tmp_path):
    result = add_finding(_finding(), root_override=tmp_path)

    found = get_finding(report_path=result["finding"]["report_path"], root_override=tmp_path)

    assert found["identity"] == result["finding"]["identity"]


def test_recon_start_run_layout_and_manifest(tmp_path):
    run = start_run(
        "httpx",
        "example.com",
        "acme",
        "web_bounty",
        "web",
        date="2026-04-28",
        run_id="run-001",
        root_override=tmp_path,
    )
    expected = tmp_path / "web_bounty" / "acme" / "web" / "recon" / "httpx" / "example.com" / "runs" / "2026-04-28" / "run-001"

    assert run.run_dir == expected
    assert run.raw_dir == expected / "raw"
    assert run.parsed_dir == expected / "parsed"
    assert run.command_path == expected / "command.txt"
    assert run.stdout_path == expected / "stdout.txt"
    assert run.stderr_path == expected / "stderr.txt"

    manifest_path = write_manifest(run, {"command": ["httpx", "-u", "https://example.com"], "exit_code": 0})
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["tool"] == "httpx"
    assert manifest["target"] == "example.com"
    assert manifest["program"] == "acme"
    assert manifest["family"] == "web_bounty"
    assert manifest["lane"] == "web"
    assert manifest["date"] == "2026-04-28"
    assert manifest["run_id"] == "run-001"
    assert manifest["started_at"] == run.started_at
    assert manifest["finished_at"] is None
    assert manifest["exit_code"] == 0
    assert manifest["run_dir"] == str(expected)
    assert manifest["raw_dir"] == str(expected / "raw")
    assert manifest["parsed_dir"] == str(expected / "parsed")
    assert manifest["command_file"] == str(expected / "command.txt")
    assert manifest["stdout_file"] == str(expected / "stdout.txt")
    assert manifest["stderr_file"] == str(expected / "stderr.txt")
    assert manifest["command_path"] == str(expected / "command.txt")
    assert manifest["stdout_path"] == str(expected / "stdout.txt")
    assert manifest["stderr_path"] == str(expected / "stderr.txt")
    assert manifest["raw_files"] == []
    assert manifest["parsed_files"] == []
    assert manifest["counts"] == {
        "raw_records": 0,
        "parsed_records": 0,
        "promotion_candidates": 0,
        "promoted_findings": 0,
    }


def test_recon_start_run_rejects_unsafe_or_invalid_date(tmp_path):
    for unsafe_date in ("../escape", "20260428", "2026-02-30"):
        with pytest.raises(ValueError):
            start_run(
                "httpx",
                "example.com",
                "acme",
                "web_bounty",
                "web",
                date=unsafe_date,
                run_id="run-001",
                root_override=tmp_path,
            )


def test_binaries_apk_recon_uses_recon_root_not_input(tmp_path):
    run = start_run(
        "apktool",
        "demo.apk",
        "mobile",
        "binaries",
        "apk",
        date="2026-04-28",
        run_id="run-001",
        root_override=tmp_path,
    )
    lane_root = tmp_path / "binaries" / "mobile" / "apk"

    assert run.run_dir == lane_root / "recon" / "apktool" / "demo.apk" / "runs" / "2026-04-28" / "run-001"
    assert "input" not in run.run_dir.parts
    assert run.layout.recon_root == lane_root / "recon"
    assert run.layout.input_root == lane_root / "input"


def test_malformed_imported_type_and_status_cannot_escape_ledger_indexes(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)

    written = refresh_indexes(
        layout,
        [
            {
                "identity": "imported-1",
                "type": "../../escaped-type",
                "status": "../escaped-status",
                "updated_at": "2026-04-28T00:00:00Z",
            }
        ],
    )

    assert written["by_type/escaped-type"] == layout.ledgers_root / "indexes" / "by_type" / "escaped-type.json"
    assert written["by_status/escaped-status"] == layout.ledgers_root / "indexes" / "by_status" / "escaped-status.json"
    assert not (layout.ledgers_root / "indexes" / "escaped-type.json").exists()
    assert not (layout.ledgers_root / "escaped-status.json").exists()


def test_duplicate_add_finding_status_move_rewrites_report_and_removes_stale_report(tmp_path):
    first = add_finding(_finding(), root_override=tmp_path)
    old_report_path = Path(first["finding"]["report_path"])
    updated_finding = _finding()
    updated_finding["status"] = "confirmed"
    updated_finding["summary"] = "Confirmed duplicate observation."

    second = add_finding(updated_finding, root_override=tmp_path)
    new_report_path = Path(second["finding"]["report_path"])

    assert second["is_new"] is False
    assert second["finding"]["status"] == "confirmed"
    assert new_report_path == old_report_path
    assert new_report_path.exists()
    assert "Confirmed duplicate observation." in new_report_path.read_text(encoding="utf-8")
