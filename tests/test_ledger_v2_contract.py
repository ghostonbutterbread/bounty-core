import json
from pathlib import Path

import pytest

from bounty_core import add_finding, patch_finding_by_fid, resolve_storage, update_finding
from bounty_core.ledger import VersionedFindingsLedger, ledger_add, ledger_get, ledger_list, ledger_path


def _payload():
    return {
        "version": 2,
        "program": "mobile",
        "updated_at": "2026-04-28T00:00:00Z",
        "coverage": {"src/preload.js": {"ipc-trust-boundary": True}},
        "findings": [
            {
                "fid": "D01",
                "type": "IPC trust boundary",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
                "first_seen": "2026-04-27T10:00:00Z",
                "first_snapshot": "snap-a",
                "last_seen": "2026-04-27T10:00:00Z",
                "last_snapshot": "snap-a",
                "sighting_count": 99,
                "team_type": "base-team",
                "sightings": [
                    {
                        "snapshot_id": "snap-a",
                        "version_label": "v1.0.0",
                        "run_id": "run-a",
                        "seen_at": "2026-04-27T10:00:00Z",
                        "status": "needs-review",
                        "review_tier": "pending-review",
                        "agent": "fixture",
                        "review_notes": ["preserve me"],
                    }
                ],
                "current": {
                    "review_tier": "pending-review",
                    "status": "needs-review",
                    "version_label": "v1.0.0",
                },
                "custom_finding_field": {"keep": True},
            }
        ],
    }


def test_core_v2_read_does_not_mutate_fixture(tmp_path):
    path = ledger_path("mobile", family="binaries", lane="apk", root_override=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(), indent=2) + "\n", encoding="utf-8")
    before = path.read_bytes()

    assert ledger_get("mobile", "D01", family="binaries", lane="apk", root_override=tmp_path)["fid"] == "D01"
    assert path.read_bytes() == before


def test_core_v2_write_preserves_unknown_fields_and_sighting_count(tmp_path):
    path = ledger_path("mobile", family="binaries", lane="apk", root_override=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(), indent=2) + "\n", encoding="utf-8")

    is_new, fid = ledger_add(
        "mobile",
        {
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "CRITICAL",
        },
        "snap-b",
        "v1.1.0",
        "run-b",
        "core-test",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )

    assert is_new is False
    assert fid == "D01"
    written = json.loads(path.read_text(encoding="utf-8"))
    finding = written["findings"][0]
    assert written["coverage"] == _payload()["coverage"]
    assert finding["team_type"] == "base-team"
    assert finding["custom_finding_field"] == {"keep": True}
    assert finding["sighting_count"] == 99
    assert finding["sightings"][0]["review_notes"] == ["preserve me"]
    assert [item["snapshot_id"] for item in finding["sightings"]] == ["snap-a", "snap-b"]


def test_core_source_apk_identity_includes_line_and_type(tmp_path):
    first = ledger_add(
        "mobile",
        {
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
        },
        "snap-a",
        "v1.0.0",
        "run-a",
        "core-test",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )
    second = ledger_add(
        "mobile",
        {
            "type": "Different sink",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
        },
        "snap-a",
        "v1.0.0",
        "run-a",
        "core-test",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )

    assert first == (True, "D01")
    assert second == (True, "D02")
    assert {item["type"] for item in ledger_list("mobile", family="binaries", lane="apk", root_override=tmp_path)} == {
        "IPC trust boundary",
        "Different sink",
    }



def test_core_v2_write_preserves_current_status_when_update_has_no_status(tmp_path):
    path = ledger_path("mobile", family="binaries", lane="apk", root_override=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(), indent=2) + "\n", encoding="utf-8")

    ledger_add(
        "mobile",
        {
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "CRITICAL",
        },
        "snap-b",
        "v1.1.0",
        "run-b",
        "core-test",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )

    finding = json.loads(path.read_text(encoding="utf-8"))["findings"][0]
    assert finding["current"]["status"] == "needs-review"
    assert finding["current"]["review_tier"] == "pending-review"
    assert finding["sightings"][-1]["status"] == "needs-review"
    assert finding["sightings"][-1]["review_tier"] == "pending-review"


def test_patch_finding_by_fid_preserves_observation_metadata_without_side_effects(tmp_path):
    path = ledger_path("mobile", family="binaries", lane="apk", root_override=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(), indent=2) + "\n", encoding="utf-8")
    layout = resolve_storage("mobile", family="binaries", lane="apk", root_override=tmp_path)
    jsonl_path = layout.ledgers_root / "findings.jsonl"
    jsonl_path.write_text(json.dumps({"existing": True}) + "\n", encoding="utf-8")
    original_jsonl = jsonl_path.read_text(encoding="utf-8")

    patched = patch_finding_by_fid(
        "mobile",
        "D01",
        {
            "title": "Corrected IPC finding",
            "file": "src/corrected.js",
            "line": 7,
            "severity": "CRITICAL",
            "first_snapshot": "bad-snap",
            "last_snapshot": "bad-snap",
            "sighting_count": 0,
            "sightings": [],
            "current": {"status": "bad"},
            "snapshot_id": "bad-snap",
            "version_label": "bad-version",
            "run_id": "bad-run",
        },
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )

    assert patched is not None
    written = json.loads(path.read_text(encoding="utf-8"))
    finding = written["findings"][0]
    assert finding["title"] == "Corrected IPC finding"
    assert finding["file"] == "src/corrected.js"
    assert finding["line"] == 7
    assert finding["severity"] == "CRITICAL"
    assert finding["first_snapshot"] == "snap-a"
    assert finding["last_snapshot"] == "snap-a"
    assert finding["sighting_count"] == 99
    assert finding["sightings"] == _payload()["findings"][0]["sightings"]
    assert finding["current"] == _payload()["findings"][0]["current"]
    assert jsonl_path.read_text(encoding="utf-8") == original_jsonl
    assert not layout.reports_root.exists()
    assert not (layout.ledgers_root / "indexes").exists()


def test_patch_finding_by_fid_can_refresh_reports_and_indexes_when_requested(tmp_path):
    path = ledger_path("mobile", family="binaries", lane="apk", root_override=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(), indent=2) + "\n", encoding="utf-8")
    layout = resolve_storage("mobile", family="binaries", lane="apk", root_override=tmp_path)

    patched = patch_finding_by_fid(
        "mobile",
        "D01",
        {
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "status": "confirmed",
            "review_notes": "Confirmed by reviewer.",
        },
        family="binaries",
        lane="apk",
        root_override=tmp_path,
        write_report=True,
        refresh=True,
        update_current=True,
    )

    assert patched is not None
    written = json.loads(path.read_text(encoding="utf-8"))
    finding = written["findings"][0]
    assert len(written["findings"]) == 1
    assert finding["fid"] == "D01"
    assert finding["current"]["review_tier"] == "CONFIRMED"
    assert finding["current"]["status"] == "confirmed"
    assert Path(finding["report_path"]).exists()
    assert (layout.ledgers_root / "indexes" / "by_status" / "confirmed.json").exists()
    assert "IPC trust boundary" in (layout.reports_root / "index" / "confirmed.md").read_text(encoding="utf-8")


def test_old_add_finding_api_uses_v2_identity_for_source_style_findings(tmp_path):
    first = add_finding(
        {
            "program": "mobile",
            "family": "binaries",
            "lane": "apk",
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "HIGH",
            "status": "needs-review",
        },
        root_override=tmp_path,
        write_report=False,
        refresh=False,
    )
    second = ledger_add(
        "mobile",
        {
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "HIGH",
        },
        "snap-a",
        "v1.0.0",
        "run-a",
        "core-test",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )

    assert first["is_new"] is True
    assert first["finding"]["fid"] == "D01"
    assert second == (False, "D01")
    findings = ledger_list("mobile", family="binaries", lane="apk", root_override=tmp_path)
    assert len(findings) == 1
    assert findings[0]["current"]["status"] == "needs-review"


def test_old_update_finding_api_preserves_custom_status_values(tmp_path):
    added = add_finding(
        {
            "program": "mobile",
            "family": "binaries",
            "lane": "apk",
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "HIGH",
            "status": "needs-review",
        },
        root_override=tmp_path,
        write_report=False,
        refresh=False,
    )

    updated = update_finding(
        added["finding"]["identity"],
        {"status": "needs-review", "review_tier": "pending-review"},
        "mobile",
        "binaries",
        "apk",
        root_override=tmp_path,
        refresh=False,
    )

    assert updated["ok"] is True
    assert updated["finding"]["status"] == "needs-review"
    assert updated["finding"]["review_tier"] == "pending-review"


def test_update_finding_preserves_hand_edited_canonical_report(tmp_path):
    added = add_finding(
        {
            "program": "mobile",
            "family": "binaries",
            "lane": "apk",
            "type": "IPC trust boundary",
            "class_name": "ipc-trust-boundary",
            "file": "src/preload.js",
            "line": 44,
            "severity": "HIGH",
            "status": "dormant",
        },
        root_override=tmp_path,
        write_report=True,
        refresh=True,
    )
    finding = added["finding"]
    report_path = Path(finding["report_path"])
    report_path.write_text(report_path.read_text(encoding="utf-8") + "\nManual reviewer note.\n", encoding="utf-8")

    updated = update_finding(
        finding["identity"],
        {"title": "Updated title from ledger", "status": "confirmed"},
        "mobile",
        "binaries",
        "apk",
        root_override=tmp_path,
        refresh=True,
    )

    assert updated["ok"] is True
    moved_path = Path(updated["finding"]["report_path"])
    assert moved_path != report_path
    assert not report_path.exists()
    text = moved_path.read_text(encoding="utf-8")
    assert "Manual reviewer note." in text
    assert "Updated title from ledger" not in text


def test_versioned_ledger_fingerprint_matches_source_style_identity_policy(tmp_path):
    ledger = VersionedFindingsLedger(
        "mobile",
        target_root=tmp_path,
        snapshot_identity={"snapshot_id": "snap-a", "version_label": "v1"},
        family="binaries",
        lane="apk",
        root_override=tmp_path,
    )
    base = {"type": "IPC trust boundary", "class_name": "ipc-trust-boundary", "file": "src/preload.js", "line": 44}

    assert ledger.fingerprint_for(base) != ledger.fingerprint_for({**base, "line": 88})
    assert ledger.fingerprint_for(base) != ledger.fingerprint_for({**base, "type": "Different sink"})
    assert ledger.fingerprint_for({"class_name": "ipc-trust-boundary", "file": "src/preload.js", "line": 44, "sink": "a"}) == ledger.fingerprint_for(
        {"class_name": "ipc-trust-boundary", "file": "src/preload.js", "line": 44, "sink": "b"}
    )

def test_core_root_override_and_storage_root_conflict_is_rejected(tmp_path):
    assert ledger_path(
        "mobile",
        family="binaries",
        lane="apk",
        root_override=tmp_path,
        storage_root=tmp_path,
    ) == tmp_path / "binaries" / "mobile" / "apk" / "ledgers" / "ledger.json"

    with pytest.raises(ValueError):
        ledger_add(
            "mobile",
            {"type": "IPC trust boundary", "class_name": "ipc", "file": "src/preload.js", "line": 44},
            "snap-a",
            "v1.0.0",
            "run-a",
            "core-test",
            family="binaries",
            lane="apk",
            root_override=tmp_path / "one",
            storage_root=tmp_path / "two",
        )
