from __future__ import annotations

import json
from pathlib import Path

import pytest

from bounty_core.reports import (
    CATEGORY_STUB_GENERATED_MARKER,
    DAILY_REPORT_DATE_FORMAT,
    FINDING_REPORT_GENERATED_MARKER,
    REPORT_NAV_GENERATED_MARKER,
    canonical_report_wikilink,
    canonical_finding_report_path,
    category_report_slug,
    is_generated_safe_finding_report,
    obsidian_report_link,
    refresh_report_navigation_from_ledger,
    refresh_report_indexes,
    render_finding_report,
    safe_symlink_or_link_stub,
    write_finding_report,
)
from bounty_core.storage import resolve_storage


def _finding(**overrides):
    finding = {
        "fid": "D01",
        "program": "acme",
        "family": "web_bounty",
        "lane": "web",
        "title": "Renderer bridge requires prior XSS",
        "type": "renderer bridge",
        "class_name": "renderer-bridge",
        "status": "dormant",
        "review_tier": "DORMANT_ACTIVE",
        "severity": "HIGH",
        "file": "src/main.js",
        "source": "location.hash",
        "sink": "host.rpc",
        "description": "Full vulnerability body text that must stay out of navigation.",
        "report_category": "Renderer / Privileged Bridge",
        "updated_at": "2026-06-13T12:00:00Z",
    }
    finding.update(overrides)
    return finding


def test_write_finding_report_uses_stable_fid_path(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    first = _finding(title="Original title", status="raw", review_tier="")
    first_path = write_finding_report(layout, first)

    changed = _finding(title="Changed title", status="confirmed", type="xss")
    changed_path = write_finding_report(layout, changed)

    assert first_path == layout.reports_root / "findings" / "active" / "D01 - HIGH - Original title.md"
    assert changed_path == layout.reports_root / "findings" / "confirmed" / "D01 - HIGH - Changed title.md"
    assert canonical_finding_report_path(layout, changed) == changed_path
    assert not first_path.exists()


def test_write_finding_report_marks_and_updates_only_generated_safe_body(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    first_path = write_finding_report(layout, _finding(title="Original title"))

    assert FINDING_REPORT_GENERATED_MARKER in first_path.read_text(encoding="utf-8")
    assert is_generated_safe_finding_report(first_path)

    changed_path = write_finding_report(layout, _finding(title="Changed title"))
    assert changed_path != first_path
    assert not first_path.exists()
    assert "# Changed title" in changed_path.read_text(encoding="utf-8")

    changed_path.write_text(changed_path.read_text(encoding="utf-8") + "\nManual reviewer note.\n", encoding="utf-8")
    assert not is_generated_safe_finding_report(changed_path)
    preserved_path = write_finding_report(layout, _finding(title="Overwrite attempt"))

    assert preserved_path == layout.reports_root / "findings" / "dormant" / "D01 - HIGH - Overwrite attempt.md"
    assert not changed_path.exists()
    edited_text = preserved_path.read_text(encoding="utf-8")
    assert "Manual reviewer note." in edited_text
    assert "Overwrite attempt" not in edited_text


def test_write_finding_report_moves_hand_edited_same_fid_to_new_canonical_path(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    old_path = write_finding_report(layout, _finding(title="Original title", status="dormant"))
    old_path.write_text(old_path.read_text(encoding="utf-8") + "\nManual reviewer note.\n", encoding="utf-8")

    changed = _finding(title="Changed (reviewed) title", status="confirmed", severity="P2")
    new_path = write_finding_report(layout, changed)

    assert new_path == layout.reports_root / "findings" / "confirmed" / "D01 - HIGH - Changed (reviewed) title.md"
    assert not old_path.exists()
    text = new_path.read_text(encoding="utf-8")
    assert "Manual reviewer note." in text
    assert "Changed (reviewed) title" not in text
    assert "report_path_conflict" not in changed


def test_refresh_report_indexes_writes_daily_month_first_link_views(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding()
    report_path = write_finding_report(layout, finding)
    report_path.write_text(render_finding_report(finding), encoding="utf-8")
    finding["report_path"] = str(report_path)

    written = refresh_report_indexes(layout, [finding])

    daily_root = layout.reports_root / "daily" / "06-13-2026"
    assert DAILY_REPORT_DATE_FORMAT == "%m-%d-%Y"
    assert written["daily/06-13-2026/index"] == daily_root / "index.md"
    dormant = (daily_root / "dormant.md").read_text(encoding="utf-8")
    assert "## HIGH" in dormant
    assert "|---|" not in dormant
    assert "D01%20-%20HIGH" not in dormant
    assert "<../../findings/dormant" not in dormant
    assert "../../findings/dormant/D01 - HIGH - Renderer bridge requires prior XSS.md" not in dormant
    assert "[[D01 - HIGH - Renderer bridge requires prior XSS|D01]]" in dormant
    assert "Full vulnerability body text that must stay out of navigation." not in dormant
    assert not (layout.reports_root / "dormant" / "06-13-2026").exists()


def test_refresh_report_indexes_writes_global_daily_and_severity_grouped_views(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    findings = [
        _finding(fid="A01", title="Raw active issue", status="raw", review_tier="", severity="LOW"),
        _finding(fid="D01", title="Dormant issue", status="dormant", review_tier="DORMANT_ACTIVE", severity="HIGH"),
        _finding(fid="C01", title="Confirmed issue", status="confirmed", review_tier="CONFIRMED", severity="MEDIUM"),
        _finding(fid="X01", title="Completed issue", status="complete", review_tier="COMPLETED", severity="UNKNOWN"),
    ]
    for finding in findings:
        finding["report_path"] = str(write_finding_report(layout, finding))

    written = refresh_report_indexes(layout, findings)

    for name in ("active", "dormant", "confirmed", "completed"):
        text = (layout.reports_root / f"{name}.md").read_text(encoding="utf-8")
        assert "## HIGH" in text
        assert "## MEDIUM" in text
        assert "## LOW" in text
        assert "## UNKNOWN" in text
        assert "|---|" not in text
        assert "Full vulnerability body text that must stay out of navigation." not in text
        assert written[f"global/{name}"] == layout.reports_root / f"{name}.md"

    daily_root = layout.reports_root / "daily" / "06-13-2026"
    assert (daily_root / "active.md").exists()
    assert (daily_root / "completed.md").exists()
    assert "A01" in (daily_root / "active.md").read_text(encoding="utf-8")
    assert "X01" in (daily_root / "completed.md").read_text(encoding="utf-8")
    assert "|---|" not in (daily_root / "index.md").read_text(encoding="utf-8")

    high_index = layout.reports_root / "severity" / "high" / "index.md"
    medium_index = layout.reports_root / "severity" / "medium" / "index.md"
    low_index = layout.reports_root / "severity" / "low" / "index.md"
    assert written["severity/high"] == high_index
    assert "D01" in high_index.read_text(encoding="utf-8")
    assert "C01" in medium_index.read_text(encoding="utf-8")
    assert "A01" in low_index.read_text(encoding="utf-8")
    assert "X01" not in low_index.read_text(encoding="utf-8")


def test_refresh_report_indexes_dedupes_generated_navigation_by_concept(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    title = "Unauthenticated recording blob read via custom protocol token enumeration"
    findings = [
        _finding(
            fid="D43",
            title=title,
            type="protocol token enumeration",
            status="raw",
            review_tier="",
            severity="HIGH",
            file="SRC/protocol.ts",
            line="42",
            report_category="information_disclosure",
        ),
        _finding(
            fid="D49",
            title=f"{title}!",
            type="Protocol Token Enumeration",
            status="dormant",
            review_tier="DORMANT_ACTIVE",
            severity="CRITICAL",
            file="src/protocol.ts",
            line=42,
            report_category="Information Disclosure",
        ),
        _finding(
            fid="D54",
            title=title,
            type="protocol-token-enumeration",
            status="confirmed",
            review_tier="CONFIRMED",
            severity="MEDIUM",
            file="src/protocol.ts",
            line=42,
            report_category="Information Disclosure",
        ),
        _finding(
            fid="D76",
            title=title.upper(),
            type="protocol token enumeration",
            status="raw",
            review_tier="",
            severity="HIGH",
            file="src/protocol.ts",
            line="42.0",
            report_category="Information Disclosure",
        ),
    ]
    for finding in findings:
        finding["report_path"] = str(write_finding_report(layout, finding))

    refresh_report_indexes(layout, findings)

    confirmed_text = (layout.reports_root / "confirmed.md").read_text(encoding="utf-8")
    active_text = (layout.reports_root / "active.md").read_text(encoding="utf-8")
    dormant_text = (layout.reports_root / "dormant.md").read_text(encoding="utf-8")
    assert "D54" in confirmed_text
    assert "Aliases: D43, D49, D76" in confirmed_text
    assert "D43" not in active_text
    assert "D76" not in active_text
    assert "D49" not in dormant_text

    medium_text = (layout.reports_root / "severity" / "medium" / "index.md").read_text(encoding="utf-8")
    high_text = (layout.reports_root / "severity" / "high" / "index.md").read_text(encoding="utf-8")
    assert "D54" in medium_text
    assert "Aliases: D43, D49, D76" in medium_text
    assert "D43" not in high_text
    assert "D49" not in high_text
    assert "D76" not in high_text

    category_text = (
        layout.reports_root / "categories" / "information-disclosure" / "index.md"
    ).read_text(encoding="utf-8")
    assert "| FID | Status | Severity | Last Seen | Title | Aliases |" in category_text
    assert "Count: 1" in category_text
    assert "D54" in category_text
    assert "D43, D49, D76" in category_text


def test_refresh_report_indexes_keeps_same_title_different_line_separate(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    findings = [
        _finding(fid="D01", title="Shared title", status="raw", review_tier="", file="src/a.js", line=10),
        _finding(fid="D02", title="Shared title", status="raw", review_tier="", file="src/a.js", line=11),
    ]
    for finding in findings:
        finding["report_path"] = str(write_finding_report(layout, finding))

    refresh_report_indexes(layout, findings)

    active_text = (layout.reports_root / "active.md").read_text(encoding="utf-8")
    assert "Count: 2" in active_text
    assert "D01" in active_text
    assert "D02" in active_text
    assert "Aliases:" not in active_text


def test_refresh_report_indexes_preserves_hand_authored_navigation_files(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding()
    finding["report_path"] = str(write_finding_report(layout, finding))

    active_path = layout.reports_root / "active.md"
    category_index = layout.reports_root / "categories" / category_report_slug(finding) / "index.md"
    severity_index = layout.reports_root / "severity" / "high" / "index.md"
    category_index.parent.mkdir(parents=True)
    severity_index.parent.mkdir(parents=True)
    active_path.write_text("# Manual active\n\nKeep this.\n", encoding="utf-8")
    category_index.write_text("# Manual category\n\nKeep this.\n", encoding="utf-8")
    severity_index.write_text("# Manual severity\n\nKeep this.\n", encoding="utf-8")

    written = refresh_report_indexes(layout, [finding])

    assert active_path.read_text(encoding="utf-8") == "# Manual active\n\nKeep this.\n"
    assert category_index.read_text(encoding="utf-8") == "# Manual category\n\nKeep this.\n"
    assert severity_index.read_text(encoding="utf-8") == "# Manual severity\n\nKeep this.\n"
    assert "global/active" not in written
    assert f"category/{category_report_slug(finding)}" not in written
    assert "severity/high" not in written


def test_refresh_report_indexes_refreshes_generated_navigation_files(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    path = layout.reports_root / "active.md"
    path.write_text(f"{REPORT_NAV_GENERATED_MARKER}\n# Old generated active\n", encoding="utf-8")

    finding = _finding(fid="A01", title="Fresh active issue", status="raw", review_tier="", severity="LOW")
    finding["report_path"] = str(write_finding_report(layout, finding))

    written = refresh_report_indexes(layout, [finding])

    assert written["global/active"] == path
    text = path.read_text(encoding="utf-8")
    assert "Fresh active issue" in text
    assert "Old generated active" not in text


def test_refresh_report_indexes_refreshes_legacy_markerless_seeded_indexes(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    status_index = layout.reports_root / "index" / "raw.md"
    type_index = layout.reports_root / "index" / "xss.md"
    nested_index = layout.reports_root / "raw" / "xss" / "index.md"
    manual_index = layout.reports_root / "index" / "auth.md"
    status_index.write_text("# Raw\n\n", encoding="utf-8")
    type_index.write_text(
        "# XSS Findings\n\n| Severity | Type | Status | Title | Asset | Source |\n|---|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    nested_index.write_text("# Raw XSS\n\n", encoding="utf-8")
    manual_index.write_text("# Auth\n\nManual navigation notes.\n", encoding="utf-8")

    finding = _finding(fid="R01", title="Legacy seeded refresh", status="raw", review_tier="", type="xss")
    finding["report_path"] = str(write_finding_report(layout, finding))

    written = refresh_report_indexes(layout, [finding])

    assert written["status/raw"] == status_index
    assert written["type/xss"] == type_index
    assert written["status_type/raw/xss"] == nested_index
    assert REPORT_NAV_GENERATED_MARKER in status_index.read_text(encoding="utf-8")
    assert "Legacy seeded refresh" in status_index.read_text(encoding="utf-8")
    assert "Legacy seeded refresh" in type_index.read_text(encoding="utf-8")
    assert "Legacy seeded refresh" in nested_index.read_text(encoding="utf-8")
    assert manual_index.read_text(encoding="utf-8") == "# Auth\n\nManual navigation notes.\n"
    assert "type/auth" not in written


def test_refresh_report_indexes_removes_stale_generated_daily_views_after_move(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding(fid="M01", title="Original daily issue", updated_at="2026-06-13T12:00:00Z")
    finding["report_path"] = str(write_finding_report(layout, finding))
    refresh_report_indexes(layout, [finding])

    old_daily_root = layout.reports_root / "daily" / "06-13-2026"
    old_dormant = old_daily_root / "dormant.md"
    manual_note = old_daily_root / "manual.md"
    manual_note.write_text("# Manual daily note\n\nKeep this.\n", encoding="utf-8")
    assert "M01" in old_dormant.read_text(encoding="utf-8")

    moved = _finding(
        fid="M01",
        title="Moved daily issue",
        status="confirmed",
        review_tier="CONFIRMED",
        updated_at="2026-06-14T12:00:00Z",
    )
    moved["report_path"] = str(write_finding_report(layout, moved))
    refresh_report_indexes(layout, [moved])

    new_confirmed = layout.reports_root / "daily" / "06-14-2026" / "confirmed.md"
    assert not old_dormant.exists()
    assert manual_note.read_text(encoding="utf-8") == "# Manual daily note\n\nKeep this.\n"
    new_text = new_confirmed.read_text(encoding="utf-8")
    assert "M01" in new_text
    assert "[[M01 - HIGH - Moved daily issue|M01]]" in new_text
    assert "Original daily issue" not in new_text


def test_refresh_report_indexes_removes_empty_generated_category_index_after_category_change(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding(fid="G01", title="Category move")
    finding["report_path"] = str(write_finding_report(layout, finding))
    refresh_report_indexes(layout, [finding])

    original_slug = category_report_slug(finding)
    original_index = layout.reports_root / "categories" / original_slug / "index.md"
    assert REPORT_NAV_GENERATED_MARKER in original_index.read_text(encoding="utf-8")
    assert "G01" in original_index.read_text(encoding="utf-8")

    moved = _finding(fid="G01", title="Category move", report_category="External Protocol Abuse")
    moved["report_path"] = str(write_finding_report(layout, moved))
    refresh_report_indexes(layout, [moved])

    new_index = layout.reports_root / "categories" / "external-protocol-abuse" / "index.md"
    assert not original_index.exists()
    assert "G01" in new_index.read_text(encoding="utf-8")
    assert "external-protocol-abuse" in new_index.read_text(encoding="utf-8")


def test_category_symlink_or_stub_and_stale_cleanup(tmp_path, monkeypatch):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding()
    report_path = write_finding_report(layout, finding)
    report_path.write_text(render_finding_report(finding), encoding="utf-8")
    finding["report_path"] = str(report_path)

    refresh_report_indexes(layout, [finding])
    original_slug = category_report_slug(finding)
    original_entry = layout.reports_root / "categories" / original_slug / "D01.md"
    assert original_entry.exists() or original_entry.is_symlink()
    assert original_entry.resolve(strict=False) == report_path.resolve(strict=False)

    moved = _finding(report_category="External Protocol Abuse")
    moved_report_path = write_finding_report(layout, moved)
    moved["report_path"] = str(moved_report_path)
    refresh_report_indexes(layout, [moved])
    assert not original_entry.exists()
    moved_entry = layout.reports_root / "categories" / "external-protocol-abuse" / "D01.md"
    assert moved_entry.exists()
    assert moved_entry.resolve(strict=False) == moved_report_path.resolve(strict=False)

    def fail_symlink(self: Path, target: Path) -> None:
        raise OSError("symlink disabled")

    monkeypatch.setattr(Path, "symlink_to", fail_symlink)
    stub_link = layout.reports_root / "categories" / "stubbed" / "D01.md"
    result = safe_symlink_or_link_stub(stub_link, report_path, reports_root=layout.reports_root)

    assert result == "stub"
    assert CATEGORY_STUB_GENERATED_MARKER in stub_link.read_text(encoding="utf-8")


def test_safe_symlink_refuses_paths_outside_reports_root(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n", encoding="utf-8")

    with pytest.raises(ValueError):
        safe_symlink_or_link_stub(
            layout.reports_root / "categories" / "xss" / "D01.md",
            outside,
            reports_root=layout.reports_root,
        )


def test_refresh_report_navigation_from_ledger_preserves_hand_edited_finding_report(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    finding = _finding()
    report_path = write_finding_report(layout, finding)
    report_path.write_text(report_path.read_text(encoding="utf-8") + "\nManual reviewer note.\n", encoding="utf-8")
    layout.ledgers_root.mkdir(parents=True, exist_ok=True)
    (layout.ledgers_root / "ledger.json").write_text(
        (
            '{"version":2,"program":"acme","findings":['
            '{"fid":"D01","program":"acme","family":"web_bounty","lane":"web",'
            '"title":"Ledger refresh title","type":"xss","status":"confirmed","severity":"HIGH"}'
            "]}\n"
        ),
        encoding="utf-8",
    )

    refresh_report_navigation_from_ledger(layout)

    moved_path = layout.reports_root / "findings" / "confirmed" / "D01 - HIGH - Ledger refresh title.md"
    assert not report_path.exists()
    text = moved_path.read_text(encoding="utf-8")
    assert "Manual reviewer note." in text
    assert "Ledger refresh title" not in text
    payload = json.loads((layout.ledgers_root / "ledger.json").read_text(encoding="utf-8"))
    assert payload["findings"][0]["report_path"] == str(moved_path)
    daily_confirmed = next((layout.reports_root / "daily").glob("*/confirmed.md"))
    assert "[[D01 - HIGH - Ledger refresh title|D01]]" in daily_confirmed.read_text(encoding="utf-8")


def test_obsidian_report_link_uses_wikilink_relative_target_without_markdown_suffix(tmp_path):
    index_path = tmp_path / "reports" / "index.md"
    target = tmp_path / "reports" / "daily" / "06-13-2026" / "active.md"

    link = obsidian_report_link(index_path, target, "Active")

    assert link == "[[daily/06-13-2026/active|Active]]"


def test_canonical_report_wikilink_uses_file_stem_and_escapes_label(tmp_path):
    target = tmp_path / "reports" / "findings" / "active" / "D01 - HIGH - title ) # [tag].md"

    link = canonical_report_wikilink(target, "D[01]|x]")

    assert link == r"[[D01 - HIGH - title ) # [tag\]|D[01\]\|x\]]]"
