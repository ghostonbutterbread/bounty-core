from pathlib import Path

import pytest

from bounty_core import add_finding, resolve_storage
from bounty_core.reports import refresh_report_indexes


def test_storage_ledger_report_indexes(tmp_path):
    result = add_finding(
        {
            "program": "acme",
            "family": "web_bounty",
            "lane": "web",
            "type": "fuzz",
            "status": "raw",
            "severity": "LOW",
            "title": "Fuzz discovery: /admin",
            "asset": "https://example.com/admin",
            "url": "https://example.com/admin",
            "status_code": 403,
            "source_tool": "test",
            "source_repo": "bounty-core-tests",
        },
        root_override=tmp_path,
    )

    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path)
    assert result["is_new"] is True
    assert (layout.ledgers_root / "ledger.json").exists()
    assert (layout.ledgers_root / "findings.jsonl").exists()
    assert (layout.ledgers_root / "indexes" / "by_type" / "fuzz.json").exists()
    assert (layout.ledgers_root / "indexes" / "by_status" / "raw.json").exists()
    assert (layout.ledgers_root / "indexes" / "active_slice.json").exists()
    assert (layout.reports_root / "raw" / "fuzz" / "index.md").exists()
    assert (layout.reports_root / "index" / "fuzz.md").exists()


def test_refresh_report_indexes_does_not_rewrite_dated_report_buckets(tmp_path):
    layout = resolve_storage("acme", family="web_bounty", lane="web", root_override=tmp_path, create=True)
    dated_index = layout.reports_root / "novel" / "05-05-2026" / "index.md"
    dated_index.parent.mkdir(parents=True)
    dated_index.write_text("# Novel Findings\n\nNo reviewed novel findings.\n", encoding="utf-8")

    refresh_report_indexes(layout, [])

    assert dated_index.read_text(encoding="utf-8") == "# Novel Findings\n\nNo reviewed novel findings.\n"
    assert not (layout.reports_root / "novel" / "05-05-2026" / "index.md").read_text(encoding="utf-8").startswith("# Novel 05-05-2026")


def test_duplicate_updates_existing_identity(tmp_path):
    finding = {
        "program": "acme",
        "family": "web_bounty",
        "lane": "web",
        "type": "fuzz",
        "status": "raw",
        "asset": "https://example.com/admin",
        "url": "https://example.com/admin",
        "status_code": 403,
        "source_tool": "test",
        "source_repo": "bounty-core-tests",
    }
    first = add_finding(finding, root_override=tmp_path)
    second = add_finding(finding, root_override=tmp_path)

    assert first["is_new"] is True
    assert second["is_new"] is False
    assert len(second["finding"].get("sightings", [])) == 2


def test_custom_lane_requires_explicit_family(tmp_path):
    with pytest.raises(ValueError):
        resolve_storage("acme", lane="custom", root_override=tmp_path)

    layout = resolve_storage("acme", family="web_bounty", lane="custom", root_override=tmp_path)

    assert layout.family == "web_bounty"
    assert layout.lane == "custom"


@pytest.mark.parametrize(
    "root_suffix",
    [
        ("Shared", "web_bounty"),
        ("web_bounty", "acme"),
        ("web_bounty", "acme", "web"),
        ("web_bounty", "acme", "web", "recon"),
        ("web_bounty", "acme", "web", "recon", "maps"),
    ],
)
def test_root_override_accepts_canonical_subroots(tmp_path, root_suffix):
    supplied_root = tmp_path.joinpath(*root_suffix)
    expected_base = tmp_path / "Shared" if root_suffix[:1] == ("Shared",) else tmp_path

    layout = resolve_storage(
        "acme",
        family="web_bounty",
        lane="web",
        root_override=supplied_root,
    )

    assert layout.base_root == expected_base
    assert layout.lane_root == expected_base / "web_bounty" / "acme" / "web"
    assert "web_bounty/web_bounty" not in layout.lane_root.as_posix()


def test_root_override_preserves_ambiguous_base_named_like_family(tmp_path):
    base_root = tmp_path / "web_bounty"

    layout = resolve_storage(
        "acme",
        family="web_bounty",
        lane="web",
        root_override=base_root,
    )

    assert layout.base_root == base_root
    assert layout.lane_root == base_root / "web_bounty" / "acme" / "web"


def test_root_override_accepts_binary_canonical_subroots(tmp_path):
    supplied_root = tmp_path / "binaries" / "mobile" / "apk" / "recon" / "maps"

    layout = resolve_storage(
        "mobile",
        family="binaries",
        lane="apk",
        root_override=supplied_root,
    )

    assert layout.base_root == tmp_path
    assert layout.lane_root == tmp_path / "binaries" / "mobile" / "apk"
