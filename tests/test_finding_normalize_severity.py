"""normalize_severity alias coverage, including the P0 exceptional-severity alias."""

import pytest

from bounty_core.finding import normalize_severity


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("P0", "EXCEPTIONAL"),
        ("p0", "EXCEPTIONAL"),
        ("EXCEPTIONAL", "EXCEPTIONAL"),
        ("exceptional", "EXCEPTIONAL"),
        ("P1", "CRITICAL"),
        ("P2", "HIGH"),
        ("P3", "MEDIUM"),
        ("P4", "LOW"),
        ("P5", "INFO"),
        ("critical", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("informational", "INFO"),
        ("", "UNKNOWN"),
        (None, "UNKNOWN"),
        ("P9", "UNKNOWN"),
        ("bogus", "UNKNOWN"),
    ],
)
def test_normalize_severity_aliases(raw, expected):
    assert normalize_severity(raw) == expected


def test_exceptional_sorts_above_critical():
    from bounty_core.reports import SEVERITY_PRIORITY

    assert SEVERITY_PRIORITY["EXCEPTIONAL"] < SEVERITY_PRIORITY["CRITICAL"]


def test_exceptional_groups_into_high_view_bucket():
    from bounty_core.reports import _severity_group_for

    finding = {"severity": "P0"}
    assert _severity_group_for(finding) == "HIGH"
