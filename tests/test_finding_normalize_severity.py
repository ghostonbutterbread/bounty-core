"""normalize_severity alias coverage, including the P0 exceptional-severity alias."""

import pytest

from bounty_core.finding import normalize_severity


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("P0", "CRITICAL"),
        ("p0", "CRITICAL"),
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
