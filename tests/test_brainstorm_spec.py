from __future__ import annotations

import json
from pathlib import Path

import pytest

from bounty_core.brainstorm_spec import (
    BrainstormSpecError,
    appmap_assignment_identity,
    append_coverage,
    coverage_event_matches_assignment,
    is_appmap_assignment_covered,
    parse_brainstorm_spec,
    read_coverage_jsonl,
    spec_to_agent_intents,
    summarize_coverage,
)


def _valid_spec_text() -> str:
    return """# Brainstorm Spec: Canva Desktop EXE

## Metadata
- Program: canva
- Family: binaries
- Lane: exe
- Target kind: electron-exe
- Target path: input/app_asar
- Created: 2026-04-30
- Status: active

## Target mental model
Canva Desktop is an Electron application wrapping a rich design/editor web app.

## Impact primitives
### P001 - ElectronBridge host RPC access
- Source: `window.ElectronBridge.requestMessagePort`
- Impact: renderer JS can potentially reach host RPC modules
- Evidence: reports/dormant/index.md
- Status: active

## Hypotheses
### H001 - SVG import can create renderer script execution
Review sanitizer behavior and preview rendering before choosing payloads.
- Status: untested
- Priority: high
- Surface: import-upload-render
- Entry point: user imports or pastes SVG/design asset
- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC
- Suggested agents:
  - canva-svg-import-xss
  - canva-renderer-bridge-chain
- Focus files:
  - dist/**/*.js
  - **/*svg*
- Tags: xss, import, renderer, electron-bridge
- Evidence:
  - DORMANT-1
  - reports/dormant/index.md:12
- Notes: prioritize sanitizer and preview render paths

### H002 - Open redirect can pivot into desktop deep link or allowlist bypass
- Status: untested
- Priority: medium
- Surface: shared-link-navigation
- Entry point: trusted Canva link redirects to attacker-controlled target
- Expected chain: trusted Canva URL -> redirect -> desktop deep link
- Suggested agents:
  - canva-open-redirect-deeplink-chain
- Tags: open-redirect, deeplink, navigation

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
"""


def _write_spec(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "brainstorm" / "spec.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_parse_valid_spec_extracts_metadata_hypotheses_and_intents(tmp_path: Path) -> None:
    spec = parse_brainstorm_spec(_write_spec(tmp_path, _valid_spec_text()))

    assert spec.metadata["Program"] == "canva"
    assert spec.metadata["Target path"] == "input/app_asar"
    assert "Electron application" in spec.mental_model
    assert spec.impact_primitives[0]["id"] == "P001"
    assert spec.impact_primitives[0]["source"] == "window.ElectronBridge.requestMessagePort"
    assert [hypothesis.id for hypothesis in spec.hypotheses] == ["H001", "H002"]

    first = spec.hypotheses[0]
    assert first.status == "untested"
    assert first.priority == "high"
    assert first.suggested_agents == [
        "canva-svg-import-xss",
        "canva-renderer-bridge-chain",
    ]
    assert first.focus_files_glob == ["dist/**/*.js", "**/*svg*"]
    assert first.tags == ["xss", "import", "renderer", "electron-bridge"]
    assert first.evidence == ["DORMANT-1", "reports/dormant/index.md:12"]
    assert first.freeform_text == "Review sanitizer behavior and preview rendering before choosing payloads."

    intent = spec_to_agent_intents(spec)[0]
    assert intent.hypothesis_id == "H001"
    assert intent.agent_key == "canva-svg-import-xss"
    assert intent.source_spec_path == spec.path
    assert intent.finding_metadata() == {
        "brainstorm_spec": str(spec.path),
        "hypothesis_id": "H001",
        "hypothesis_title": "SVG import can create renderer script execution",
        "brainstorm_agent_key": "canva-svg-import-xss",
        "brainstorm_surface": "import-upload-render",
        "brainstorm_tags": ["xss", "import", "renderer", "electron-bridge"],
    }


def test_parse_rejects_duplicate_hypothesis_ids(tmp_path: Path) -> None:
    text = _valid_spec_text().replace("### H002", "### H001")

    with pytest.raises(BrainstormSpecError, match="duplicate hypothesis id: H001"):
        parse_brainstorm_spec(_write_spec(tmp_path, text))


def test_parse_rejects_invalid_status_priority_and_missing_fields(tmp_path: Path) -> None:
    bad_status = _valid_spec_text().replace("- Status: untested", "- Status: maybe", 1)
    with pytest.raises(BrainstormSpecError, match="invalid status 'maybe'"):
        parse_brainstorm_spec(_write_spec(tmp_path / "status", bad_status))

    bad_priority = _valid_spec_text().replace("- Priority: high", "- Priority: urgent", 1)
    with pytest.raises(BrainstormSpecError, match="invalid priority 'urgent'"):
        parse_brainstorm_spec(_write_spec(tmp_path / "priority", bad_priority))

    missing_chain = _valid_spec_text().replace(
        "- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC\n",
        "",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="missing required field\\(s\\): expected_chain"):
        parse_brainstorm_spec(_write_spec(tmp_path / "missing", missing_chain))


def test_parse_rejects_duplicate_or_unsafe_suggested_agent_keys(tmp_path: Path) -> None:
    duplicate = _valid_spec_text().replace(
        "canva-open-redirect-deeplink-chain",
        "CANVA-SVG-IMPORT-XSS",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(_write_spec(tmp_path / "duplicate", duplicate))

    unsafe = _valid_spec_text().replace("canva-svg-import-xss", "../escape", 1)
    with pytest.raises(BrainstormSpecError, match="path separators"):
        parse_brainstorm_spec(_write_spec(tmp_path / "unsafe", unsafe))


def test_parse_rejects_paths_outside_lane_root_by_default(tmp_path: Path) -> None:
    bad_target = _valid_spec_text().replace(
        "- Target path: input/app_asar",
        "- Target path: /etc/passwd",
    )
    with pytest.raises(BrainstormSpecError, match="metadata 'Target path' path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "target", bad_target))

    bad_focus = _valid_spec_text().replace("dist/**/*.js", "../outside/**/*.js")
    with pytest.raises(BrainstormSpecError, match="focus_files path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "focus", bad_focus))

    bad_evidence = _valid_spec_text().replace(
        "reports/dormant/index.md:12",
        "/var/tmp/outside.md",
    )
    with pytest.raises(BrainstormSpecError, match="evidence path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "evidence", bad_evidence))


def test_parse_path_validation_can_be_disabled(tmp_path: Path) -> None:
    text = _valid_spec_text().replace(
        "- Target path: input/app_asar",
        "- Target path: /etc/passwd",
    )
    spec = parse_brainstorm_spec(_write_spec(tmp_path, text), validate_paths=False)

    assert spec.metadata["Target path"] == "/etc/passwd"


def test_coverage_append_and_summary_distinguish_statuses_and_outcomes(
    tmp_path: Path,
) -> None:
    spec = parse_brainstorm_spec(_write_spec(tmp_path, _valid_spec_text()))
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    events = [
        {"event": "hypothesis_loaded", "hypothesis_id": "H001", "status": "untested"},
        {"event": "agent_queued", "hypothesis_id": "H001", "agent_key": "agent-a"},
        {"event": "agent_spawned", "hypothesis_id": "H001", "agent_key": "agent-a"},
        {"event": "agent_completed_no_finding", "hypothesis_id": "H001", "agent_key": "agent-a"},
        {"event": "agent_timeout", "hypothesis_id": "H003", "agent_key": "timeout-agent"},
        {"event": "agent_crashed", "hypothesis_id": "H004", "agent_key": "crash-agent"},
        {"event": "agent_invalid_output", "hypothesis_id": "H005", "agent_key": "invalid-agent"},
        {"event": "agent_duplicate_only", "hypothesis_id": "H006", "agent_key": "dupe-agent"},
        {"event": "review_rejected", "hypothesis_id": "H007", "agent_key": "rejected-agent"},
        {
            "event": "review_promoted",
            "hypothesis_id": "H008",
            "agent_key": "promoted-agent",
            "linked_fids": ["D12"],
        },
    ]
    for event in events:
        append_coverage(coverage_path, event)

    lines = coverage_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(events)
    assert json.loads(lines[0])["recorded_at"]

    summary = summarize_coverage(coverage_path, spec=spec)

    assert summary["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert summary["hypotheses"]["H002"]["status"] == "untested"
    assert summary["hypotheses"]["H003"]["status"] == "blocked"
    assert summary["hypotheses"]["H008"]["status"] == "tested_finding"
    assert summary["hypotheses"]["H008"]["linked_fids"] == ["D12"]
    assert summary["counts_by_status"]["untested"] == 1
    assert summary["counts_by_status"]["tested_no_finding"] == 3
    assert summary["counts_by_status"]["blocked"] == 3
    assert summary["counts_by_status"]["tested_finding"] == 1
    assert summary["counts_by_outcome"]["no_finding"] == 1
    assert summary["counts_by_outcome"]["timeout"] == 1
    assert summary["counts_by_outcome"]["crash"] == 1
    assert summary["counts_by_outcome"]["invalid_output"] == 1
    assert summary["counts_by_outcome"]["duplicate_only"] == 1
    assert summary["counts_by_outcome"]["review_rejected"] == 1
    assert summary["counts_by_outcome"]["review_promoted"] == 1


def test_append_coverage_validates_event_shape(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    with pytest.raises(BrainstormSpecError, match="hypothesis_id"):
        append_coverage(coverage_path, {"event": "hypothesis_loaded"})

    with pytest.raises(BrainstormSpecError, match="agent_key"):
        append_coverage(coverage_path, {"event": "agent_spawned", "hypothesis_id": "H001"})

    with pytest.raises(BrainstormSpecError, match="linked_fids"):
        append_coverage(
            coverage_path,
            {"event": "review_promoted", "hypothesis_id": "H001", "agent_key": "agent-a"},
        )

    with pytest.raises(BrainstormSpecError, match="raw_finding_signatures or raw_findings"):
        append_coverage(
            coverage_path,
            {
                "event": "agent_completed_with_raw_findings",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        )


def test_parse_rejects_case_insensitive_suggested_agent_key_collisions(
    tmp_path: Path,
) -> None:
    same_hypothesis = _valid_spec_text().replace(
        "  - canva-renderer-bridge-chain",
        "  - Canva-Svg-Import-Xss",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(_write_spec(tmp_path / "same", same_hypothesis))

    across_active_hypotheses = _valid_spec_text().replace(
        "canva-open-redirect-deeplink-chain",
        "CANVA-SVG-IMPORT-XSS",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(_write_spec(tmp_path / "across", across_active_hypotheses))


def test_parse_validates_retired_hypothesis_suggested_agent_keys(
    tmp_path: Path,
) -> None:
    unsafe_retired = _valid_spec_text().replace(
        "- Status: untested\n- Priority: medium",
        "- Status: retired\n- Priority: medium",
        1,
    ).replace("canva-open-redirect-deeplink-chain", "../escape", 1)
    with pytest.raises(BrainstormSpecError, match="path separators"):
        parse_brainstorm_spec(_write_spec(tmp_path / "unsafe_retired", unsafe_retired))

    retired_active_collision = _valid_spec_text().replace(
        "- Status: untested\n- Priority: medium",
        "- Status: retired\n- Priority: medium",
        1,
    ).replace("canva-open-redirect-deeplink-chain", "canva-svg-import-xss", 1)

    spec = parse_brainstorm_spec(
        _write_spec(tmp_path / "retired_collision", retired_active_collision)
    )

    assert spec.hypotheses[1].status == "retired"


def test_parse_preserves_nested_evidence_urls_and_freeform_text(tmp_path: Path) -> None:
    text = _valid_spec_text().replace(
        "Review sanitizer behavior and preview rendering before choosing payloads.",
        "Review sanitizer behavior and preview rendering before choosing payloads.\n"
        "Free-form analyst context before fields.",
        1,
    ).replace(
        "  - DORMANT-1",
        "  - DORMANT-1\n  - https://example.com/report?id=1:2",
        1,
    )

    spec = parse_brainstorm_spec(_write_spec(tmp_path, text))

    first = spec.hypotheses[0]
    assert first.freeform_text == (
        "Review sanitizer behavior and preview rendering before choosing payloads.\n"
        "Free-form analyst context before fields."
    )
    assert "https://example.com/report?id=1:2" in first.evidence


def test_coverage_raw_findings_are_pending_until_review_result(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
            "raw_finding_signatures": ["raw-1"],
        },
    )
    raw_only = summarize_coverage(coverage_path)
    assert raw_only["hypotheses"]["H001"]["status"] == "raw_finding_pending"
    assert raw_only["counts_by_status"] == {"raw_finding_pending": 1}
    assert raw_only["counts_by_outcome"] == {"raw_finding_pending": 1}
    assert raw_only["hypotheses"]["H001"]["raw_findings"] == ["raw-1"]

    append_coverage(
        coverage_path,
        {
            "event": "review_rejected",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
        },
    )
    rejected = summarize_coverage(coverage_path)
    assert rejected["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert rejected["hypotheses"]["H001"]["outcomes"]["review_rejected"] == 1

    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H002",
            "agent_key": "promoted-agent",
            "raw_findings": ["raw-2"],
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H002",
            "agent_key": "promoted-agent",
            "linked_fids": ["D99"],
        },
    )
    promoted = summarize_coverage(coverage_path)
    assert promoted["hypotheses"]["H002"]["status"] == "tested_finding"
    assert promoted["hypotheses"]["H002"]["linked_fids"] == ["D99"]


def test_coverage_explicit_hypothesis_status_is_not_overwritten(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"
    append_coverage(
        coverage_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H001",
            "agent_key": "agent-a",
            "linked_fids": ["D1"],
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "coverage_status_changed",
            "hypothesis_id": "H001",
            "status": "retired",
        },
    )

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "retired"


@pytest.mark.parametrize(
    "events",
    [
        [
            {
                "event": "agent_timeout",
                "hypothesis_id": "H001",
                "agent_key": "agent-blocked",
            },
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-clean",
            },
        ],
        [
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-clean",
            },
            {
                "event": "agent_timeout",
                "hypothesis_id": "H001",
                "agent_key": "agent-blocked",
            },
        ],
    ],
)
def test_coverage_mixed_blocked_and_no_finding_status_is_order_independent(
    tmp_path: Path,
    events: list[dict[str, str]],
) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    for event in events:
        append_coverage(coverage_path, event)

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "blocked"
    assert summary["hypotheses"]["H001"]["agents"]["agent-blocked"]["status"] == "blocked"
    assert (
        summary["hypotheses"]["H001"]["agents"]["agent-clean"]["status"]
        == "tested_no_finding"
    )


def test_coverage_rejects_agent_scoped_status_changes(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    with pytest.raises(BrainstormSpecError, match="must not include agent_key"):
        append_coverage(
            coverage_path,
            {
                "event": "coverage_status_changed",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
                "status": "retired",
            },
        )


def _appmap_identity_metadata(tmp_path: Path, **overrides: str) -> dict[str, str]:
    metadata = {
        "hypothesis_id": "H001",
        "brainstorm_agent_key": "agent-a",
        "source_spec_path": str(tmp_path / "brainstorm" / "spec.md"),
        "appmap_candidate_id": "C0001",
        "appmap_context_packet": str(tmp_path / "brainstorm" / "agent_contexts" / "H001-C0001-agent-a.json"),
        "appmap_run_id": "run-a",
        "_snapshot_id": "snap-a",
        "_snapshot_version": "1.0.0",
    }
    metadata.update(overrides)
    return metadata


def _matching_coverage_event(identity: dict[str, str], event: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "event": event,
        "hypothesis_id": identity["hypothesis_id"],
        "agent_key": identity["agent_key"],
        "source_spec_path": identity["source_spec_path"],
        "appmap_candidate_id": identity["candidate_id"],
        "appmap_context_packet": identity["appmap_context_packet"],
        "appmap_run_id": identity["appmap_run_id"],
        "snapshot_id": identity["snapshot_id"],
        "snapshot_version": identity["snapshot_version"],
    }
    row.update(overrides)
    return row


def test_appmap_assignment_identity_requires_candidate_or_context_packet(tmp_path: Path) -> None:
    tag_only = _appmap_identity_metadata(
        tmp_path,
        appmap_candidate_id="",
        appmap_context_packet="",
    )
    tag_only["brainstorm_tags"] = "appmap"

    assert appmap_assignment_identity(tag_only) is None

    with_packet = appmap_assignment_identity(
        _appmap_identity_metadata(tmp_path, appmap_candidate_id="")
    )
    assert with_packet is not None
    assert with_packet["candidate_id"] == ""
    assert with_packet["appmap_context_packet"].endswith("H001-C0001-agent-a.json")


def test_appmap_assignment_coverage_uses_latest_terminal_semantics(tmp_path: Path) -> None:
    identity = appmap_assignment_identity(_appmap_identity_metadata(tmp_path))
    assert identity is not None

    queued = _matching_coverage_event(identity, "agent_queued")
    spawned = _matching_coverage_event(identity, "agent_spawned")
    covered = _matching_coverage_event(identity, "agent_completed_no_finding")
    promoted = _matching_coverage_event(identity, "review_promoted")
    raw_only = _matching_coverage_event(identity, "agent_completed_with_raw_findings")
    timeout = _matching_coverage_event(identity, "agent_timeout")

    assert not is_appmap_assignment_covered(identity, [queued, spawned])
    assert is_appmap_assignment_covered(identity, [queued, covered])
    assert is_appmap_assignment_covered(identity, [raw_only, promoted])
    assert not is_appmap_assignment_covered(identity, [raw_only])
    assert not is_appmap_assignment_covered(identity, [covered, raw_only])
    assert not is_appmap_assignment_covered(identity, [covered, timeout])
    assert is_appmap_assignment_covered(identity, [timeout, covered])


def test_appmap_assignment_matching_is_strict_for_run_snapshot_and_context(tmp_path: Path) -> None:
    identity = appmap_assignment_identity(_appmap_identity_metadata(tmp_path))
    assert identity is not None

    assert coverage_event_matches_assignment(
        _matching_coverage_event(identity, "agent_completed_no_finding"),
        identity,
    )
    assert not coverage_event_matches_assignment(
        _matching_coverage_event(identity, "agent_completed_no_finding", appmap_run_id=""),
        identity,
    )
    assert not coverage_event_matches_assignment(
        _matching_coverage_event(identity, "agent_completed_no_finding", appmap_run_id="run-b"),
        identity,
    )
    assert not coverage_event_matches_assignment(
        _matching_coverage_event(identity, "agent_completed_no_finding", snapshot_id="snap-b"),
        identity,
    )

    packet_only = appmap_assignment_identity(
        _appmap_identity_metadata(tmp_path, appmap_candidate_id="")
    )
    assert packet_only is not None
    assert not coverage_event_matches_assignment(
        _matching_coverage_event(
            packet_only,
            "agent_completed_no_finding",
            appmap_context_packet=str(tmp_path / "other.json"),
        ),
        packet_only,
    )


def test_read_coverage_jsonl_tolerates_missing_invalid_and_non_object_rows(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"
    assert read_coverage_jsonl(coverage_path) == []

    coverage_path.parent.mkdir(parents=True)
    coverage_path.write_text(
        "\n".join(
            [
                '{"event":"agent_queued","hypothesis_id":"H001","agent_key":"agent-a"}',
                "not json",
                '["not", "object"]',
                '{"event":"agent_spawned","hypothesis_id":"H001","agent_key":"agent-a"}',
            ]
        ),
        encoding="utf-8",
    )

    assert [row["event"] for row in read_coverage_jsonl(coverage_path)] == [
        "agent_queued",
        "agent_spawned",
    ]
