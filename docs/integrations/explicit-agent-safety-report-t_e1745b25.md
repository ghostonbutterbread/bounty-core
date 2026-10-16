# Explicit agent safety report route — integration dossier

- **Status:** feature; awaiting independent workflow review
- **Owner:** Kanban t_e1745b25
- **Branch / owning ref:** `feat/explicit-agent-safety-report-t_e1745b25`
- **Base commit:** `763afe0bc9a5d792f7aaf3c06881e943d3566046` (status-event parent; itself based on `ce8718b6bfb39fb08533f506bd2bfe627b52e5da` from beta)
- **Intended integration target:** `beta`, after t_701a1867 review and root integration
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `030923f21c71fff622bc9e20c807ec25827e6920`
- **Feature implementation commit(s):** `030923f21c71fff622bc9e20c807ec25827e6920`
- **Inspiration / canonical reference:** existing `SafetyIncidentStore.record` and `bounty_core.safety_cli record` on beta

## Intent and contract

Add an explicitly named `python -m bounty_core.safety_cli ... report` route for agent self-reporting; retain `record` as a backwards-compatible alias. Both commands validate required fields and category/outcome using the existing store/parser, fsync the redacted append-only incident before optional notification, and return JSON with a top-level `incident_id` plus the stored incident and notification disposition. Invalid fields do not write or notify. Neither importing the package nor constructing the store infers an incident; only the explicit command calls `record`. No webhook configuration, automatic interception, or runtime activation is included.

## Evidence and review

- `PYTHONPATH="$PWD" pytest -q tests/test_safety_incidents.py`: 20 passed.
- `PYTHONPATH="$PWD" pytest -q`: 206 passed.
- `git diff --check`: clean.
- Offline `python -m bounty_core.safety_cli ... report ... --no-notify` returned an ID, and the exact ID was read back in lane-local `events.jsonl`; no network send was requested.
- Independent review: pending t_701a1867, which also reviews sibling notification work.
- Merge/ancestry: branch starts at status-event parent commit named above; integrate with sibling notification branch deliberately, checking overlapping `bounty_core/safety_incidents.py` and `README.md`.

## Blockers and deferred work

- **Missing evidence:** independent review of combined store/route/notification tree and integration tests.
- **Command / fixture:** reviewer t_701a1867 runs offline tests in isolated combined tree; root performs beta merge preflight.
- **Trigger:** both feature branches committed and ready for review.
- **Why it blocks integration:** overlapping source edits and end-to-end redaction/receipt guarantees require joint evaluation.
- **Next completion step:** root t_3db7709f integrates reviewed combined tree into beta; do not merge/push or activate from this child.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/explicit-agent-safety-report-t_e1745b25`
- **Latest immutable recovery checkpoint:** `030923f21c71fff622bc9e20c807ec25827e6920`; this handoff update is a later dossier-only commit.
- **Feature implementation commit(s):** `030923f21c71fff622bc9e20c807ec25827e6920`.
- **Exact resume point:** verify branch tip against tests, review sibling overlap, hand off to t_701a1867 and root.
- **Working-tree state at handoff:** clean after committing this dossier update.

## Decision gates

- **Integration gate:** independent review of combined feature plus offline suites; beta merge owned by root.
- **Activation / cohort gate:** no beta or live runtime activation in this task.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-15 — Reuse the existing append-only store; make reporting explicit and discoverable without adding a second persistence path or inferred incidents.
