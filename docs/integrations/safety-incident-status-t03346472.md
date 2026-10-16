# Safety incident status events integration dossier

- Status: feature, awaiting independent root integration review
- Owner: Kanban t_03346472
- Branch: `feat/safety-incident-status-events-t03346472`
- Base commit: `ce8718b6bfb39fb08533f506bd2bfe627b52e5da` (`origin/beta` at creation)
- Intended integration target: `beta` (not main; no activation here)
- Last updated: 2026-10-15
- Owning feature branch/ref: `feat/safety-incident-status-events-t03346472`
- Latest immutable recovery checkpoint: none yet (initial implementation commit pending)
- Feature implementation commit(s): none yet
- Inspiration / canonical reference: existing `bounty_core/safety_incidents.py` report and notification streams on beta.

## Intent

Complete the append-only store contract for status changes without duplicating the already integrated original-report and notification paths. Preserve backward compatibility with version-1 report rows that have no `record_type` field. Do not add webhook credentials, send alerts, or integrate into beta in this card.

## Implemented contract

`SafetyIncidentStore.append_status(id, status=..., producer=..., note=...)` validates attribution and an existing report, redacts inputs, then fsync-appends an event with `schema_version`, `record_type=status`, unique `event_id`, `incident_id`, timestamp, producer, status and note to `events.jsonl`. `history(id)` reads the report and status records in append order; `get(id)` returns only the original report. The interface has no overwrite or delete method. Direct filesystem tampering is outside this interface's guarantee.

## Evidence and review

- Red test: two new status tests failed with `AttributeError` before implementation.
- `PYTHONPATH="$PWD" pytest -q tests/test_safety_incidents.py`: 18 passed.
- `PYTHONPATH="$PWD" pytest -q`: 204 passed.
- `git diff --check`: clean.
- Independent review: deferred to root integration/review lane.
- Merge/ancestry evidence: feature branched from fetched `origin/beta` ce8718b; no merge performed.

## Blockers and deferred work

- Missing evidence: independent exact-diff review and beta integration checks.
- Command/fixture: review feature diff against ce8718b, run focused and full offline tests in isolated worktree, then integrate via standard beta lifecycle.
- Trigger: downstream root task t_3db7709f after the other child cards finish.
- Why it blocks integration: owner requested independent review before beta integration.
- Next completion step: root task reviews, merges approved feature, removes this branch-local dossier from beta, and verifies remote readback. No live webhook action is part of this child.

## Interruption / resume handoff

- Owning feature branch/ref: `feat/safety-incident-status-events-t03346472`
- Latest immutable recovery checkpoint: pending initial commit; update after committing.
- Feature implementation commit(s): pending initial commit.
- Exact resume point: commit verified implementation and update checkpoint; then hand off to root integration.
- Working-tree state at handoff: initially dirty until committed.

## Decision gates

- Integration gate: independent review and beta compatibility by root task.
- Activation/cohort gate: separate operator-approved runtime configuration; no webhook used by this change.
- Promotion gate: no main promotion authorized.

## Decision record

- 2026-10-15: Existing beta already has persistent reports/notification receipts; this task adds only status append/read and immutability tests.
