# Lead-scoped hypothesis context

## Intent
Add a lead-linked, explicit follow-up retrieval path while keeping ordinary hypothesis discovery private to the current owner and run.

## Branch topology
- Feature branch: `feat/lead-scoped-hypothesis-context`
- Base: `origin/master` at `dc31a6c4e8394dd7795056a545c8bb7b5417f4ab`
- Intended integration target: Core `beta`, then BBH `feat/blackbox-evidence-routing`; no runtime activation.

## Implemented contract
- Hypotheses may link to an opaque public lead ID.
- Ordinary `list_visible` remains private to current ownership.
- A lead-linked hypothesis can be deliberately released by its live owner.
- `lead_followup` returns only caller-owned, released, or stale/reclaimable unresolved context for one exact lead ID.
- Existing SQLite databases receive additive migration columns before the dependent lead index is created, preserving legacy rows as private/unlinked.

## Evidence
- `uv run --with pytest python -m pytest tests/test_hypothesis_ledger.py::test_legacy_hypotheses_migrate_before_lead_index_creation_and_preserve_rows -q` — 1 passed after a prior expected red failure reproducing the old-schema index error.
- `PYTHONPATH=. uv run --with pytest python -m pytest -q` — 104 passed.
- `git diff --check` passed before this checkpoint.

## Review and next gate

- Independent re-review accepted `5089b104e7229cbf0f012875a4fbe3dc8d271af5`: no blockers; full suite `104 passed`; legacy migration was manually verified twice with preserved rows, indexes, and `PRAGMA integrity_check=ok`.
- Merge this reviewed feature into a clean Core `beta` lane and publish that lane before BBH consumes it.
- BBH/Leads remains responsible for validating that an exact public Lead card exists before requesting Core follow-up context. BBH must pin the published immutable Core revision and rerun its isolated suite; no runtime activation is part of this work.