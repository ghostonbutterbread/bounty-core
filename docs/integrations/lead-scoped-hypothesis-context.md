# Lead-scoped hypothesis context

## Intent
Add a lead-linked, explicit follow-up retrieval path while keeping ordinary hypothesis discovery private to the current owner and run.

## Branch topology
- Feature branch: `feat/lead-scoped-hypothesis-context`
- Base: `origin/master` at `dc31a6c4e8394dd7795056a545c8bb7b5417f4ab`
- Intended successor: BBH `feat/blackbox-evidence-routing`; no runtime activation.

## Implemented contract
- Hypotheses may link to an opaque public lead ID.
- Ordinary `list_visible` remains private to current ownership.
- A lead-linked hypothesis can be deliberately released by its live owner.
- `lead_followup` returns only caller-owned, released, or stale/reclaimable unresolved context for one exact lead ID.
- Existing SQLite databases receive additive migration columns.

## Evidence
- `uv run --with pytest python -m pytest tests/test_hypothesis_ledger.py -q` — 15 passed.
- `git diff --check` passed before this checkpoint.

## Remaining work
Add refusal/migration edge-case tests, then expose the contract through BBH wrappers and Leads. BBH must consume a committed Bounty Core revision; do not assume an uncommitted local Core checkout is runtime-visible.
