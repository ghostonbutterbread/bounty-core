# Run-scoped blocker briefs

- **Objective:** generalize blockers beyond BOLA as an optional external-prerequisite handoff.
- **Branch:** `feat/blocker-run-brief`
- **Base / target:** `beta` at `ee266ad` → `beta`

## Contract

Every blocker event has a `run_id`. The Core brief reads the latest lifecycle of
all keys and returns only still-open blockers attributed to one completed run.
This does not gate coverage, schedule work, or retry anything.

## Evidence

- `PYTHONPATH=/home/ryushe/worktrees/bounty-core-blocker-run-brief python3 -m pytest -q` → 118 passed.

## Activation boundary

BBH must consume this Core API before it is enabled in agent instructions.