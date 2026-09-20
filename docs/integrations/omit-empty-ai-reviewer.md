# Omit empty AI reviewer attribution — integration dossier

- **Feature branch:** `fix/omit-empty-ai-reviewer`
- **Base / target:** `65cfe628a69c920637e4c50cb52374869f5d623c` (`origin/beta`) → `beta`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-omit-empty-reviewer`

## Intent

Restore the optional-field contract for model-less Hypothesis Ledger records.
The SQLite storage column remains legacy-safe with `[]` as its schema default,
but API payloads and created records must omit `ai_reviewed_by` entirely when no
valid `(agent_id, model_id)` pair was supplied.

## Implemented contract

- Creation serializes the durable `[]` column value when no reviewer exists but
does not expose the optional field in its returned payload.
- SQLite readback omits empty/malformed/absent attribution from record payloads.
- Tagged records retain their structured reviewer list.

## Evidence

- Focused attribution, ledger, and durable-store suites: `49 passed`.
- Full provider suite: `147 passed`.
- `python3 -m compileall -q bounty_core tests` and `git diff --check` passed.

## Next action

Commit this defect fix, obtain independent review, then merge/publish it to
Bounty Core `beta` before updating the BBH dependency pin.
