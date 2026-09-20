# AI review attribution — Bounty Core integration dossier

- **Feature branch:** `feat/ai-review-attribution`
- **Base / target:** `201a47f7afff1db1b592f5d7126e7717d1feb171` (`origin/beta`) → `beta`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-ai-review-attribution`

## Intent

Give derived, durable AI interpretations a compact optional provenance tag so a
later agent can deliberately obtain another model's view without claiming that
raw evidence itself was model-authored.

## Contract

`ai_reviewed_by` is a deduplicated list of `{agent_id, model_id}` records. Both
values are required for a tag; absence preserves legacy records unchanged. The
provider exposes a small normalizer and adds optional model attribution to core
evidence, Error, Blocker, Public Artifact, and Hypothesis Ledger writes.

## Evidence

- Provider implementation: `03115ffcbb8aeb89b629e36252de6b943cb65f67`.
- Durable-persistence and legacy-migration regressions: `eb526d2ffa3b67e1e2ccb42d56a1c72ce450e7a6`.
- Full provider suite: `147 passed`; focused provider suite: `49 passed`.
- Syntax/whitespace check: `compileall`, `py_compile`, and `git diff --check` passed.
- Fresh independent review: approved the full `origin/beta...eb526d2` range after
  rerunning the suite and inspecting JSONL/SQLite readback assertions.

## Boundaries

No raw-evidence migration/backfill, no fabricated `unknown` model value, and no
change to read visibility or lifecycle semantics. BBH must pin the reviewed
provider commit and exercise its real CLI paths before its companion change can
be accepted.

## Next action

Commit this provider change, obtain independent review, merge/push it to beta,
then pin that immutable revision in the BBH feature branch and run its installed
consumer tests.
