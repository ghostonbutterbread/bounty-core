# Prerequisite-aware Blocker Store

- **Task:** `t_46c5491e`
- **Branch:** `feat/blocker-store`
- **Base / target:** `beta` at `0a73cd7` → `beta`
- **Intent:** retain factual test prerequisites that block a valid coverage conclusion without conflating them with Errors, Attempts, MapStore facts, or private hypotheses.

## Contract

`BlockerStore` writes redacted append-only lifecycle events to:

```text
{Shared}/{family}/{program}/{lane}/blockers/events.jsonl
```

An open event names an exact subject and test scope, a stable `blocker_key`, type, evidence-backed reason, selected non-secret account references where applicable, and a concrete unblock condition. The coverage gate derives only the latest event per key: an open blocker returns `blocked`; a later resolved/superseded event unblocks it without deleting history.

## Evidence

- `PYTHONPATH=/home/ryushe/worktrees/bounty-core-blocker-store python3 -m pytest -q` → 118 passed (includes full-history lifecycle and URL-userinfo redaction regressions).

## Activation boundary

BBH’s adapter and access-control guidance must consume this exact Bounty Core API. Do not merge BBH before the Core feature commit is available on its selected beta lane.

## Next action

Run independent review; resolve findings; commit Core first, then test BBH against that committed Core source.