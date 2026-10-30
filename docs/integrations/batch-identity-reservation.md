# Batch identity reservation — integration dossier

- **Status:** blocked pending independent provider review; feature checkpoint only.
- **Owner:** BBH task `t_c8c8b748`, provider-side implementation.
- **Branch:** `fix/batch-identity-reservation-tc8c8b748`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-batch-identity-tc8c8b748`
- **Base:** freshly fetched `origin/beta` `c10866524a7fb30ac811fce8ef050fd5d8c922cc`; intended target `beta`.
- **Last updated:** 2026-10-29.
- **Latest immutable recovery checkpoint / implementation commit:** `41c78bf174b18fb68e5110582a934e613e6747f2` (verify subsequent dossier-only handoff tip separately).
- **Inspiration:** BBH published beta `f8a38feedc2326175bc216cb5ce3ec8f794f5c69`, installed provider pin `6c36ee88a60073e1b687ec32deeade24ffafdd4f` (ancestor of fetched beta); task `t_c8c8b748`, synthetic collision audit PC-20261030-013848-36ae0ab7.

## Intent and contract

Add only `VersionedFindingsLedger.reserve_batch(list)` for at most 1,000 identities. Preserve single-item behavior and per-item order. Existing and earlier-batch identities take precedence over FID conflicts; the same allocator and entry builder are shared with single reservations. Evaluate under one existing exclusive ledger lock and replace the ledger once only when every candidate validates. On conflict, invalid FID, or pre-replacement failure, the original ledger bytes are unchanged. No consumer modifications.

This guarantees only reservation atomicity for cooperating writers and ordinary filesystem replacement, not fsync/crash durability or packet, finalization, index, or report-import atomicity. The existing consumer can reserve then fail during finalization and retry may skip the incomplete reservation as a duplicate. There is no durable per-report recovery/ownership contract here; report-level recovery is **not solved**. An orphan temporary file can remain after a failed replacement, as with the existing atomic writer.

## Evidence and review

- RED: test for late collision failed against the unmodified fetched beta due to missing API before implementation. Additional eight nonconcurrency batch tests run against a scratch archive of that same base all failed on missing API. The concurrency regression was not run red against the base.
- GREEN: full provider suite `pytest -q tests`: **228 passed**. The interpreter was `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python`, with `PYTHONPATH` resolving `bounty_core.ledger` to this feature worktree. Tests used synthetic temporary roots and a scratch HOME. A seccomp wrapper denied socket/connect/send calls; a socket probe returned `EPERM`. Wrapper used: `/home/ryushe/.hermes/profiles/bugfix/cache/scratch/manual-class-netdeny.py` (ephemeral; reproduce equivalent denial if unavailable). `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`.
- New tests cover late existing and intra-batch collisions with unchanged bytes, duplicate/new ordering, allocation, loose duplicate matching, one replacement, invalid FID, injected `Path.replace` failure, unchanged single `check`, bounds, and a process/event coordinated competing writer plus nonblocking flock probe. `compileall` and `git diff --check` passed.
- Independent provider review: **NOT YET DONE**. This child session has no delegation tool. An attempted read-only Claude CLI review failed: OAuth session expired and could not be refreshed; no review was produced. Parent must dispatch a separate no-edit provider reviewer against the committed tip; reviewer should rerun tests offline with source provenance and examine semantics, atomic replacement, concurrency, tests, and this dossier.
- Base verification: local `beta` and fetched `origin/beta` both equal `c10866524a7fb30ac811fce8ef050fd5d8c922cc`; installed pin ancestor check succeeded. Existing local refs and task discovery did not identify matching batch reservation work; do not retire other branches.

## Blockers, gates, and resume

- **Provider integration gate:** independent review and resolution of findings; fetch target anew and reconcile or stop if it moved. User did not authorize merge or push.
- **Consumer/recovery gate:** separately design durable per-report ownership/incomplete state and retries, then inject post-reservation, packet, and index failures through the real consumer using synthetic data. Provider success does not prove the pinned consumer uses this API. Consumer changes, provider publication and immutable pin update require separate authorization and verification.
- **Activation/stable:** not authorized; no push, merge, runtime activation, live data, or task closure.
- **Exact resume:** parent obtains an independent provider review of this branch tip and retains the resulting receipt; address any findings on this branch with tests. Record the immutable implementation SHA in successor handoff; it is the parent of any later dossier-only checkpoint.
