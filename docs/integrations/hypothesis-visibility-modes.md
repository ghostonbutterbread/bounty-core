# Hypothesis visibility modes integration dossier

- **Status:** feature
- **Owner:** Core feature agent
- **Branch:** `feat/hypothesis-visibility-modes`
- **Base commit:** `fc361eca86f9c86acb357e1b9ce6426bc44aef83`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `feat/hypothesis-visibility-modes`
- **Latest immutable recovery checkpoint:** `619232e216d272f020c7d2d04f0e11c6216720b5`
- **Feature implementation commit(s):** `619232e216d272f020c7d2d04f0e11c6216720b5`
- **Inspiration / canonical references:** user visibility-modes contract

## Intent

Add explicit, cooperative Core read APIs for current exact surface+URL peer
history and operator application-wide thinking review. Ordinary private lists,
Lead follow-up, delegation/release, and stale reclaim semantics remain unchanged.
No BBH runtime, policy, target, or activation changes are included.

## Implemented contract

- `review_current_surface` requires viewer agent/run IDs, exact nonblank surface,
  normalized nonblank URL, and `current-surface-peer-history`; it returns only
  unresolved exact surface+URL results with optional AND tags/status subset.
- `operator_app_review` requires actor IDs, nonblank request ID, and
  `application-thinking-review`; it returns unresolved program-wide results and
  full matching surface counts.
- Both APIs sort `updated_at DESC, id ASC`, use opaque keyset cursors, return
  normalized query/count metadata, and append sanitized review audit events.
- SQLite adds non-destructive review indexes. Terminal records remain excluded.

## Evidence and review

- Tests and commands: RED receipt: `PYTHONPATH=. python3 -m pytest -q tests/test_hypothesis_ledger.py` → 4 failed / 18 passed because APIs were absent. GREEN focused: same command → 22 passed. Full: `PYTHONPATH=. python3 -m pytest -q` → 110 passed. `PYTHONPATH=. python3 -m compileall -q bounty_core tests` passed. `git diff --check` passed.
- Independent review: pending parent/integration review.
- Replay/cohort/fixture evidence: focused temporary SQLite fixtures validate legacy migration/indexes, exact matching, peer inclusion, terminal exclusion, pagination, audit and no record mutation.
- Merge/ancestry evidence: branch starts at declared beta base.

## Blockers and deferred work

- **Missing test or evidence:** BBH CLI/policy authorization and runtime exposure tests.
- **Command / fixture / environment needed:** successor BBH branch invoking these Core APIs through its CLI/policy boundary.
- **Trigger to run it:** after Core integration is accepted.
- **Why it blocks integration, activation, or promotion:** it does not block this Core-only feature; it blocks activation of any caller-facing review workflow.
- **Next completion step / successor reference:** planned BBH successor: wire authorized CLI commands and policy enforcement, preserving these exact Core intent markers.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/hypothesis-visibility-modes`
- **Latest immutable recovery checkpoint:** `619232e216d272f020c7d2d04f0e11c6216720b5`.
- **Feature implementation commit(s):** `619232e216d272f020c7d2d04f0e11c6216720b5`.
- **Exact resume point:** inspect implementation and dossier commits, then submit for parent review; do not merge/push from this task.
- **Working-tree state at handoff:** clean after committing this dossier.

## Decision gates

- **Integration gate:** focused/full Core tests, compile, diff check, and review pass.
- **Activation / cohort gate:** BBH successor supplies authorization/policy and CLI integration.
- **Promotion gate:** parent-owned beta review; no runtime activation is implied.

## Decision record

- 2026-09-01 — implementation checkpoint `619232e216d272f020c7d2d04f0e11c6216720b5`; added Core-only explicit visibility review APIs, pagination, indexes, and sanitized read-audit events; pending parent review.
