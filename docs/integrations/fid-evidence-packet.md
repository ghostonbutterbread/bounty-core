# FID evidence packet integration dossier

- **Status:** feature
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/fid-evidence-packet`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-fid-evidence-packet`
- **Base commit:** `8cc64e68bc93919573c5e3cb2662283889d7858c` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Latest immutable recovery checkpoint:** `1122ea5` (privacy correction; feature tip)
- **Feature implementation commit(s):** `dd016020`, `1122ea5`
- **Inspiration:** FID-to-ledger evidence packet and rough draft submission handoff.

## Intent and implemented contract

When report writing is enabled, Bounty Core creates a stable `reports/{FID}/EVIDENCE.md` scaffold alongside editable `REPORT.md`. The scaffold is create-only, counts initial ledger evidence leads without copying free-form content (which may contain quoted secrets), and has the internal claim, actor, evidence, reproduction, impact, controls, PoC and gap headings needed for investigation. The investigator reviews the source and adds sanitized pointers. Existing evidence and manually edited reports are preserved. Existing ledger/navigation refresh backfills a missing scaffold. `write_report=False` with `refresh=False` creates no packet. No automatic `FINALIZED.md`, evidence completeness claim, or submission action.

Generated rough reports now expose Summary, Technical details, How to reproduce, Impact, and Remediation with ledger-provided values or explicit unknowns. Existing Source -> Sink, Blocking / Chain Requirements, Review Notes, and Evidence remain. No ledger schema or navigation behavior changes.

## Evidence and review

- `python3 -m pytest -q -p no:cacheprovider tests/test_reports.py tests/test_ledger_v2_contract.py`: 41 passed.
- `python3 -m pytest -q -p no:cacheprovider`: 158 passed.
- `git diff --check`: clean.
- Independent review: initial privacy block (quoted secret forms); free-form evidence copying removed; final re-review accepted feature tip `1122ea5` for beta integration.
- Replay/cohort fixture: local pytest tmp-path integration exercises report writes, ledger backfill, and opt-out.
- Merge/ancestry: feature based on fetched `origin/beta` at base SHA; parent owns reconciliation.

## Blockers and deferred work

- None for local implementation. Parent must independently review/retest before integration; no activation or submission claim.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/fid-evidence-packet`
- **Latest immutable recovery checkpoint:** `1122ea5` (privacy correction; feature tip)
- **Feature implementation commit(s):** `dd016020`, `1122ea5`
- **Exact resume point:** parent review and integration into `beta` (not this subagent).
- **Working-tree state at handoff:** to be committed clean.

## Decision gates

- **Integration gate:** parent review, reconcile fetched beta, rerun focused tests.
- **Activation / cohort gate:** none in this feature; deployment separate.
- **Promotion gate:** not requested.

## Decision record

- 2026-09-29 — feature implementation and local tests complete; handoff for review.
