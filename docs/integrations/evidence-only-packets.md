# Evidence-only packets integration dossier

- **Status:** feature; provider handoff, pending independent review/integration
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/evidence-only-packets`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-evidence-only`
- **Base commit:** `54ac5e8261edd313c815adde17d4fbb64fb4727d` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12 (local)
- **Latest immutable recovery checkpoint:** none before implementation commit
- **Feature implementation commit(s):** pending
- **Inspiration:** BBH FID-ledger -> populated EVIDENCE.md -> separate Bunny-authored final FID report. Provider owns storage and navigation, not report authoring.

## Intent and implemented contract

Opt-in `packet_mode="evidence_only"` on `add_finding`, `patch_finding_by_fid`, `update_finding`, `refresh_report_indexes`, and `refresh_report_navigation_from_ledger`. Create-only EVIDENCE.md and packet directories; no REPORT.md/SUBMISSION.md generation or deletion. Existing `report_path` and authored reports stay intact. New entries have `evidence_path`, `report_dir`, and FID, but not a synthetic `report_path`. Navigation uses path-qualified per-FID EVIDENCE links until an existing final report is recorded, then links to the final path. `record_final_finding_report` accepts only an existing `*-<FID>.md` inside its packet, stores `report_path`, refreshes navigation, and does not write report contents. Default legacy mode and APIs remain unchanged. No BBH or Bunny fork modifications.

## Evidence and review

- Focused: `python -m pytest tests/test_evidence_only_packets.py tests/test_reports.py tests/test_ledger_v2_contract.py -q` — 45 passed before final registration additions; rerun before commit.
- Full: `python -m pytest -q` — 162 passed before final registration additions; rerun before commit.
- Coverage: source and normalized add, edit/submission, final registration, link targets, repeated refresh, legacy preservation, missing target fallback, invalid mode/path.
- Independent review: pending parent/reviewer.
- Merge/ancestry: fetched `origin/beta` at base SHA before branching and again before commit; no movement observed. No merge/push authorized.

## Blockers and deferred work

- Consumer BBH pin, installed provenance, integration, and runtime activation are parent-owned, not claimed here. Trigger after provider acceptance/integration; exercise BBH installed dependency against the pinned immutable provider SHA.
- Independent provider review and target integration are parent-owned. Review this branch's diff and dossier, rerun tests, then reconcile with current beta before integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/evidence-only-packets`
- **Latest immutable recovery checkpoint:** implementation commit to be reported in handoff (this dossier cannot contain its own SHA)
- **Feature implementation commit(s):** implementation commit to be reported in handoff
- **Exact resume point:** parent independent review, then beta integration only if accepted.
- **Working-tree state at handoff:** intended clean after commit.

## Decision gates

- **Integration gate:** independent review, current beta comparison, tests on accepted diff.
- **Activation / cohort gate:** consumer pinned installation and real BBH path tests; separately authorized.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-12 — feature branch created at fetched beta, additive evidence-only API implemented and tested locally; integration deferred to parent.
