# Evidence-only packets integration dossier

- **Status:** feature accepted for beta integration; runtime activation remains separate
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/evidence-only-packets`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-evidence-only`
- **Base commit:** `54ac5e8261edd313c815adde17d4fbb64fb4727d` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13 (local)
- **Latest immutable recovery checkpoint:** `0a966b7698240e0f2774ed43f2f911b435c6205a` on `feat/evidence-only-packets`; repair commit is this dossier's successor
- **Feature implementation commit(s):** `0a966b7698240e0f2774ed43f2f911b435c6205a`; review repair follows on this branch
- **Inspiration:** BBH FID-ledger -> populated EVIDENCE.md -> separate Bunny-authored final FID report. Provider owns storage and navigation, not report authoring.

## Intent and implemented contract

Opt-in `packet_mode="evidence_only"` on `add_finding`, `patch_finding_by_fid`, `update_finding`, `refresh_report_indexes`, and `refresh_report_navigation_from_ledger`. Create-only EVIDENCE.md and packet directories; no REPORT.md/SUBMISSION.md generation or deletion. Existing `report_path` and authored reports stay intact. New entries have `evidence_path`, `report_dir`, and FID, but not a synthetic `report_path`. Navigation uses path-qualified per-FID EVIDENCE links until an existing final report is recorded, then links to the final path. `record_final_finding_report` accepts only an existing `*-<FID>.md` inside its packet, stores `report_path`, refreshes navigation, and does not write report contents. Default legacy mode and APIs remain unchanged. No BBH or Bunny fork modifications.

Review repair: reject symlinked packet/EVIDENCE paths before packet writes and reject external/symlinked final report registration. New `report_path` and `evidence_path` pointers must address their owning FID packet, including default-mode FID patches with no report refresh. Navigation and legacy migration ignore cross-FID packet pointers; replacement cleanup is limited to the owning packet or FID-prefixed legacy lifecycle path, preserving other FIDs and legitimate legacy migration artifacts.

## Evidence and review

- Focused: `python -m pytest tests/test_evidence_only_packets.py tests/test_reports.py tests/test_phase_b.py -q` — 45 passed after repair.
- Full: `python -m pytest -q` — 165 passed after repair; `git diff --check` clean.
- Coverage: source and normalized add, edit/submission, final registration, link targets, repeated refresh, legacy preservation, missing target fallback, invalid mode/path; two new negative regressions prove external packet symlink cannot write EVIDENCE or register a final report (including a report-file symlink), and D01 cannot point at D02's report/evidence or delete D02's generated REPORT.md on legacy update. Poisoned ledger navigation falls back to D01 evidence.
- Independent review: initial reviewer found both defects in `0a966b7`; fresh read-only rereview of repaired `7810622b6b624522bbd03221f0b5bc18d1badb00` returned ACCEPT, independently replayed both attacks and ran full suite (165 passed).
- Merge/ancestry: fetched `origin/beta` at base SHA before branching and again before commit; no movement observed. Beta merge/publish is a separate tracked integration step.

## Blockers and deferred work

- Consumer BBH pin, installed provenance, integration, and runtime activation are parent-owned, not claimed here. Trigger after provider acceptance/integration; exercise BBH installed dependency against the pinned immutable provider SHA.
- Independent provider review and target integration are parent-owned. Review this branch's diff and dossier, rerun tests, then reconcile with current beta before integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/evidence-only-packets`
- **Latest immutable recovery checkpoint:** `0a966b7698240e0f2774ed43f2f911b435c6205a`; repair commit is successor to be reported in handoff (this dossier cannot contain its own SHA)
- **Feature implementation commit(s):** `0a966b7698240e0f2774ed43f2f911b435c6205a` plus repair commit in handoff
- **Exact resume point:** parent independent rereview of repaired feature tip, then beta integration only if accepted.
- **Working-tree state at handoff:** intended clean after commit.

## Decision gates

- **Integration gate:** independent review, current beta comparison, tests on accepted diff.
- **Activation / cohort gate:** consumer pinned installation and real BBH path tests; separately authorized.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-12 — feature branch created at fetched beta, additive evidence-only API implemented and tested locally; integration deferred to parent.
- 2026-10-13 — independent reviewer reproduced external symlink write and cross-FID pointer/navigation/deletion. Fixed on owning feature branch only; no descendants or identifier rename. Full provider suite 165 passed; integration deferred to parent.
