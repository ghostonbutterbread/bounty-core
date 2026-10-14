# Flat standalone PoC packet integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/flat-poc-packets-t21d4b6ff`
- **Base commit:** `fd66f7ab9069a92c2aae624c85c00d15b6b34c90`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-14
- **Owning feature branch/ref:** `feat/flat-poc-packets-t21d4b6ff`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryu's packet-layout clarification in Discord thread 1559687914517045351; BBH's `security-reporting` handoff and standalone Bunny authoring rule.

## Intent

Keep standalone `poc.<ext>` next to the final report and `EVIDENCE.md` in the FID packet, not in an automatically created `poc/` folder. Make `EVIDENCE.md` the claim and reference index, with an optional `evidence/` attachments folder only on demand. Preserve populated historical folders and all authored content.

## Implemented contract

The provider packet scaffold now creates `EVIDENCE.md` and `_meta/` but not empty `poc/` or `evidence/`. Its PoC/artifact hint points to a root-level `poc.<ext>` and optional `evidence/` attachments. Legacy and evidence-only packet creation both omit those two empty folders, without moving or deleting historical contents or changing FID/report paths. BBH/Bunny already author standalone PoCs beside the final report.

## Evidence and review

- Tests and commands: `python3 -m pytest tests/test_packet_migration.py::test_new_evidence_packet_keeps_poc_at_packet_root_without_empty_attachment_folders -q --tb=short` failed red on precreated `poc/`, then passed green; `python3 -m pytest -q --tb=short` passed **186**; `git diff --check` clean.
- Independent review: pending.
- Replay/cohort/fixture evidence: disposable pytest roots; no live target or production Shared write.
- Merge/ancestry evidence: feature based on fetched `origin/beta` `fd66f7ab9069a92c2aae624c85c00d15b6b34c90`.

## Blockers and deferred work

- **Missing test or evidence:** independent no-edit acceptance and integration-lane rerun.
- **Command / fixture / environment needed:** full provider `python3 -m pytest -q --tb=short` in clean feature and beta integration worktrees.
- **Trigger to run it:** committed feature review and clean fetched beta.
- **Why it blocks integration, activation, or promotion:** normal provider change review gate; runtime activation remains separate.
- **Next completion step / successor reference:** accept, merge to beta and read back; if provider pin is updated in BBH, reinstall consumer and verify provenance. Existing BBH PoC destination already agrees, so no consumer source edit is required.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/flat-poc-packets-t21d4b6ff`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit, obtain independent review, then integrate into clean beta.
- **Working-tree state at handoff:** intentionally uncommitted pending review-ready checkpoint.

## Decision gates

- **Integration gate:** independent review + green beta suite.
- **Activation / cohort gate:** provider consumer pin/installed runtime separately; no automatic activation.
- **Promotion gate:** explicit stable promotion only.

## Decision record

- 2026-10-14 — feature implemented with red-green regression; pending review.
