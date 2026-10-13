# Descriptive finding packets integration dossier

- **Status:** feature (independent review pending)
- **Owner:** Bounty Core provider implementation
- **Branch / owning ref:** `feat/report-packet-fid-slug-tf9946642`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-report-packets-tf9946642`
- **Base commit:** `9968eeb58ca902549097d8941875b0e01cfe0af2` (`origin/beta` fetched before work)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Latest immutable recovery checkpoint:** none yet (commit pending)
- **Feature implementation commit(s):** none yet (commit pending)
- **Inspiration:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; BBH consumer requested `D01-owned-xss` and `D01-sqlite-injection-via-exposed-ipc-port`.

## Intent and contract

New `packet_mode="evidence_only"` findings allocate `reports/<exact-FID>-<initial-title-slug>/`, store an absolute `report_dir` in the per-program/per-lane ledger, and retain it through subsequent title/status/severity edits. Existing `reports/<FID>/` folders and legacy mode (`REPORT.md`, legacy navigation) remain usable without automatic move. Exact-FID packet/path checks reject another FID, unsafe path, symlinked packet/file, and external report; `report_dir` cannot be patched as a routine update. Explicit duplicate FIDs are rejected on new ledger allocation. Bunny's `*-<FID>.md` final report must exist in the stored packet and is registered without writing it.

Evidence-only navigation creates class and severity indexes only when populated, and `reports/submitted/index.md` only when `submission.state == "submitted"`. Changing state removes the generated view, not the packet. Navigation targets registered final Markdown, otherwise EVIDENCE.md. `ensure_layout` no longer seeds empty status-by-class, daily, or index roots. Evidence-only refresh does not generate those legacy views, and does not remove populated/hand-authored historical files. Default legacy refresh still emits its legacy daily/matrix navigation for compatibility; this is intentionally distinct from the evidence-only route.

## Evidence and review

- RED: `python -m pytest tests/test_packet_migration.py -q` initially 3 failed / 2 passed (missing descriptive packet, eager daily tree, report_dir mutation). Unsafe-FID ledger persistence regression independently failed before its fix.
- GREEN: `python -m pytest -q --tb=short` — 174 passed after README and provider changes; `git diff --check` clean.
- Source-style and normalized intake, legacy default reporting, old FID-only packets, historical authored content, final registration, submission reversal, class/severity links, title freeze, symlink/cross-FID negatives covered with isolated `tmp_path` roots. No production Shared writes or network actions.
- Independent review: pending parent/reviewer; do not merge/push here.
- Merge/ancestry: feature based on fetched `origin/beta` above; integration/pin not performed.

## Blockers and deferred work

- **Missing evidence:** BBH consumer tests against this committed provider revision and independent diff review.
- **Command/fixture:** BBH disposable-root `pytest agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_base_team_review.py -q`, then consumer environment reinstallation from its immutable provider pin.
- **Trigger:** provider review/integration and published full commit; no production Shared migration automatically.
- **Why:** BBH still assumes the previous FID-only folder until its consumer changes and pin are integrated.
- **Next:** parent reviews provider diff; then provider beta integration/publish, BBH pin/consumer verification. Historical populated legacy folders remain read-only unless separately approved for cleanup.

## Handoff and gates

- **Exact resume point:** review feature diff and test receipts; reconcile any advanced `origin/beta`, run tests, then integrate only if review accepts. Parent owns merge/push/pin.
- **Working tree at handoff:** intended clean after commit.
- **Integration gate:** independent review, full suite green, branch reconciliation.
- **Activation gate:** BBH immutable provider pin and installed provenance plus disposable-root tests.
- **Promotion gate:** explicit separate decision; no production Shared migration.
- **Decision:** 2026-10-13 — implemented and tested as feature branch; no merge/push.
