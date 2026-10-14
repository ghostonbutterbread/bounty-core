# Descriptive finding packets integration dossier

- **Status:** accepted feature (independent no-edit review of `180ebd0`; beta integration pending)
- **Owner:** Bounty Core provider implementation
- **Branch / owning ref:** `feat/report-packet-fid-slug-tf9946642`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-report-packets-tf9946642`
- **Base commit:** `9968eeb58ca902549097d8941875b0e01cfe0af2` (`origin/beta` fetched before work)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Latest immutable recovery checkpoint:** `c374c4511472401e2362569e6c800f8c5f94da5e`
- **Feature implementation commit(s):** `a879453c0ea084e944455d9453592cf7048b1103`, `e66506a960cd1acc6cf44b53ecc4752ef4320ca6`, `5a557eef277d6b87fcb4a3043db41abfec15ba7f`, `c374c4511472401e2362569e6c800f8c5f94da5e`
- **Inspiration:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; BBH consumer requested `D01-owned-xss` and `D01-sqlite-injection-via-exposed-ipc-port`.

## Intent and contract

New `packet_mode="evidence_only"` findings allocate `reports/<exact-FID>-<initial-title-slug>/`, store an absolute `report_dir` in the per-program/per-lane ledger, and retain it through subsequent title/status/severity edits. Existing `reports/<FID>/` folders and legacy mode (`REPORT.md`, legacy navigation) remain usable without automatic move. Exact-FID packet/path checks reject another FID, unsafe path, symlinked packet/file, and external report; `report_dir` cannot be patched as a routine update. Explicit duplicate FIDs are rejected on new ledger allocation. Bunny's `*-<FID>.md` final report must exist in the stored packet and is registered without writing it.

Evidence-only navigation creates class and severity indexes only when populated, and `reports/submitted/index.md` only when `submission.state == "submitted"`. Changing state removes the generated view, not the packet. Navigation targets registered final Markdown, otherwise EVIDENCE.md. `ensure_layout` no longer seeds empty status-by-class, daily, or index roots. Evidence-only refresh does not generate those legacy views, and does not remove populated/hand-authored historical files. Default legacy refresh still emits its legacy daily/matrix navigation for compatibility; this is intentionally distinct from the evidence-only route.

## Evidence and review

- RED: `python -m pytest tests/test_packet_migration.py -q` initially 3 failed / 2 passed (missing descriptive packet, eager daily tree, report_dir mutation). Unsafe-FID ledger persistence regression independently failed before its fix.
- GREEN: initial `python -m pytest -q --tb=short` — 174 passed. Independent review blocked beta on three defects: no-sightings legacy normalization dropped `report_dir`; normalized intake allowed duplicate explicit FID; a fresh source-style FID could adopt an existing descriptive packet after ledger allocation.
- Targeted correction: added three red tests in `tests/test_packet_migration.py`, then preserved legacy `report_dir`, rejected duplicate normalized FIDs, and allocated source-style evidence-only packets under the FID lock before persisting the new row. Preexisting descriptive packets now raise without adopting content or leaving a ledger row. Corrected tests `12 passed`; full `python3 -m pytest -q --tb=short` — **177 passed**; BBH source-contract smoke (six focused files) — **130 passed, 13 subtests passed**. One initial full-suite invocation timed out at 180 seconds; rerun at 600 seconds completed in 15.90 seconds. `git diff --check` and independent re-review pending.
- Independent re-review of `e66506a` found a new failure path: source-style packet materialization preceded ledger commit, so a transient ledger write error stranded a `D01-owned-xss` packet and a retry collided. The normalized intake had the same ordering hazard. Added RED injected-ledger-write regressions for both entry routes and retry after the packet-phase write; split evidence-only into reservation/ledger commit followed by packet materialization under the ledger lock. First-write failures now leave no packet, while second-write failures retain the frozen pointer for safe retry. Targeted migration tests **15 passed**, full provider **180 passed**, BBH source-contract smoke **131 passed, 13 subtests passed**. `git diff --check` clean; independent re-review pending.
- Independent re-review of `5a557ee` blocked beta on two remaining paths: bulk ledger backfill created packets before writing their pointers and without ledger lock; interrupted create-only scaffold writes left zero-byte `EVIDENCE.md` that retries would not repair. Added RED bulk-refresh injected ledger failure/retry regression, then routed bulk refresh through locked reservation/commit before materialization. Scaffold creation now writes to a private temporary file and publishes only complete contents with create-only hardlink; interrupted publication leaves no empty `EVIDENCE.md`, and source/normalized retries succeed without overwriting authored evidence. Two injected publication failure tests pass. Targeted migration **18 passed**, complete provider **183 passed**, BBH eight focused files **240 passed, 13 subtests passed**. An *already existing* zero-byte historical file cannot be safely classified as generated versus authored and remains untouched for explicit operator reconciliation.
- Independent re-review of `c374c45` found an interleaved legacy `D02` insert between the two bulk-refresh locks could still strand a `D02-new-arrival` packet on second-write failure. The refresh now reserves and atomically commits pointers **inside its existing exclusive lock** before materializing any packet, rather than releasing/reacquiring around a changing row set. Added a deterministic interleaving regression that inserts `D02` at the former unlock boundary, injects an error if a packet would be stranded, and verifies a later refresh handles `D02` safely. Provider **184 passed**, BBH source-contract **240 passed, 13 subtests passed**; independent final review pending.
- Evidence-only mode creates no daily/matrix navigation. Legacy default mode retains daily/index generation deliberately for existing source-team consumers; this is a compatibility boundary, not the new default web route. Removing legacy generation requires a distinct approved migration of those consumers.
- Source-style and normalized intake, legacy default reporting, old FID-only packets, historical authored content, final registration, submission reversal, class/severity links, title freeze, symlink/cross-FID negatives covered with isolated `tmp_path` roots. No production Shared writes.
- Merge/ancestry: feature based on fetched `origin/beta` above; integration/pin not performed.

## Blockers and deferred work

- **Missing evidence:** BBH consumer tests against an installed immutable provider beta revision; provider independent no-edit acceptance passed `180ebd0` with **184 full / 54 focused tests** and clean diff.
- **Command/fixture:** Bounty Core `python3 -m pytest -q --tb=short`; BBH disposable-root `pytest agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py -q` against its pinned/reinstalled Core.
- **Trigger:** publish reviewed provider beta, pin its full reachable SHA in BBH and reinstall BBH checkout-local dependencies.
- **Why:** BBH still imports the old installed Core revision until its manifest and checkout-local environment are updated.
- **Next:** merge/push reviewed provider into fetched beta, pin/install BBH, run installed E2E. Historical populated legacy folders remain read-only unless separately approved for cleanup.

## Handoff and gates

- **Exact resume point:** reconcile fetched provider beta, merge reviewed feature, retire dossier from beta, run suite, push/readback; then BBH immutable pin and installed E2E.
- **Working tree at handoff:** clean after final dossier-only commit; verify feature tip separately from the checkpoint above.
- **Integration gate:** independent review, full suite green, branch reconciliation.
- **Activation gate:** BBH immutable provider pin and installed provenance plus disposable-root tests.
- **Promotion gate:** explicit separate decision; no production Shared migration.
- **Decision:** 2026-10-13 — independent no-edit provider acceptance of implementation `180ebd0` after 184 full and 54 focused tests; beta publication pending.
