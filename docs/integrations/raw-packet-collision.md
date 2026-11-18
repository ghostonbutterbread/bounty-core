# Raw packet collision integration dossier

- **Status:** Core atomic import candidate implemented; local suite passes. BLOCKED from integration/publication pending independent review and BBH implementation, immutable pin/install, and combined release verification.
- **Owner:** delegated Core implementer; parent owns review and integration.
- **Branch / worktree:** `fix/core-raw-collision-minimal` / `/home/ryushe/worktrees/core-raw-collision-minimal`.
- **Base / intended target:** fetched `origin/beta` `6142defb3de7cef44887c1685e4f670072585785` / `beta`.
- **Prior checkpoints:** `e35033c6ce59aaec171a922edfa180c19924f82c`, `d510bca6d3aa0c1cf925ad2fb331fe14068712c7`, and regression checkpoint `51c181f598a2a8046c67a6a74b117336ed10f296`.
- **Implementation/test checkpoints:** original `33b68293b9c31af6ac7082378bd96ee9cc2c3354`; review corrections `e394424b7208198bd40815c4c7779af5617a70b6`. Branch tip includes the subsequent dossier-only handoff.
- **Atomic-import implementation checkpoint:** `f5185210ebbf5f16181b0f2e5e304786fa436456`; the branch tip also contains a later dossier-only handoff commit. Parent should review the full `origin/beta..fix/core-raw-collision-minimal` range and then coordinate the BBH adoption described below.
- **Prior test-only recovery checkpoint:** `f45c96adaa5d94c0eb096e909640bcaff684a761`; the old split-call probe remains recoverable in history and is superseded by the candidate described below.
- **Inspiration:** previous broader candidate on `fix/promo-fid-reserved-namespace`; not merged or modified here.

## Current atomic-import candidate and handoff

`VersionedFindingsLedger.import_finding(candidate, packet_mode="evidence_only")`
returns `(is_duplicate, fid, finding)`. Under one exclusive lock it uses the
existing `check()` duplicate rules, preflights the complete refresh set and new
row, reserves the identity, creates the packet and refreshes indexes. Existing
complete duplicates are unchanged. A new row is persisted with
`_atomic_import_pending` before packet/index I/O; an exception propagates and a
same-identity/same-mode call resumes that persisted row, returning nonduplicate
on completion. Other modes are rejected while pending. It does not alter the
existing `check`, `update`, `ledger_add`, or `reserve_batch` contracts.

BBH's intended change is to replace the check and `update_team_finding` pair
with this **single** operation, preserving the current ValueError/duplicate
branches. `tests/test_bbh_reservation_raw_boundary.py` archives BBH
`4ba241ce9859e7ee4964566e54976aeb032336fd` and modifies only its temporary
`sync_reports.py` import call and removes the following update call; it invokes
the adapted real entrypoint on synthetic roots with this Core source first on
PYTHONPATH. It proves collision/retry, normal duplicate, and injected partial
materialization recovery. This is not the unmodified BBH release, an installed
Core pin, or a production test. The removed conditional xfail probes remain in
git history at `f45c96adaa5d94c0eb096e909640bcaff684a761`; they diagnosed the
old split-call path, which remains unsafe until BBH adopts the new API.

Focused provider tests cover both packet modes, raw collision/retry, FID
conflicts, interrupted refresh and final ledger-write failure, mode mismatch,
and a pair of spawned-process lock interleavings (competitor wins before lock;
competitor observes contention through materialization and wins afterward).
Full suite: **294 passed**, no skips/xfails, on the isolated source worktree,
disposable HOME/XDG/TMPDIR, socket-connect fence, and BBH git archive. Command:
`BBH_TEST_REPO=/home/ryushe/worktrees/bbh-beta-fetcher-family-integration PYTHONPATH=$PWD:/home/ryushe/.hermes/cache/scratch/core-raw-fix.XGnLbNk2/site PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider --basetemp=<disposable> tests`.

Boundaries: the lock coordinates only cooperating ledger writers; generated
files and ledger are not a single transactional commit and no fsync or sudden
power-loss guarantee is provided. Failures may leave partial output alongside a
pending row. Other APIs/old BBH can mistake the pending row for a duplicate;
pre-existing unmarked partial reservations cannot be auto-recovered. A newly
introduced raw row after an interrupted operation prevents retry until manually
resolved. The operation has no migration and does not guarantee ownership
against noncooperating filesystem edits. Independent complete-diff review is
required, followed by BBH implementation, pinning and installing a reviewed
immutable Core revision, and real installed-consumer tests before release.
Parent owns those steps, integration and Kanban. No push or activation here.

## Historical check-preflight feasibility checkpoint

Everything below this heading records the earlier state and its then-current
blockers and proposed tests; the current status and receipt are above.

The subsequent Core-only investigation did **not** implement a production fix for the BBH split transaction. `VersionedFindingsLedger.check` commits and releases its exclusive ledger lock before returning; the existing BBH `sync_reports_main` then calls `update_team_finding` separately. A full refresh-set plus proposed-row preflight under that first lock prevents an already-present collision, but it cannot exclude a cooperating writer that commits a legacy raw row after `check` returns and before the later refresh acquires its lock. That interleaving still leaves D01 reserved and causes a retry to falsely skip it. The lock cannot remain held across the two existing API calls without changing their ownership/lifetime contract. Silently materializing packets inside every `check` or globally rejecting valid ledger-only checks would change existing callers' behavior. No such broad behavioral change was made. An atomic check-and-materialize operation needs explicit caller adoption, or a separately designed durable incomplete-reservation/recovery contract; neither has been reviewed or implemented here. This is a blocker, not a complete race fix.

`tests/test_bbh_reservation_raw_boundary.py` adds an opt-in, offline, synthetic cross-repository probe. It calls the **real** BBH entrypoint from an explicitly supplied immutable archive and uses the Core worktree under test first on `PYTHONPATH`; it does not modify the BBH worktree. With preflight simulated only in the test, a spawned cooperating writer committing before reservation is correctly detected and the synthetic retry succeeds; a spawned writer committing after the validated check lock is released reproduces the false skip in both legacy and evidence-only preflight modes. The latter checks the full proposed refresh set while verifying the real lock is held. The actual unmodified path also reproduces legacy-collision/false-skip, while normal import and true duplicate pass. Conditional xfails occur only after asserting the precise known failure, including the false-skip output; unexpected errors fail the suite.

BBH archives `38024c057f64a394fe7adc83071b7d17b6da3bc0` and `0ad82e9bd270bc2ddaf294eea2a298dc6db8e6ce` each yielded **3 passed, 3 xfailed** in the focused probe. These archives declare Core pins `54ac5e8261edd313c815adde17d4fbb64fb4727d` and `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, respectively; the probe deliberately overrides both pins with this candidate Core worktree, so it is **not** evidence of behavior from either pinned installation. A future combined release must pin an immutable reviewed Core commit, reinstall using the consumer's supported provisioning path, and re-run the actual importer and interruption/recovery tests. The newer BBH uses evidence-only packet mode; the older snapshot uses legacy reports.

The final full Core suite with the newer archived BBH and this Core worktree first on `PYTHONPATH` yielded **286 passed, 3 xfailed**; all xfails are the unresolved BBH defect above, not passing fixes. Tests used disposable HOME/XDG/TMPDIR and explicit roots, disabled pytest plugin autoload, and fenced socket connections. Run the focused probe with `BBH_TEST_ROOT=<isolated immutable BBH archive> PYTHONPATH=<Core worktree>:<network-fence> /usr/bin/python3 -m pytest -q -rx -p no:cacheprovider tests/test_bbh_reservation_raw_boundary.py`; the fixture skips when BBH_TEST_ROOT is unset. Remove the conditional xfails only after a fix passes the same real-entrypoint checks, including both concurrent orderings and retry; add interruption recovery and review the complete combined candidate before integration. No BBH files, pins, deployed runtime, or external data were changed.

## Contract and implementation

`reports/raw` is input, never a finding packet. Validate packet targets and historic `report_dir`, `report_path`, and `evidence_path` pointers into raw before packet/index/event/ledger data effects. Refresh validates its full materialization set before creating the first packet. Both add paths now hold the existing exclusive ledger lock from the pre-effect checks through reservation and packet materialization; source-style shares its ledger mutation logic rather than committing under a separate earlier lock. Evidence-only reservation remains committed before packet creation, preserving the tested retry behavior. Patch/update paths preflight before refreshing other records as well. Normal input under raw, a separately reserved `raw-bug` packet, and ledger-only `raw` remain supported. Ambiguous data is neither rewritten nor migrated.

Acquiring the existing advisory lock may create or touch `ledger.lock` and create its parent directory on rejection. Regressions ignore only an empty regular lock file and its real parent directory; they still compare all other files, file contents, directories and symlinks. The lock is never unlinked. These guarantees cover cooperating ledger writers and the raw collision; they do not provide rollback for arbitrary I/O failures or protect against noncooperating filesystem writers.

Historical pointers are checked using both normalized lexical and filesystem-resolved paths, including missing `alias/..` and symlink aliases. Pointers starting in reports that resolve outside it are rejected, while unrelated historical absolute external report pointers retain their existing non-deletion compatibility. Both direct packet writers validate historical pointers before modifying the finding or filesystem; the evidence-only writer validates before it reserves `report_dir`.

## Evidence

- The prior branch had **244 passed, 9 failed**: six raw/historical add regressions, two multirow refresh regressions, and a pre-flock concurrent ledger claim. The original six fixture cases remain and now pass.
- Original full unfiltered suite: **270 passed in 26.68s**. Correction checkpoint full suite: **283 passed in 21.93s**, no deselections, `/usr/bin/python3 -m pytest -q -p no:cacheprovider --basetemp=/home/ryushe/.hermes/cache/scratch/core-review-repro/full`, disposable HOME/XDG/TMPDIR, plugin autoload disabled, Core worktree first on PYTHONPATH, and `sitecustomize` IPv4/IPv6 connect fence. Printed `bounty_core.__file__` confirmed this worktree; an attempted IPv4 connection raised `network fenced`. Earlier scratch receipt: `/home/ryushe/.hermes/cache/scratch/core-raw-fix-latest` points to the ephemeral directory containing `final.log`.
- Review regressions produced 7 expected red cases before the pointer/direct-writer fix and 2 expected red traversal cases before the escape fix; all pass in the 283-test run. Coverage includes all pointer fields with lexical `alias/..`, raw symlinks, escape symlinks and traversal, both direct writers, and a non-raw external historical pointer compatibility case.
- Regression matrix covers normalized/source input and legacy/evidence modes, raw and historical pointers, multirow refresh, regular add/get with raw intake, patch/update, ledger-only raw, and descriptive packets. Spawned-process tests force a competing raw ledger claim immediately before flock and separately prove the exclusive lock remains held after candidate preflight through the reservation boundary, across both input styles and packet modes. Packet interruption/retry regressions are included in the full suite. `git diff --check` passed.

## Handoff and remaining gates

- **Actual BBH blocker reproduced:** with unmodified BBH `38024c057f64a394fe7adc83071b7d17b6da3bc0`, current Core, disposable explicit roots, raw source, and historical `raw` ledger row, the real `sync_reports_main` failed on the first import after persisting `D01`; retry returned 0 with `D01 already exists, skipped`. Raw source remained intact. The isolated probe is `/home/ryushe/.hermes/cache/scratch/core-review-repro/bbh_probe.py` (its disposable fixture already exists). BBH `sync_reports.py` calls `VersionedFindingsLedger.check`, which independently reserves and commits before `update_team_finding(..., write_report=True, refresh=True)`; a preflight called separately cannot close that race. This remains unfixed; no BBH files were edited.
- **Combined contract / implementation plan for BBH owner:** replace the check/reserve-then-update sequence for import with a single provider operation which, under the same Core ledger lock, checks duplicate identity, validates the entire refresh set and proposed row, then reserves and materializes. Core `add_finding(candidate, program=..., family=..., lane=..., root_override=..., write_report=True, refresh=True, packet_mode='legacy')` already performs the raw-collision preflight and source-style ledger reservation under one lock and returns `is_new` and `finding`; BBH must map snapshot/version/run/agent onto the candidate and verify that its source-style dedupe and returned fields meet importer semantics. It is **not** a drop-in unchanged-duplicate check: existing rows can be merged and receive a sighting. If unchanged duplicate semantics are required, add a single Core atomic check-and-materialize operation with explicit duplicate behavior rather than chaining `check()` and preflight. Do not call the existing non-locking `preflight_finding_packets` as a standalone guarantee. `add_finding` protects this collision, not general I/O-failure atomicity: durable reservations may precede materialization, so BBH must explicitly resume incomplete reservations rather than blindly skip them after interruption; distinguish complete duplicates from incomplete imports using a durable completion/recovery contract, without deleting someone else's reservation.
- **Required consumer tests:** actual `sync_reports_main` with raw intake and historical raw row must reject without D01 or packet/index/event effects (other than Core lock inode); after resolving fixture collision retry imports once; no-collision import and true duplicate preserve expected fields, snapshot/sighting and reporting behavior; inject interruption after reservation and verify retry completes rather than skips; concurrent cooperating raw ledger insertion at the lock boundary must either precede validation and reject or follow complete import, never create a hidden partial import. Test on the intended BBH integration revision with reviewed immutable Core installed in an isolated environment, not merely a Core mock. Previously observed partial D01 rows require explicit operator reconciliation; no automatic migration or deletion is authorized.
- **Review:** rerun independent review of the complete feature and corrections, then the consumer's combined revision and the tests above before integration. Existing Core suite is not evidence that BBH was fixed. Parent removes this dossier from beta during any accepted integration. Stable propagation and runtime activation require separate authorization. No beta merge, push, production data mutation, or runtime activation was performed. Parent owns Kanban reconciliation; child task contexts cannot mutate it.

The unrelated cross-FID descriptive-name ownership concern from the broader candidate is outside this minimal raw-only task and remains unresolved; no general namespace protection or migration is claimed.
