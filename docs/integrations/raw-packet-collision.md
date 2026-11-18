# Raw packet collision integration dossier

- **Status:** implementation and isolated Core suite passed; independent review and consumer gate pending. Do not merge, push, promote, or activate on this receipt alone.
- **Owner:** delegated Core implementer; parent owns review and integration.
- **Branch / worktree:** `fix/core-raw-collision-minimal` / `/home/ryushe/worktrees/core-raw-collision-minimal`.
- **Base / intended target:** fetched `origin/beta` `6142defb3de7cef44887c1685e4f670072585785` / `beta`.
- **Prior checkpoints:** `e35033c6ce59aaec171a922edfa180c19924f82c`, `d510bca6d3aa0c1cf925ad2fb331fe14068712c7`, and regression checkpoint `51c181f598a2a8046c67a6a74b117336ed10f296`.
- **Implementation/test checkpoint:** `33b68293b9c31af6ac7082378bd96ee9cc2c3354`; the branch tip includes this later dossier-only handoff.
- **Inspiration:** previous broader candidate on `fix/promo-fid-reserved-namespace`; not merged or modified here.

## Contract and implementation

`reports/raw` is input, never a finding packet. Validate packet targets and historic `report_dir`, `report_path`, and `evidence_path` pointers into raw before packet/index/event/ledger data effects. Refresh validates its full materialization set before creating the first packet. Both add paths now hold the existing exclusive ledger lock from the pre-effect checks through reservation and packet materialization; source-style shares its ledger mutation logic rather than committing under a separate earlier lock. Evidence-only reservation remains committed before packet creation, preserving the tested retry behavior. Patch/update paths preflight before refreshing other records as well. Normal input under raw, a separately reserved `raw-bug` packet, and ledger-only `raw` remain supported. Ambiguous data is neither rewritten nor migrated.

Acquiring the existing advisory lock may create or touch `ledger.lock` and create its parent directory on rejection. Regressions ignore only an empty regular lock file and its real parent directory; they still compare all other files, file contents, directories and symlinks. The lock is never unlinked. These guarantees cover cooperating ledger writers and the raw collision; they do not provide rollback for arbitrary I/O failures or protect against noncooperating filesystem writers.

## Evidence

- The prior branch had **244 passed, 9 failed**: six raw/historical add regressions, two multirow refresh regressions, and a pre-flock concurrent ledger claim. The original six fixture cases remain and now pass.
- Final full unfiltered suite: **270 passed in 26.68s**. `/usr/bin/python3 -m pytest -q --basetemp=<disposable>/finaltmp`, fresh disposable HOME/XDG/TMPDIR, plugin autoload disabled, Core worktree source on PYTHONPATH, and `sitecustomize` IPv4/IPv6 connect fence. Printed `bounty_core.__file__` confirmed this worktree; an attempted IPv4 connection raised `network fenced`. Scratch receipt: `/home/ryushe/.hermes/cache/scratch/core-raw-fix-latest` points to the ephemeral directory containing `final.log`.
- Regression matrix covers normalized/source input and legacy/evidence modes, raw and historical pointers, multirow refresh, regular add/get with raw intake, patch/update, ledger-only raw, and descriptive packets. Spawned-process tests force a competing raw ledger claim immediately before flock and separately prove the exclusive lock remains held after candidate preflight through the reservation boundary, across both input styles and packet modes. Packet interruption/retry regressions are included in the full suite. `git diff --check` passed.

## Handoff and remaining gates

Parent should review the complete feature diff against `6142def`, particularly effective packet selection, before/after preflight and same-lock reservation/materialization, and whether any compatibility cases require narrower validation. The **pinned BBH consumer end-to-end has not been run**: select the intended BBH integration revision, install this reviewed immutable Core commit into an isolated disposable environment, and exercise its real raw-input/non-raw-report entrypoint plus relevant consumer tests. This checkout's tests exercise the real Core API, not a BBH entrypoint or deployed environment. Perform that gate and independent review before integration; any findings require focused regression and correction.

The unrelated cross-FID descriptive-name ownership concern from the broader candidate is outside this minimal raw-only task and remains unresolved; no general namespace protection or migration is claimed. Parent removes this dossier from beta during any accepted integration. Stable propagation and runtime activation require separate authorization. No beta merge, push, production data mutation, or runtime activation was performed. Parent owns Kanban reconciliation; child task contexts cannot mutate it.
