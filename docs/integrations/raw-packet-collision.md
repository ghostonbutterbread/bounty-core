# Raw packet collision integration dossier

- **Status:** BLOCKED / incomplete; do not integrate, push, promote, or activate.
- **Owner:** delegated Core investigator; parent owns review and integration.
- **Branch / worktree:** `fix/core-raw-collision-minimal` / `/home/ryushe/worktrees/core-raw-collision-minimal`.
- **Base / intended target:** fetched `origin/beta` `6142defb3de7cef44887c1685e4f670072585785` / `beta`.
- **Implementation checkpoints:** `e35033c6ce59aaec171a922edfa180c19924f82c`, `d510bca6d3aa0c1cf925ad2fb331fe14068712c7`; this dossier is a later handoff-only commit.
- **Prior evidence:** `docs/integrations/reserved-packet-namespace.md` on `fix/promo-fid-reserved-namespace`; that blocked branch was not modified or integrated.

## Intent and current contract

Preserve `reports/raw` as input while preventing packet writers from treating it as a finding packet. Do not prohibit a ledger-only FID `raw`, or a distinct descriptive packet merely because its FID is `raw`. Do not migrate or overwrite ambiguous historic material.

The checkpoint rejects the exact `reports/raw` packet path in the shared packet-path resolver, and validates an evidence packet reservation before mutating its finding dictionary. Direct calls to both writers now reject that exact collision; a separate `raw-bug` packet and ledger-only `raw` remain supported. **This does not meet the requested pre-effect guarantee:** `add_finding` still writes scaffolding and/or ledger, event or packet data before encountering this error, including when refresh encounters a historical raw row. The guard is not sufficient for release.

## Evidence

- Test-first direct and add regressions: original baseline produced 6 failures / 1 pass; direct writer dictionary mutation separately reproduced red, then the focused direct-writer plus packet-migration suite passed 25 tests.
- Final unfiltered isolated suite on `d510bca`: **244 passed, 6 failed in 23.28s**. All six failures are `tests/test_raw_packet_collision.py`: four direct `raw` adds (normalized/source × legacy/evidence-only), and two unrelated adds with the immutable baseline historical `raw` ledger row (normalized/source). All six reject but modify other files before rejection. Fixture is byte-identical to the previous branch's 6142def-generated synthetic ledger; that original dossier records its producer command.
- Run used `/usr/bin/python3 -m pytest -q`, worktree first on `PYTHONPATH`, fresh disposable HOME, XDG, TMPDIR and `--basetemp`, plugin autoload disabled, with a `sitecustomize` socket IPv4/IPv6 connect fence. `bounty_core.__file__` was verified inside this worktree and a fenced connect attempt raised. Log (ephemeral): `/home/ryushe/.hermes/cache/scratch/core-raw-tests.XrpBh4br/full-final.log`.
- Snapshots in the current tests compare files, intentionally omit `.lock` files, and do not compare empty directories; they do not yet establish literal no-effect semantics for lock/scaffolding metadata. No race test, pinned consumer end-to-end, or independent review has been completed.

## Blocker and exact resume

Restructure preflight and locking, rather than adding an unlocked check. For source-style adds `ledger_add` currently commits in a separate lock before the packet phase; normalized evidence mode commits a reservation in one lock and creates/refreshes packets in another. `resolve_storage(create=True)` and the lock helper also create state before current checks. Determine the effective candidate and every packet refresh will actually materialize, validate the exact raw collision and existing ambiguous legacy pointers before any relevant effect, with concurrent cooperating ledger claims serialized across validation and reservation. Preserve tested reservation-before-packet crash behavior; do not claim rollback of arbitrary I/O failures. Ensure any locking metadata effects are explicitly covered by the required no-effect contract, not hidden by snapshots.

Resume from `d510bca6d3aa0c1cf925ad2fb331fe14068712c7` plus this dossier; make the six regressions pass without weakening assertions. Add deterministic real interprocess race coverage at the actual lock boundary, historical raw packet variants, no-effect snapshots that include directories/lock files, ordinary add/find/report and real raw intake coverage. Run the full isolated suite and pinned consumer workflow, then obtain independent review. No broader namespace hardening or automatic migrations are authorized. Parent should remove the dossier from beta on any later accepted integration. Stable propagation and runtime activation require separate authorization.

Kanban lookup returned `delegate_task child contexts cannot mutate Kanban tasks or boards`; parent must reconcile the existing task. No push, beta merge, shared-ref update, or runtime activation was performed.
