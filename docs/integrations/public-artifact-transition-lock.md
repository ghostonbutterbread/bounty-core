# Public artifact transition lock integration dossier

- **Status:** review requested; not integrated or pushed
- **Owner:** Hermes promotion blocker subtask; independent review by parent
- **Branch:** `fix/promo-artifact-lifecycle-race`
- **Worktree:** `/home/ryushe/worktrees/bounty-core-promo-artifact-race`
- **Base:** `8fc4f99fee8e7d4e8e0a6542480b23f9618373f4` (fetched `origin/beta`)
- **Intended integration target:** `beta`; stable promotion is a separate decision
- **Implementation checkpoint:** pending first commit; successor handoff commit will record the actual SHA.
- **Inspiration / predecessor:** `fix/public-artifact-transition-lock` at `641d33dff0260d31152e3480db20cb0b6e7262c4`, implementation `48530961231e7053a7eb57c0e7c0a29b30a56437`; retained untouched. Its dossier flagged the old concurrency test's timeout-based ordering as a blocker. This branch supersedes it as a review candidate, not as an authorization to retire it.

## Contract and boundary

`PublicArtifactStore.record` reads and validates the latest persisted transition while holding the same exclusive `flock` through append, flush and fsync. This prevents a stale update after cleanup and duplicate creation for a caller-supplied ID among cooperating writers. Storage schema and public API remain unchanged. Opening the append file before transition validation can create an empty file on rejection; input-error precedence can also differ. Locking is advisory and assumes cooperating writers use the same file/inode and a filesystem with working `flock`; direct writes, file replacement and multi-host filesystem semantics are not established here. Readers remain unlocked.

The actual fix is patch-equivalent to the predecessor's implementation. `origin/master` at `dc31a6c4e8394dd7795056a545c8bb7b5417f4ab` has no public artifact store; no stable-branch change is authorized here. Propagate the reviewed beta fix through the intended promotion, not by duplicating it into descendants.

## Evidence

- Before the fix, both multiprocess cases failed with `('appended', '')`: the competing writer signalled at the pre-flock boundary, the parent committed cleanup or creation, and the stale writer appended. On an isolated base snapshot, the lock-ownership case failed with `DID NOT RAISE BlockingIOError`.
- After the fix, `python -m pytest -q tests/test_public_artifact_store.py`: **9 passed**; `python -m pytest -q tests`: **239 passed**. `/usr/bin/python3`, pytest 9.0.3, worktree first on `PYTHONPATH`, plugin autoload disabled, disposable `HOME`/XDG/TMPDIR, no inherited credentials or environment. Python internet sockets were fenced by a scratch `sitecustomize`; fixture paths were temporary and no production store was used.
- The tests use spawned processes, explicit events at the real lock/read boundaries and a real nonblocking flock probe; timeouts are only deadlock/failure guards, not ordering evidence. They cover both commit orders, duplicate ID creation, rejected append history and non-reusable cleanup state.
- `git diff --check` clean. Code-only stable patch ID matches predecessor `b06850c249a54b02c3620232be2c47c050287b5e`.

## Outstanding review / activation

Independent complete-diff and test-evidence review remains for the parent before any integration. No beta merge, push, runtime activation or stable promotion is authorized by this branch. Recheck fetched beta and rerun the isolated suite on the actual integration tree after any concurrent changes. The predecessor dossier also mentioned a separate BBH report-source compatibility blocker; its current disposition is outside this subtask and must be checked by the promotion owner, not assumed resolved.

## Handoff

Exact next step: review this branch against the base above, including the deterministic ordering tests and lock assumptions; then decide on beta integration. Remove this branch-local dossier from the integration result after acceptance. Preserve the predecessor branch/worktree until its owner decides its disposition.
