# Public-artifact privacy and cleanup integration dossier

- **Status:** awaiting independent review
- **Owner:** delegated Core artifact-safety worker
- **Owning feature branch/ref:** `fix/promo-artifact-safety` in the separate clone `/home/ryushe/worktrees/bounty-core-promo-artifact-safety`
- **Base commit:** `6142defb3de7cef44887c1685e4f670072585785` (fetched `origin/beta`)
- **Intended integration target:** Core `beta`, then separately authorized beta → `master` promotion
- **Latest immutable recovery checkpoint / implementation commit:** `66ef4cb65873686943d33e0670cb95864370cba5`
- **Last updated:** 2026-11-17
- **Inspiration / references:** independent promotion review findings; BBH `public-artifacts` policy and `agents/public_artifacts.py` consumer.

## Intent and implemented contract

Reject credentialed, query-bearing, fragment-bearing or malformed URLs and nonempty arbitrary details at the actual shared store boundary, with safe error messages. Guard remaining short text fields against common obvious secret/payload forms. Bind later lifecycle records to account, kind, exact URL and any known object ID under the append lock. Omitted object IDs retain prior known identity. Require a recorded private state before cleanup and the BBH-compatible pending → deleted → verified sequence; avoid silent visibility changes and accept only a real boolean cleanup flag. Preserve incomplete or corrupt history and reject further writes; an fsync failure leaves append outcome uncertain. Read views remain tolerant and are not integrity checks.

## Evidence and review

- Initial focused red phase: eight tests failed against base for actual unrestricted URL/details and identity swap.
- Isolated complete Core suite at implementation checkpoint: 273 passed; `env -i` with disposable HOME/XDG/TMPDIR, checkout-first PYTHONPATH, `python -m pytest -q -p no:cacheprovider tests` using `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python`.
- Isolated BBH CLI consumer workflow: 3 passed from `/home/ryushe/worktrees/bbh-artifact-contract`, `BOUNTY_CORE_TEST_SOURCE` and `PYTHONPATH` both pointing to this clone; same interpreter, disposable HOME/XDG/TMPDIR.
- Regression coverage includes mismatched account/kind/URL/object ID, public-to-cleanup skip, nonboolean evidence, invalid URL/detail/sensitive variants, torn writes, uncertain fsync, lock ownership, and deterministic competing-process identity revalidation.
- `git diff --check` passed before implementation commit. Parent/independent reviewer must assess the exact commit range and behavioral compatibility; no independent acceptance is claimed.

## Blockers, caveats and deferred work

- Semantic privacy cannot be proven from syntax: opaque secrets and sensitive share links in URL paths or short labels are indistinguishable from valid IDs. Callers remain responsible for supplying non-secret inputs. Existing events are not sanitized or migrated; audit and remediation require a separate authorized storage operation.
- Public direct deletion cannot be recorded as completed cleanup under the existing BBH policy/CLI. Keep it unresolved instead of fabricating a private transition.
- Discovery reads skip malformed lines; the write path rejects corrupt history. Advisory locks coordinate cooperating processes on one stable filesystem inode, not uncooperative writers or separate sync replicas.
- Existing beta consumers using nonempty `details`, mutable identity, or cleanup transitions that bypass private/pending now fail and require migration; current inspected BBH CLI passes empty `details` and its real workflow passed.
- Provider FID raw namespace collision is outside this task and `reports.py` was not modified.
- Independent review is required before beta integration/promotion. If it identifies compatibility or privacy gaps, add reproducing regressions and rerun the full Core and CLI suites above.

## Resume / decision gates

- Resume from the implementation checkpoint and the later dossier-only tip on `fix/promo-artifact-safety`; verify both commit IDs and diff. This is a separate clone, so the integration owner must explicitly fetch the local feature ref from that clone before merging/cherry-picking; no shared refs were changed.
- Exact next action: independent review of URL/label limitations, historical data, state transitions, partial failures and races; reconcile any findings. Target `beta`; remove this branch-local dossier on integration. Do not push or promote or activate runtime as part of this handoff.
- Integration gate: parent-run review and combined integration tests. Promotion and runtime activation are separate decisions.
