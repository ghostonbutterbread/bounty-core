# Generated type-index cleanup integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `fix/prune-stale-finding-type-index`
- **Base commit:** `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** `604d2b5f8c9e156df182f28c7fbc35e0e941a311`
- **Feature implementation commits:** `604d2b5f8c9e156df182f28c7fbc35e0e941a311`
- **Inspiration:** Manual hunter FID content corrections reveal stale generated type navigation after type changes.

## Intent and contract

After rebuilding generated type/status navigation, remove only generated old type indexes no longer in the current ledger view. Preserve human-authored files, current type views, dated report buckets and category views. Do not alter canonical ledger data or finalized reports.

## Evidence and review

- `python3 -m pytest -q tests/test_reports.py tests/test_core_smoke.py`: 33 passed, including colliding daily/category status and retained-type/different-status regressions.
- New regression changes a finding from a unique obsolete type to a corrected type, checks old generated type indexes removed, new index written, manual nav untouched.
- Independent review: first review blocked on collisions with daily/category namespaces and a retained-type/different-status view; both corrected with known-status-root scoping and exact status/type pairs. Re-review pending.
- Merge/ancestry: feature from fetched origin/beta at base above.

## Blockers / deferred work

- Independent review and provider beta merge/push pending. Consumer must pin the published provider revision, reinstall and rerun its integration tests before release.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/prune-stale-finding-type-index`
- **Latest immutable recovery checkpoint:** `604d2b5f8c9e156df182f28c7fbc35e0e941a311`
- **Feature implementation commits:** `604d2b5f8c9e156df182f28c7fbc35e0e941a311`
- **Exact resume point:** review, merge provider beta, pin BBH consumer.
- **Working-tree state:** clean after corrective checkpoint.

## Decision gates

- Provider beta: independent approval, focused/full tests, current beta.
- Consumer activation: exact pin and checkout-local installed provenance.
- Stable: separate owner direction.

## Decision record

- 2026-09-25 — isolated report-index repair for FID correction contract.
