# Scoped stale/reclaimable hypothesis discovery

## Intent
Repair the post-integration reclaimability blocker: a non-owner needs an explicit, narrow way to discover stale unresolved hypotheses that can be reclaimed, without exposing active private peer work or creating a shared feed.

## Branch topology
- Feature branch: `fix/stale-reclaim-discovery`
- Base: published Core beta `04b5149f617dafe7837726faec4d1bc5cf5471b6`
- Intended integration target: Core `beta`
- Runtime activation: none; this is a source-only Core fix.

## Implemented contract
- Owner `list_visible` behavior remains unchanged.
- A non-owner sees a peer hypothesis only when it is unresolved, the owner heartbeat is stale, and the request explicitly narrows by normalized `url`, exact `surface`, or one or more `tags`.
- Unfiltered non-owner retrieval and status-only retrieval remain empty. Active peer hypotheses remain private even with a matching scope filter.
- Ordering, release/lead-specific retrieval, storage schema/migrations, and input validation remain unchanged.

## Evidence
- Expected RED: `PYTHONPATH="$PWD" /usr/bin/python3 -m pytest -q tests/test_hypothesis_ledger.py -k 'non_owner_can_discover_stale_unresolved_hypotheses_only_with_a_scope_filter or non_owner_cannot_discover_active_peer_hypotheses_or_bypass_scope_with_status'` — `1 failed, 1 passed, 15 deselected` against the published beta base; the scoped stale result was `[]`.
- GREEN: same focused command — `2 passed, 15 deselected`.
- Full isolated suite: `PYTHONPATH="$PWD" /usr/bin/python3 -m pytest -q` — `105 passed in 7.97s`.
- `PYTHONPATH="$PWD" /usr/bin/python3 -m compileall -q bounty_core tests` and `git diff --check` passed.

## Review and next gate
- No unresolved implementation blockers.
- Review the focused privacy boundaries and merge this coherent fix into a clean Core `beta` lane. Do not push, merge, or activate runtime as part of this branch task.
