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
- A non-owner sees a peer hypothesis only when it is **private and unlinked**, unresolved, the owner heartbeat is stale, and the request explicitly narrows by normalized `url`, exact `surface`, or one or more `tags`.
- Lead-linked context, including `context_state='released'`, remains discoverable only through `lead_followup(..., lead_id=<exact lead>)`; generic url/surface/tag discovery never returns it.
- Unfiltered non-owner retrieval and status-only retrieval remain empty. Active peer hypotheses and terminal records remain private even with a matching scope filter.
- Ordering, release/lead-specific retrieval, storage schema/migrations, and input validation remain unchanged.

## Evidence
- Review defect reproduced (RED) on candidate `5cb50abf6e59732b8b0c503e37cebfe8b885c3b3`: `PYTHONPATH="$PWD" /usr/bin/python3 -m pytest -q tests/test_hypothesis_ledger.py::test_non_owner_generic_discovery_excludes_stale_released_lead_context` — `1 failed`; generic `surface="export"` returned the stale `context_state='released'` lead-linked record.
- GREEN focused boundary receipt: `PYTHONPATH="$PWD" /usr/bin/python3 -m pytest -q tests/test_hypothesis_ledger.py -k 'non_owner_generic_discovery_excludes_stale_released_lead_context or non_owner_can_discover_stale_unresolved_hypotheses_only_with_a_scope_filter or lead_followup_reveals_only_released_linked_context'` — `3 passed, 15 deselected`.
- Full isolated suite: `PYTHONPATH="$PWD" /usr/bin/python3 -m pytest -q` — `106 passed in 7.94s`.
- `PYTHONPATH="$PWD" /usr/bin/python3 -m compileall -q bounty_core tests` and `git diff --check` passed.

## Review and next gate
- The reviewed privacy regression from candidate `5cb50ab` is corrected by restricting generic stale recovery to `lead_id is None` and `context_state == "private"`; no migration is required.
- No unresolved implementation blockers. Review this follow-up repair's privacy boundaries and merge this coherent fix into a clean Core `beta` lane. Do not push, merge, or activate runtime as part of this branch task.
