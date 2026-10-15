# Discord safety webhook transport repair integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `fix/safety-webhook-user-agent`
- **Base commit:** `21005a1` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `bd7af07523fac5ae91f0e0c757b2ef8162d2136e`
- **Feature implementation commit(s):** `c6df7ff965378f38c568cb64a224f6bff28d8f08`, `bd7af07523fac5ae91f0e0c757b2ef8162d2136e`
- **Inspiration / canonical references:** Real approved Discord webhook test: urllib default identity returned Cloudflare 1010/403, while a browser-compatible User-Agent allowed GET and POST.

## Intent

Make the Bounty Core safety notifier work with the approved Discord webhook from this host, without storing its bearer URL or sending sensitive event details. Add a delivery message ID when Discord returns one, enabling exact read-back.

## Implemented contract

`SafetyIncidentStore.notify` sends JSON with a browser-compatible User-Agent and `wait=true`. Successful HTTP 200/204 is `sent`; a numeric Discord message ID from a 200 JSON response is included in the persisted notification receipt. Failed/unconfigured delivery remains durable and nonzero in CLI. No change to incident trigger or storage root.

## Evidence and review

- Red test: User-Agent regression failed before fix because request carried none.
- Tests: initial 15 focused / 201 full passed; post-review fix `python -m pytest -q tests/test_safety_incidents.py` 16 passed, `python -m pytest -q` 202 passed, `git diff --check` clean.
- Independent review: first fresh release gate reproduced `http.client.IncompleteRead` after HTTP 200 leaving only `pending`; fixed by treating unparseable/truncated response metadata as accepted with no message ID, preserving the final receipt. Second release gate pending.
- Live, owner-approved, synthetic-only delivery: direct webhook POST with `wait=true` returned message `1560427336875245640`, exact GET read-back matched. Library from feature worktree recorded synthetic incident `SI-7d71822a577f4a099510e8e19f16688e`, receipt `sent` with message `1560428166743330837`, exact GET read-back matched. No raw webhook URL stored in repository, script, or output.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- Agent runtime activation: this host's feature code works live; remote agent installations and injected process secret are not verified. A chat-shared webhook may be used with owner acceptance; no rotation gate. Do not claim universal deployment.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/safety-webhook-user-agent`
- **Latest immutable recovery checkpoint:** `bd7af07523fac5ae91f0e0c757b2ef8162d2136e`
- **Feature implementation commit(s):** `c6df7ff965378f38c568cb64a224f6bff28d8f08`, `bd7af07523fac5ae91f0e0c757b2ef8162d2136e`
- **Exact resume point:** independent release review, beta integration/test/push/read-back, retire dossier and feature worktree.
- **Working-tree state at handoff:** clean after this dossier checkpoint commit.

## Decision gates

- **Integration:** independent review, passing suite, clean beta merge and post-merge checks.
- **Activation:** verify each agent runtime resolves a compatible Bounty Core and process secret, then a live channel read-back.
- **Stable promotion:** owner decision.

## Decision record

- 2026-10-15 — bounded compatibility repair and synthetic live delivery verified; no production incident was fabricated.
