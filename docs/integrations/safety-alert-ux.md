# Safety incident alert UX integration dossier

- **Status:** feature (local verification complete; integration review pending)
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/safety-incident-alert-ux`
- **Base commit:** `ce8718b6bfb39fb08533f506bd2bfe627b52e5da` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none before task commit; branch tip is the recovery ref
- **Feature implementation commit(s):** task commit at branch tip (see handoff SHA)
- **Inspiration / canonical references:** safety incident API and CLI in `bounty_core/safety_incidents.py`; README safety incident section

## Intent and implemented contract

Add an operator-readable alert after durable recording without changing notification receipts, stdout JSON, or exit status. `severity` is optional (`unknown`, `low`, `medium`, `high`, `critical`), stored with the incident; old records without severity notify as unknown. CLI record prints saved ID, category, severity and bounded action on stderr after event fsync and before notification. Discord content conveys ID, severity and urgency; one severity-colored embed conveys sanitized, bounded action, impact and containment. Mentions are disabled. No actual incident or live webhook was used.

## Evidence and review

- Focused: `python -m pytest tests/test_safety_incidents.py -q` — 27 passed.
- Full: `python -m pytest -q` — 213 passed.
- `git diff --check` — clean.
- Offline fixtures cover 5 colors, malformed/legacy severity, truncation, webhook redaction, mention/control suppression, 200/204 and invalid body, notification failure, fsync-before-stderr-before-network, failed receipt, and old callers.
- Independent review: pending parent-agent review. No merge or push performed.
- Merge/ancestry: branch based on `origin/beta` at `ce8718b6` when fetched.

## Blockers and deferred work

- **Missing evidence:** live Discord delivery/rendering in an operator-approved channel; intentionally not run in this task.
- **Trigger / fixture:** only with explicit authorization and a controlled incident fixture plus approved webhook; confirm channel rendering and receipt read-back.
- **Boundary:** blocks claims about live Discord appearance, not local feature verification. Agent routing/activation remains separate.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-alert-ux`
- **Latest immutable recovery checkpoint:** task commit at branch tip (see handoff SHA).
- **Feature implementation commit(s):** task commit at branch tip.
- **Exact resume point:** independent review of branch diff and offline receipts; reconcile current `beta` before any integration.
- **Working-tree state at handoff:** expected clean after commit.

## Decision gates

- **Integration gate:** parent review and deliberate reconcile/merge into `beta`; remove branch-local dossier from target.
- **Activation / cohort gate:** separate routing and approved webhook configuration.
- **Promotion gate:** no stable promotion authorized.

## Decision record

- 2026-10-15 — feature implemented and locally verified offline; handoff for review, no merge/push.
