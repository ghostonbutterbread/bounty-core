# Safety incident alert UX integration dossier

- **Status:** independently reviewed and accepted for beta integration; live rendering deferred
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/safety-incident-alert-ux`
- **Base commit:** `ce8718b6bfb39fb08533f506bd2bfe627b52e5da` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `d8f19fb9e1de0cc3dd38f8da53ced6018f816805` on `feat/safety-incident-alert-ux`
- **Feature implementation commit(s):** `35b7c894a3fdaf9b03aba3c51d3314b052330850`, `d8f19fb9e1de0cc3dd38f8da53ced6018f816805`
- **Inspiration / canonical references:** safety incident API and CLI in `bounty_core/safety_incidents.py`; README safety incident section

## Intent and implemented contract

Add an operator-readable alert after durable recording without changing notification receipts, stdout JSON, or exit status. `severity` is optional (`unknown`, `low`, `medium`, `high`, `critical`), stored with the incident; old records without severity notify as unknown. CLI record prints saved ID, category, severity and bounded action on stderr after event fsync and before notification. Discord content conveys ID, severity and urgency; one severity-colored embed conveys sanitized, bounded action, impact and containment. Mentions are disabled. No actual incident or live webhook was used.

## Evidence and review

- Focused: `python -m pytest tests/test_safety_incidents.py -q` — 27 passed.
- Full: `python -m pytest -q` — 213 passed.
- `git diff --check` — clean.
- Offline fixtures cover 5 colors, malformed/legacy severity, truncation, webhook redaction, mention/control suppression, 200/204 and invalid body, notification failure, fsync-before-stderr-before-network, failed receipt, and old callers.
- Follow-up: an unavailable stderr after the durable write must not prevent webhook delivery. CLI console output now tolerates `OSError`; regression verifies the notification still runs. Focused `28 passed`, full `214 passed`, `git diff --check` clean.
- Independent review: accepted after fresh `28 passed` focused and `214 passed` full; inspected diff, old callers/records, failure receipts, stderr-before-network, defensive redaction, and Discord's webhook payload contract (content 2000, rich embeds, wait response). No concrete release-blocking defect found. No live webhook was sent.
- Merge/ancestry: fetched `origin/beta` at `ce8718b6`; feature remains a direct descendant. No merge or push performed at decision checkpoint.

## Blockers and deferred work

- **Missing evidence:** live Discord delivery/rendering in an operator-approved channel; intentionally not run in this task.
- **Trigger / fixture:** only with explicit authorization and a controlled incident fixture plus approved webhook; confirm channel rendering and receipt read-back.
- **Boundary:** blocks claims about live Discord appearance, not local feature verification. Agent routing/activation remains separate.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-alert-ux`
- **Latest immutable recovery checkpoint:** `d8f19fb9e1de0cc3dd38f8da53ced6018f816805` on `feat/safety-incident-alert-ux`; verify later dossier-only commit separately.
- **Feature implementation commit(s):** `35b7c894a3fdaf9b03aba3c51d3314b052330850`, `d8f19fb9e1de0cc3dd38f8da53ced6018f816805`.
- **Exact resume point:** integrate accepted feature into the fetched clean `beta` checkout, remove dossier, verify focused/full suite, publish/read back; do not activate or send a live webhook.
- **Working-tree state at handoff:** expected clean after commit.

## Decision gates

- **Integration gate:** parent review and deliberate reconcile/merge into `beta`; remove branch-local dossier from target.
- **Activation / cohort gate:** separate routing and approved webhook configuration.
- **Promotion gate:** no stable promotion authorized.

## Decision record

- 2026-10-15 — feature implemented and locally verified offline; handoff for review, no merge/push.
- 2026-10-15 — independent release gate accepts for beta: fetched beta unchanged, reviewed actual branch diff and provider contract, reran focused/full checks, `git diff --check` clean. Live Discord rendering remains explicitly unverified and requires operator authorization. No live send or stable promotion.
