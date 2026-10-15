# Safety incident store integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `feat/safety-incident-store`
- **Base commit:** `035c9a1` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `a0e397e2bd0a93aaaf2066173d45a8894ec09d83`
- **Feature implementation commit(s):** `a0e397e2bd0a93aaaf2066173d45a8894ec09d83`
- **Inspiration / canonical references:** Ryushe's safety-incident request; Bounty Core `ErrorStore`, `BlockerStore`, and storage resolver.

## Intent

Provide a durable, distinct, immediate self-report path for agent actions with potential non-owned or production impact and a Discord alert attempt. Do not conflate incidents with vulnerability findings or routine errors. Do not use the webhook URL pasted in chat.

## Implemented contract

Agent stops unsafe work, records a sanitized lane-scoped event, then optionally delivers a fixed-minimal Discord webhook notification. Store the delivery disposition separately; missing/failed delivery is nonzero in CLI. No automatic request interception, agent routing, guarantee of detection, live webhook configuration, or unauthorized remediation.

## Evidence and review

- Tests and commands: initial 192 passed; post-review `python -m pytest -q tests/test_safety_incidents.py` — 14 passed; `python -m pytest -q` — 200 passed; `git diff --check` clean; offline CLI smoke persisted an incident without alert.
- Independent review: `a0e397e` review found partial-tail recovery, pre-send receipt, webhook-path redaction, existing-file mode, and CLI boundary gaps; patched on feature branch, re-review pending.
- Replay/cohort/fixture evidence: mocked webhook only; no live posting to exposed credential.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** Live Discord channel read-back, agent-routing integration, and secret provisioning.
- **Command / fixture / environment needed:** a newly rotated, privately configured `DISCORD_SAFETY_WEBHOOK_URL` and a private channel with a safe test message; integration of agent safety policy/BBH invocation.
- **Trigger to run it:** operator rotates the exposed webhook and authorizes runtime activation.
- **Why it blocks activation:** pasted URL is a bearer credential; no safe notification delivery confirmation or agent invocation is possible here.
- **Next completion step:** separately configure and verify delivery, then route agents to the CLI/library at the safety boundary.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-store`
- **Latest immutable recovery checkpoint:** `a0e397e2bd0a93aaaf2066173d45a8894ec09d83`
- **Feature implementation commit(s):** `a0e397e2bd0a93aaaf2066173d45a8894ec09d83`
- **Exact resume point:** address independent review findings, rerun tests, then integration decision.
- **Working-tree state at handoff:** committed implementation; dossier-only receipt edit pending commit.

## Decision gates

- **Integration gate:** passing focused/full tests and independent review.
- **Activation / cohort gate:** rotated webhook, secret configuration, and verified private-channel read-back; agent routing separately reviewed.
- **Promotion gate:** explicit owner direction for stable.

## Decision record

- 2026-10-15 — created feature branch from fetched beta; live webhook intentionally unused.
