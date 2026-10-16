# Safety incident beta integration handoff

Owner/card: t_3adcf07e; branch `feat/safety-incident-beta-integration-t3adcf07e`.
Base: Bounty Core `origin/beta` at `6c36ee8`; target: `beta` (not `main`).
Sources: reviewed status/explicit-report tip `97c56d90eb07bff4bbabcdc1bdeccc86c1871bf4` (including status implementation `9f660310d9785fa832ab5dddc20dbe6f0641633b`); reviewed notification diff from `feat/safety-redacted-discord-t8c456548` against `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`.

Intent: reconcile explicit agent reporting, append-only status/history, and per-attempt delivery receipts with the concurrently integrated severity-aware safety-alert UX on current beta. Keep beta's sanitizing embed and stderr receipt; retain the explicit route and per-attempt IDs. Do not include the source branches' temporary dossiers on beta. README documents fresh process-secret provisioning and lookup/receipt inspection, not live activation.

Evidence: upstream independent review t_701a1867 passed its exact older combined tree (21 focused / 207 full); current-beta reconciliation is materially different because severity UX landed afterward. A fresh independent read-only review passed the reconciled code on staged tree `c2b9f36f02647fbc46ef84c39d08b4b9497dfa84`, with `DISCORD_SAFETY_WEBHOOK_URL` absent: focused `python -m pytest -q tests/test_safety_incidents.py` 33 passed; full `python -m pytest -q` 219 passed; `git diff --cached --check` passed. Reviewer explicitly requires excluding this temporary dossier from beta before commit; no live send. Before beta merge/push, confirm the reviewed source/README/test blobs are unchanged after removing this dossier and rerun isolated checks.

Activation boundary: code integration only. No webhook URL is embedded, imported, provisioned, or used live here. Operators separately provide a fresh `DISCORD_SAFETY_WEBHOOK_URL` as a process secret and verify runtime inheritance before enabling alerts. This task does not restart deployed agents or activate Hoster.

Resume: merge this accepted code into local beta with this branch-local dossier excluded, run offline tests on beta, then push and read back. If beta has advanced, re-review the new integration before pushing.
