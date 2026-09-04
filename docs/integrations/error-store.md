# Error Store integration dossier

## Intent

Provide Bounty Core with the canonical, lane-scoped Error Store needed by BBH's
Error Intelligence workflow. It records redacted server, application, client,
and related error observations without conflating them with exact Attempts,
MapStore facts, private hypotheses, or findings.

## Branch and target

- Feature branch: `feat/error-store`
- Base: Bounty Core `beta` at `f3d02453f26a4e221632466c26742dfb55368f28`
- Intended integration target: `beta`
- Consumer follow-up: BBH `feat/error-intelligence` pins the accepted Core
  commit and exposes the skill-facing CLI.

## Implemented contract

- `bounty_core.ErrorStore` resolves the existing program/family/lane layout and
  appends each redacted event to `errors/events.jsonl`.
- Records receive `E-...` identities rather than Attempts' `A-...` identities.
- Required error fields cover producer, subject, reason, layer, channel,
  status/event, fingerprint, and trigger family; optional fields retain safe
  input location, actor/repro state, exact-attempt pointer, artifact pointer,
  and redacted details.
- A bounded fingerprint summary groups repeated observations without discarding
  the immutable evidence events.

## Evidence

- RED: `python3 -m pytest tests/test_error_store.py -q` failed because
  `bounty_core.error_store` did not exist.
- RED: importing `ErrorStore` from the public package failed before export.
- GREEN: `python3 -m pytest tests/test_error_store.py tests/test_evidence.py -q`
  passed with 10 tests.

## Activation boundary

This commit adds the Core primitive only. It does not create runtime traffic or
activate a BBH agent. BBH integration must pin the reviewed immutable Core
commit, add its wrapper/tests/skill update, and pass independent review before
beta integration.

## Resume point

Run the full Core test suite and review the implementation; then commit this
feature. Build BBH's wrapper only against the resulting immutable Core commit.
