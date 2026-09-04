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
- GREEN: `PYTHONPATH=. python3 -m pytest tests -q` passed with 113 tests.
- Review repair: free-text bearer credentials are now redacted before persistence;
  `tests/test_error_store.py::test_record_redacts_bearer_credentials_in_free_text_fields`
  was observed RED then GREEN.

## Activation decision

Independent re-review accepted repair commit
`75cbcc6193f5070052e30a12de214d9e2b5b1904`: bearer credentials are absent from
returned events and persisted JSONL, and the isolated full Core suite passed
(`113 passed`). The Core feature is approved for merge into `beta`; BBH must pin
the resulting immutable Core beta commit before its own review/integration.

## Resume point

Merge this clean reviewed feature into Core `beta`, test and push Core beta, then
update BBH's immutable Core pin to the resulting beta ref and re-run its focused
wrapper test.
