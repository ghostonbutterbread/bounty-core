# Public Artifact Store Integration Dossier

## Intent

Provide a generic, lane-scoped Bounty Core registry for non-secret owned public-artifact references so consumers can reuse an existing artifact, record the owning account reference and URL/object ID, and retain verified cleanup history.

## Scope and boundary

- **Provider branch:** `feat/public-artifact-store`
- **Base / target:** `origin/beta` at `1bba64b557aa3b604092b5bad47689fcb40cc0f7` → `beta`
- **Implementation:** `bounty_core.public_artifact_store.PublicArtifactStore`, exported from `bounty_core`.
- **Contract:** append-only JSONL at `<lane>/public_artifacts/events.jsonl`; lifecycle events are `created`, `updated`, `visibility_changed`, `cleanup_pending`, `deleted`, and `cleanup_verified`; `current()` derives the latest event per artifact.
- **Non-goals:** publication authorization, community selection, payload/test policy, and account credentials. Consumers own those decisions.

## Evidence

- **Implementation checkpoint:** `d54c9677c5850ed7f3983b3bba71603da69f3712`; the current branch tip will add this dossier-only handoff commit.
- `python3 -m pytest -q tests/test_public_artifact_store.py` — 3 passed.
- `python3 -m pytest -q` — 122 passed.
- `git diff --check` — passed.

## Consumer handoff

After provider review and beta integration, BBH must pin the resulting full immutable provider SHA in `requirements.txt`, exercise its CLI through an installed dependency, and add the Public Artifacts skill. Runtime activation or skill synchronization remains separate.

## Next action

Obtain an independent no-edit review of this branch; resolve any blocker and re-run the full provider suite before integrating to Bounty Core beta.
