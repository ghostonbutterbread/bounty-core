# Bounty Core

Bounty Core owns canonical storage, ledgers, and generated report navigation for Ghost bug bounty workflows.

## Canonical Storage

Storage is organized by program, family, and lane:

```text
~/Shared/{family}/{program}/{lane}/
```

Current canonical families are:

- `web_bounty`: web and API work, with default lanes `web` and `api`.
- `binaries`: binary and client work, with default lanes `apk`, `exe`, and `mac`.

Each lane keeps its own `reports/`, `ledgers/`, `working/`, `context/`, `notes/`, and `recon/` roots. Binary lanes also have `input/`. This keeps findings, generated artifacts, notes, and context isolated per target lane.

## Report UX

The evidence-only report UX centers on stable finding packets and populated navigation:

```text
reports/
  D01-owned-xss/
    EVIDENCE.md              # investigator's claim, proof index, reproduction record
    poc.py                   # optional standalone PoC, next to final report
    example-com-xss-D01.md   # final report when reviewed and registered
    evidence/                # optional attachments only when needed; never precreated
  categories/
  severity/
  submitted/                 # only while a submitted finding exists
```

- New evidence-only packets use `reports/<FID>-<slug>/`, where the slug comes from the initial title and `report_dir` is frozen in the ledger. Existing `reports/<FID>/` packets remain where they are. The default legacy flow still writes an editable `REPORT.md` to `reports/<FID>/`; `FINALIZED.md` is an explicit legacy copy made only by `finalize_finding_report`.
- Lifecycle and severity are generated navigation views, not storage paths. `report_dir` and `report_path` remain valid when status, severity, or title changes.
- The legacy default report mode retains date-scoped `reports/daily/{MM-DD-YYYY}/` views, but evidence-only refresh does not generate daily or status-by-class matrix views.
- `reports/categories/{category}/` contains category indexes and per-FID links or stubs back to canonical finding reports.
- `reports/severity/{high,medium,low}/` contains severity-focused indexes.

No empty legacy matrix or daily roots are seeded by storage initialization. Historical hand-authored and populated legacy files are not removed by evidence-only refresh.

## Agent safety incidents (opt-in beta API)

`SafetyIncidentStore` is **separate** from findings, errors, and blockers. An agent that
realizes its action may have changed non-owned data, made an **unplanned change
to live production infrastructure** (for example a write to a production AWS
bucket, IAM change, deployment, or service shutdown), crossed scope, or caused
unauthorized sensitive exposure should stop, report observed facts promptly,
and seek operator direction for containment. Production impact counts even if
we own the infrastructure. Expected actions on explicitly owned test fixtures,
including deletion of a disposable owned account during an authorized IDOR
test, are normal testing, not incidents. Classify actual authorization, target,
and consequence—not the HTTP verb or the fact that an account was deleted.
Suspected effects can be recorded as `uncertain`; do not wait to prove damage
or attempt an unapproved reversal. This is self-reporting, **not automatic
interception** of requests or a guarantee that every unsafe action is detected.

The lane-local append-only record is
`~/Shared/{family}/{program}/{lane}/safety_incidents/events.jsonl`. Notification
attempts and their status are in `notifications.jsonl`; they are not finding
severity or proof packets. Keep raw requests/responses, customer data, secrets,
and webhook URLs out of descriptions; common credentials and Discord webhook
paths are also redacted defensively. Give concise sanitized context in `action`,
`subject`, `impact`, and `containment`. The Discord alert includes a short urgency
line (ID, severity, program/lane, category, outcome) and a severity-colored embed
with sanitized, single-line, bounded `action`, `impact`, and `containment`. Do not
put raw requests, customer data, or secrets in those fields: defensive redaction
is not a substitute for preparing safe summaries. Discord mentions are disabled.

The original version-1 report row retains its `incident_id`, timestamp,
program/family/lane, producer, run ID, category, outcome, action, subject,
impact, and containment. It is never edited through this interface. For a
subsequent status change, call `store.append_status(incident_id, status=...,
producer=..., note=...)`. This appends a version-1 `record_type: status` row
with its own `event_id` and timestamp to the same stream; `store.get(id)` always
returns the original report, and `store.history(id)` returns report and status
rows in append order. Notification attempts stay in the separate receipt stream.
The interface exposes no overwrite or delete operation. File-system operators
must still protect the underlying storage from direct modification.

```bash
python -m bounty_core.safety_cli --program PROGRAM --lane web report \
  --producer AGENT --run-id RUN --category non-owned-mutation \
  --outcome uncertain --severity high --action 'POST changed an object' \
  --subject 'object ownership uncertain' --impact 'possible non-owned mutation' \
  --containment 'stopped further writes; awaiting operator'
```

`--severity` is optional (`unknown` by default); choices are `unknown`, `low`,
`medium`, `high`, and `critical`. Library callers can likewise pass `severity=`
to `SafetyIncidentStore.record(...)`; existing callers default to `unknown` and
older incidents without severity remain retriable. The CLI prints a brief saved
ID/category/severity/action to **stderr** immediately after fsync and before
notification, then emits the final JSON on **stdout**.

`report` is an explicit agent action, not an automatic inference from normal
testing activity. Its JSON receipt includes a top-level `incident_id` and the
stored `incident` (including the same ID), plus the separate `notification`
receipt. The older `record` command remains an alias for existing callers.
Invalid inputs do not create a report or attempt a notification.

The record is fsynced **before** any network delivery. With no configuration, the
command records a `not-configured` notification receipt and exits 1; it does not
silently claim an alert was delivered. An operator should create a **fresh**
Discord webhook for a private incident channel, provision its URL as
`DISCORD_SAFETY_WEBHOOK_URL` in the agent process's secret environment, and
verify that new processes inherit it. Never use a webhook previously exposed
in chat, or place its URL in a repository, command line, Shared artifact, or
agent prompt. Treat the URL as a bearer credential and restrict access.
Do not enable delivery until the runtime secret has been provisioned by an
operator; merging this code does not activate alerts. Discord's `wait=true`
response records `sent` and, when provided, a `message_id` in the notification
receipt for exact message read-back. HTTP failures and timeouts retain the
incident and a failure/unknown receipt.
A `pending` receipt is fsynced before each delivery attempt; its `attempt_id`
links it to the final disposition, even when attempts for one incident overlap.
If an attempt has no final receipt, delivery is unknown; check the channel
before retrying. If receipt storage fails, the CLI still returns the persisted
incident ID with `receipt-write-failed` and exits nonzero. A timeout can mean delivery
happened; retrying may duplicate a message. After
checking the channel, manually retry an undelivered ID with:

```bash
python -m bounty_core.safety_cli --program PROGRAM --lane web notify SI-INCIDENT_ID
```

For a reported ID, open the lane-local `events.jsonl` to find its original
report and later `record_type: status` rows; inspect `notifications.jsonl` for
the same `incident_id` and match pending/final rows by `attempt_id`. A final
`sent` row may include Discord `message_id`; `http-*`, `not-configured`, and
`invalid-configuration` are unsuccessful, while `delivery-unknown`, an unmatched
`pending`, or `receipt-write-failed` requires channel and storage inspection
before any retry. Do not infer delivery from the CLI's persisted incident ID.

`SafetyIncidentStore(..., root_override=...)` supports explicit local tests.
No webhook is sent unless the environment variable is configured. Rollout to
agents requires a separate routing/integration step; importing the library does
not turn on automatic monitoring.

Generated navigation files are marked with:

```text
<!-- generated: bounty-core-report-navigation -->
```

Files with that marker are safe to refresh. Unmarked hand-authored navigation files are not overwritten. Generated finding reports are separately marked and checksummed; if a canonical finding report has been hand-edited, Bounty Core preserves it instead of replacing it during refresh.

## Navigation Dedupe

Generated navigation dedupes duplicate finding concepts by normalized title, file, line, and category. Duplicate FIDs are kept as aliases on the selected representative.

When choosing a representative for a duplicate concept, Bounty Core prefers lifecycle in this order:

```text
confirmed > active > dormant > completed
```

It then chooses by severity priority and finally by natural FID order.

Generated navigation uses Obsidian wikilinks for internal report links. Default canonical finding links target the packet's stable `REPORT.md`, such as `[[REPORT|D54]]`; they do not depend on lifecycle, severity, title, or absolute path prefixes.

## Evidence-only packets (opt-in)

BBH can call `add_finding(finding, program=..., family=..., lane=..., root_override=..., packet_mode="evidence_only")`. The return value has `finding["fid"]`, the stored absolute `finding["report_dir"]`, and `finding["evidence_path"]`, but no new `report_path`. For title `Owned XSS` and FID `D01`, the packet is `reports/D01-owned-xss/`. This creates `EVIDENCE.md` once and `_meta/`; it does not precreate empty `poc/` or `evidence/` folders. `EVIDENCE.md` is the investigator's claim and evidence index, not a duplicate of any attached files; add sanitized attachments under `evidence/` only when needed, and put a standalone `poc.<ext>` beside `EVIDENCE.md` and the final report. It never generates `REPORT.md` or `SUBMISSION.md`. Its investigator edits survive later operations.

For FID-based edits or submission state, call `patch_finding_by_fid(program, fid, patch, family=..., lane=..., root_override=..., packet_mode="evidence_only", refresh=True, update_current=True)`; use `update_current` only when changing current status/tier. Identity-based edits use `update_finding(identity, patch, program, family, lane, root_override=..., packet_mode="evidence_only")`. `write_report=True` on the FID patch does **not** generate a report in this mode. Existing legacy `report_path`, `REPORT.md`, and `SUBMISSION.md` are left alone.

Once Bunny has written `Path(finding["report_dir"]) / "<domain>-<vuln>-<FID>.md"`, call `record_final_finding_report(program, fid, report_path, family=..., lane=..., root_override=...)`. The file must exist in that exact FID's packet and end in `-<FID>.md`. This records `report_path` and refreshes navigation without writing or copying the file; the return value is the patched finding (or `None` if FID is absent). Before registration, navigation points to `EVIDENCE.md`; afterwards it points to the recorded final report. Both use path-qualified Obsidian links.

For an operator-confirmed submission use `patch_finding_by_fid(..., {"submission": {"state": "submitted"}}, packet_mode="evidence_only", refresh=True)`. `reports/submitted/index.md` links to the stable packet and disappears when the state changes to `not_submitted` or `dropped`; there is no physical move. Severity and category indexes only appear when populated in evidence-only mode. Never infer `report_dir` from an edited title or replace an existing FID-only packet automatically.

For a bulk navigation/backfill pass use `refresh_report_navigation_from_ledger(layout, packet_mode="evidence_only")`, where `layout = resolve_storage(program, family=..., lane=..., root_override=...)`. An in-memory index refresh is `refresh_report_indexes(layout, findings, packet_mode="evidence_only")`. Both create only missing evidence scaffolds and never rewrite legacy reports or stored `report_path` values. Always pass the mode for this route: the default ledger refresh remains the legacy report-generation flow.
