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

Current report UX centers on this reports tree:

```text
reports/
  findings/
  daily/
  categories/
  severity/
```

- `reports/{FID}/` is the immutable per-finding packet. The default flow contains the editable canonical `REPORT.md`; the opt-in evidence-only flow starts with create-only `EVIDENCE.md`. Bounty Core creates `poc/`, `evidence/`, and `_meta/` for agent artifacts. The optional `FINALIZED.md` is an explicit legacy submission-ready copy made only by `finalize_finding_report`.
- Lifecycle and severity are generated navigation views, not storage paths. `report_dir` and `report_path` remain valid when status, severity, or title changes.
- `reports/daily/{MM-DD-YYYY}/` contains date-scoped views for active, confirmed, dormant, novel, and completed findings.
- `reports/categories/{category}/` contains category indexes and per-FID links or stubs back to canonical finding reports.
- `reports/severity/{high,medium,low}/` contains severity-focused indexes.

Compatibility indexes may still be written elsewhere, but this tree is the current report UX.

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

BBH can call `add_finding(finding, program=..., family=..., lane=..., root_override=..., packet_mode="evidence_only")`. The return value has `finding["fid"]`, `finding["report_dir"]` and `finding["evidence_path"]`, but no new `report_path`. This creates `reports/<FID>/EVIDENCE.md` once plus `poc/`, `evidence/`, `_meta/`; it never generates `REPORT.md` or `SUBMISSION.md`. `EVIDENCE.md` is a create-only scaffold and its investigator edits survive later operations. The ordinary default (`packet_mode="legacy"`) is unchanged.

For FID-based edits or submission state, call `patch_finding_by_fid(program, fid, patch, family=..., lane=..., root_override=..., packet_mode="evidence_only", refresh=True, update_current=True)`; use `update_current` only when changing current status/tier. Identity-based edits use `update_finding(identity, patch, program, family, lane, root_override=..., packet_mode="evidence_only")`. `write_report=True` on the FID patch does **not** generate a report in this mode. Existing legacy `report_path`, `REPORT.md`, and `SUBMISSION.md` are left alone.

Once Bunny has written `reports/<FID>/<domain>-<vuln>-<FID>.md`, call `record_final_finding_report(program, fid, report_path, family=..., lane=..., root_override=...)`. The file must exist in that FID's packet and end in `-<FID>.md`. This records `report_path` and refreshes navigation without writing or copying the file; the return value is the patched finding (or `None` if FID is absent). Other submission fields can then be patched in evidence-only mode. Before registration, navigation points to per-FID `EVIDENCE.md`; afterwards it points to the recorded report. Both use path-qualified Obsidian links to avoid same-name packet collisions.

For a bulk navigation/backfill pass use `refresh_report_navigation_from_ledger(layout, packet_mode="evidence_only")`, where `layout = resolve_storage(program, family=..., lane=..., root_override=...)`. An in-memory index refresh is `refresh_report_indexes(layout, findings, packet_mode="evidence_only")`. Both create only missing evidence scaffolds and never rewrite legacy reports or stored `report_path` values. Always pass the mode for this route: the default ledger refresh remains the legacy report-generation flow.
