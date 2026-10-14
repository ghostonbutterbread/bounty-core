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
