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

- `reports/findings/{lifecycle}/` contains canonical finding reports, grouped by lifecycle such as `active`, `confirmed`, `dormant`, and `completed`.
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

Generated navigation uses Obsidian wikilinks for internal report links. Canonical finding links use the target report file stem, such as `[[D54 - MEDIUM - Unauthenticated recording blob read via custom protocol token enumeration|D54]]`, so they do not depend on absolute path prefixes or vault-root-relative path choices.
