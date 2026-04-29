# Bounty Core Skill Ledger CLI Spec

## Status

Draft: 2026-04-29

Reviewer status: reviewed; blockers incorporated as requirements

## Background / Brainstorm Summary

Ryushe uses `/me` as an agent briefing skill during bug bounty work. The skill explains how agents should coordinate with Ghost's ledger, dedupe findings, mark coverage, and write reports as if they were participating in an orchestrated team such as `zero_day_team` or `apk_team`.

After extracting shared storage/ledger/report logic into `bounty-core`, the important backend path is now largely centralized, but `/me` still tells agents to call a harness-local script:

```bash
python3 me_ledger.py check ...
python3 me_ledger.py add ...
python3 me_ledger.py cover ...
```

That is fragile because an agent may run from any working directory. The desired direction is not to move `/me` into `bounty-core`. `/me` remains a skill/instruction wrapper. Instead, `bounty-core` should expose stable CLI commands that can be installed with pip and called from anywhere.

## Goal

Make ledger/report/coverage coordination available as a normal installed command so any skill, agent, harness, or standalone tool can integrate with Ghost's canonical bug bounty system without knowing repository layout.

Desired outcome:

```bash
python3 -m pip install -e /path/to/bounty-core

bounty-core ledger check ...
bounty-core ledger add ...
bounty-core coverage mark ...
bounty-core report path ...
```

Then `/me` can instruct agents to use `bounty-core ...` instead of a local `me_ledger.py` path.

## Non-goals

- Do not move the `/me` skill into `bounty-core`.
- Do not make every bounty skill depend on the harness repo.
- Do not require agents to run from `bug_bounty_harness/agents`.
- Do not ask agents to edit ledger JSON directly.
- Do not require agents to know low-level ledger file format details.
- Do not replace orchestrated team flows; this CLI is a stable manual/agent integration surface.

## Current State

Current `/me` path:

```text
/me skill
  -> tells agent: python3 me_ledger.py ...

bug_bounty_harness/agents/me_ledger.py
  -> imports agents.ledger

bug_bounty_harness/agents/ledger.py
  -> ensure_bounty_core_importable()
  -> imports bounty_core.ledger ledger_add/check/get/list/etc.
```

So the real ledger logic already goes through `bounty_core` indirectly, but the user-facing command remains repo-local and fragile.

## Proposed Architecture

```text
bug_bounty_harness/skills/me/SKILL.md
  = briefing/instructions/workflow
  = tells agents which stable Bounty Core commands to run

bounty-core package
  = installed Python package + CLI entrypoint
  = canonical storage resolution, ledger dedupe/write/read, coverage state, report paths/rendering

bug_bounty_harness/agents/me_ledger.py
  = temporary compatibility wrapper
  = may delegate to Bounty Core CLI/API until retired
```

Dependency shape:

```text
/me skill ──instructs──> bounty-core CLI ──uses──> bounty_core.{storage,ledger,reports,indexes}
```

## Installation Model

`bounty-core` should be installable as a Python package:

```bash
python3 -m pip install -e ~/projects/bounty-core
```

`pyproject.toml` should expose a console entrypoint:

```toml
[project.scripts]
bounty-core = "bounty_core.cli:main"
```

Optional shorter alias later:

```toml
bounty = "bounty_core.cli:main"
```

The CLI should also work as a module for environments where console scripts are not on PATH:

```bash
python3 -m bounty_core.cli ledger check ...
```

## CLI Command Surface

### Global Flags

All subcommands that touch storage should accept:

```text
--program <slug>              required unless inferable by context
--family web_bounty|binaries  optional if lane/hunt type can infer safely
--lane web|api|apk|exe|mac    optional with safe defaults only where explicit
--root <path>                 optional explicit Shared root override for tests/local runs
--json                        output machine-readable JSON (default for agent-facing commands)
--pretty                      pretty JSON output
```

Rules:

- Explicit `--family` and `--lane` win.
- Unknown custom lanes require explicit `--family`.
- No command should write to legacy `~/Shared/bounty_recon/...` paths.
- Commands must return non-zero on invalid input or failed writes.

### `ledger check`

Purpose: dedupe before adding a finding.

Example:

```bash
bounty-core ledger check \
  --program notion \
  --family web_bounty \
  --lane web \
  --file src/preload.js \
  --class-name native-module-abuse \
  --type "SQLite IPC"
```

Output:

```json
{
  "exists": true,
  "fid": "D03",
  "finding": {"fid": "D03", "type": "SQLite IPC"}
}
```

Implementation target:

- call `bounty_core.ledger.ledger_check(...)`
- if duplicate and FID exists, call `ledger_get(...)` for full row

### `ledger add`

Purpose: reserve/add a finding through canonical ledger logic.

Flag mode for simple findings:

```bash
bounty-core ledger add \
  --program notion \
  --family web_bounty \
  --lane web \
  --file src/preload.js \
  --class-name native-module-abuse \
  --type "SQLite IPC" \
  --severity HIGH \
  --agent codex \
  --summary "Attacker-controlled IPC reaches SQLite sink"
```

JSON mode for richer findings:

```bash
bounty-core ledger add \
  --program notion \
  --family web_bounty \
  --lane web \
  --json-file finding.json
```

Output:

```json
{
  "added": true,
  "duplicate": false,
  "fid": "D07",
  "finding": {"fid": "D07", "type": "SQLite IPC"},
  "ledger_path": "/home/ryushe/Shared/web_bounty/notion/web/ledgers/ledger.json"
}
```

Implementation target:

- normalize/coerce incoming fields through `bounty_core.finding` where possible
- call `bounty_core.ledger.ledger_add(...)`
- call `ledger_get(...)` after add so the returned object matches canonical stored state

### `ledger patch`

Purpose: update a reserved finding after review or manual refinement.

```bash
bounty-core ledger patch \
  --program notion \
  --family web_bounty \
  --lane web \
  --fid D07 \
  --json-file reviewed-finding.json \
  --write-report \
  --refresh-indexes
```

Implementation target:

- call `bounty_core.ledger.patch_finding_by_fid(...)`
- support `--write-report`, `--refresh-indexes`, `--update-current`, `--update-sighting`
- return patched finding or clear error if FID does not exist

### `ledger get`

```bash
bounty-core ledger get --program notion --lane web --fid D07
```

### `ledger list`

```bash
bounty-core ledger list --program notion --family web_bounty --lane web --status confirmed
```

Filtering should start conservative:

- `--snapshot-id`
- `--version-label`
- `--status`
- `--type`
- `--class-name`
- `--min-severity` can be later

### `coverage mark`

Purpose: mark a surface/file/class as explored.

```bash
bounty-core coverage mark \
  --program notion \
  --family web_bounty \
  --lane web \
  --file src/preload.js \
  --class-name native-module-abuse \
  --agent codex
```

This should use the same coverage state model that teams use, not ad hoc JSON writes.

### `report path`

Purpose: tell an agent where to write supporting report notes/artifacts without guessing storage paths.

```bash
bounty-core report path \
  --program notion \
  --family web_bounty \
  --lane web \
  --fid D07 \
  --title "SQLite IPC"
```

Output:

```json
{
  "report_path": "/home/ryushe/Shared/web_bounty/notion/web/reports/raw/sqlite-ipc/D07_sqlite-ipc.md",
  "reports_root": "/home/ryushe/Shared/web_bounty/notion/web/reports"
}
```

### `doctor`

Purpose: help agents self-check install and path issues.

```bash
bounty-core doctor
```

Checks:

- package import works
- console script path is visible
- storage root is writable
- known families/lanes are available
- optional: current `bounty-core` version

## Rich Finding Data / Formatting Concern

Ryushe's question: when an agent updates the ledger, there may be a lot of data. Can the agent format it correctly?

Answer: agents should not be expected to hand-format the ledger file. They should provide structured finding data to the CLI, and Bounty Core should normalize, validate, and write the canonical ledger shape.

Design rules:

1. **Never edit `ledger.json` directly.**
2. **Small findings may use flags.**
3. **Rich findings should use JSON input.**
4. **Bounty Core owns canonical formatting and defaults.**
5. **Invalid or incomplete input fails loudly with a useful message.**

Recommended JSON input shape:

```json
{
  "type": "SQLite IPC",
  "title": "SQLite IPC reaches privileged query sink",
  "class_name": "native-module-abuse",
  "file": "src/preload.js",
  "line": 42,
  "severity": "HIGH",
  "review_tier": "PENDING_REVIEW",
  "status": "active",
  "agent": "codex",
  "summary": "Attacker-controlled IPC parameter reaches SQLite query builder.",
  "description": "Longer explanation...",
  "evidence": [
    "src/preload.js:42",
    "logs/repro.txt"
  ],
  "repro_steps": [
    "Open renderer devtools",
    "Send crafted IPC payload",
    "Observe privileged SQLite query"
  ],
  "impact": "Potential local privilege boundary bypass inside app context.",
  "confidence": "MEDIUM",
  "source": "ipc handler",
  "sink": "sqlite query",
  "trust_boundary": "renderer-to-main"
}
```

CLI validation should require at minimum:

- `type`
- `class_name`
- `file`
- `severity` for add
- `fid` for patch, either flag or JSON field

The CLI should fill or normalize:

- `program`
- `family`
- `lane`
- `fid` where reserved by ledger
- `agent`
- `run_id`
- `snapshot_id`
- `version_label`
- timestamps where core ledger already owns them
- canonical severity/status strings
- canonical storage/report paths

For long text, agents should use `--json-file` instead of shell flags to avoid quoting problems.

## `/me` Skill Update

Current wording should change from local script references to Bounty Core CLI references.

Before:

```markdown
python3 me_ledger.py check --program {program} --file <file> --class-name <class>
```

After:

```markdown
bounty-core ledger check --program {program} --file <file> --class-name <class> --type "<type>"
```

Add install/bootstrap instruction:

```markdown
If `bounty-core doctor` fails, install Bounty Core:
`python3 -m pip install -e /path/to/bounty-core`
```

If the skill knows the common local layout, it may say:

```bash
python3 -m pip install -e ~/projects/bounty-core
```

But it should not require that layout if the package is already installed.

## Compatibility Plan

1. Add `bounty_core/cli.py` with subcommands above.
2. Add `[project.scripts] bounty-core = "bounty_core.cli:main"`.
3. Add tests in `bounty-core/tests/test_cli.py` using temporary roots.
4. Update `bug_bounty_harness/skills/me/SKILL.md` to call `bounty-core ...`.
5. Keep `bug_bounty_harness/agents/me_ledger.py` as a wrapper temporarily.
6. Update harness tests to assert `/me` docs mention `bounty-core` and no longer rely on cwd-local `me_ledger.py` as the primary instruction.
7. After one or two successful hunts, either retire `me_ledger.py` or leave it as deprecated compatibility.

## Test Plan

Bounty Core tests:

- `bounty-core doctor` exits 0 in editable install/dev path.
- `ledger add` with flags writes a finding to a temp root and returns JSON with FID.
- `ledger check` finds the added finding.
- `ledger add --json-file` accepts rich data and preserves evidence/repro fields.
- `ledger patch --fid ... --json-file ... --write-report --refresh-indexes` updates stored finding and writes reports/indexes.
- `ledger list` filters by snapshot/status/class/type.
- invalid JSON returns non-zero and no ledger mutation.
- missing required fields return non-zero and no ledger mutation.
- custom lane without family fails.

Harness tests:

- `/me` skill references `bounty-core ledger check/add`.
- legacy `me_ledger.py` still works if called directly.
- no active skill instruction tells agents to edit ledger JSON directly.

## Open Design Questions

1. CLI name: `bounty-core` vs `bounty`.
   - Recommendation: start with `bounty-core`; optionally add `bounty` alias later.
2. Should `coverage mark` live under `coverage` or `ledger cover`?
   - Recommendation: `coverage mark`, because coverage is related but not a finding ledger write.
3. Should report writing be fully exposed now?
   - Recommendation: expose `report path` first, then `report write` once `bounty_core.reports` migration is complete.
4. Should `/me` mention `python3 -m bounty_core.cli` fallback?
   - Recommendation: yes, as a fallback if the console script is not on PATH.

## Recommended First Implementation Slice

Smallest useful implementation:

1. Add `bounty_core/cli.py`.
2. Implement:
   - `doctor`
   - `ledger check`
   - `ledger add`
   - `ledger get`
   - `ledger list`
3. Add console script in `pyproject.toml`.
4. Add tests for those commands.
5. Update `/me` skill to use the new commands.

Second slice:

1. Add `ledger patch`.
2. Add `coverage mark`.
3. Add `report path`.
4. Deprecate or wrap `agents/me_ledger.py`.

## Reviewer Feedback Incorporated — 2026-04-29

Reviewer verdict: directionally sound, but the rich ledger update contract needed to be stricter before implementation. The following constraints are accepted into the spec and should be treated as requirements for implementation.

### Required CLI Input Schema

The CLI must validate input before calling ledger APIs. Agents are allowed to provide rich data, but only through a documented schema.

#### Allowed Fields for `ledger add --json-file`

Required:

- `type`: string, human-readable display label. Example: `SQLite IPC`.
- `class_name`: string, normalized to lower-case slug-ish class name. Example: `native-module-abuse`.
- `file`: string, normalized relative path or absolute evidence path.
- `severity`: string, normalized through Bounty Core severity aliases.

Optional scalar strings:

- `title`
- `summary`
- `description`
- `impact`
- `confidence`
- `status`
- `review_tier`
- `agent`
- `source_tool`
- `source_repo`
- `url`
- `endpoint`
- `asset`
- `method`
- `parameter`
- `source`
- `sink`
- `trust_boundary`
- `flow_path`
- `exploitability`
- `fid_prefix`

Optional integers:

- `line`
- `status_code`

Optional string arrays:

- `evidence`
- `repro_steps`
- `references`
- `tags`

Optional object fields, preserved but validated as JSON objects:

- `metadata`
- `review`
- `tool_output`

Unknown-field policy for v1:

- Default: reject unknown fields with a clear error and no mutation.
- Optional future flag: `--allow-extra` may preserve unknown fields under `metadata.extra`, but should not silently write arbitrary top-level keys.

#### Allowed Fields for `ledger patch --json-file`

Patch may update descriptive/review/reporting fields:

- `title`
- `summary`
- `description`
- `impact`
- `confidence`
- `status`
- `review_tier`
- `severity`
- `evidence`
- `repro_steps`
- `references`
- `tags`
- `metadata`
- `review`
- `tool_output`
- `source`
- `sink`
- `trust_boundary`
- `flow_path`
- `exploitability`

Patch must reject identity/dedupe fields by default:

- `fid`
- `file`
- `line`
- `class_name`
- `type`
- `program`
- `family`
- `lane`
- `first_seen`
- `first_snapshot`
- `last_seen`
- `last_snapshot`
- `sightings`
- `sighting_count`
- `current`
- `snapshot_id`
- `version_label`
- `run_id`

Reason: changing identity fields after reservation can alter dedupe/report/index meaning. If we later need that behavior, add an explicit high-friction flag such as `--allow-identity-change` and log the before/after identity in history.

### Type Semantics

The CLI `type` field is a human-readable display label, not a slug.

- Example accepted input: `SQLite IPC`.
- Ledger should preserve display label in `type` unless existing ledger API semantics intentionally normalize it.
- If a slug is needed for file paths or indexes, it should be derived separately as `type_slug` or local path slug, not overwrite display `type`.

Implementation note: do not blindly pass CLI findings through `bounty_core.finding.normalize_finding()` if that would slugify display `type`. Add a CLI-specific normalizer or update core normalization so display type and slug are separate.

### Surface Format for `coverage mark`

`coverage mark` should convert inputs into a deterministic surface string before calling `update_coverage_state()`.

Recommended format:

```text
<class_name>:<normalized_file>
```

If a line is provided:

```text
<class_name>:<normalized_file>:<line>
```

Examples:

```text
native-module-abuse:src/preload.js
provider:AndroidManifest.xml:42
```

The CLI output should include both the computed `surface` and the returned coverage state.

### Report Path Semantics

`report path` should not write report content in v1.

It should:

- resolve canonical storage
- create the containing directory only if `--create-dirs` is passed
- return the path that matches Bounty Core's report filename/path algorithm
- never create or mutate ledger entries

`report write` can be a later explicit command once `bounty_core.reports` fully owns report rendering.

### Revised First Implementation Slice

The first implementation slice should be a minimal complete `/me` loop, not only read/add:

1. Add `bounty_core/cli.py`.
2. Add `[project.scripts] bounty-core = "bounty_core.cli:main"`.
3. Implement:
   - `doctor`
   - `ledger check`
   - `ledger add --json-file`
   - `ledger get`
   - `ledger patch --json-file`
4. Add CLI schema validation before ledger API calls.
5. Add tests proving:
   - invalid JSON fails with no mutation
   - wrong field types fail with no mutation
   - missing required fields fail with no mutation
   - unknown fields fail with no mutation
   - identity-field patch attempts fail with no mutation
   - display `type` is preserved as display text
6. Update `/me` to prefer `bounty-core`, with `python3 -m bounty_core.cli` fallback.

`coverage mark` and `report path` may be slice two only if `/me` clearly says those commands are pending and keeps the old compatibility wrapper for those specific actions until implemented.

## Scope Correction — `/me` Should Run the Team Backend Flow, Not Just Ledger Commands

Ryushe clarified that the goal is broader than a portable ledger CLI.

The desired `/me` behavior is to let manually-run or separately-spawned agents submit findings into the same backend flow used by `apk_team` and `zero_day_team`:

```text
agent/manual finding
  -> reserve/dedupe ledger identity
  -> stage/report-person review
  -> reviewer determines whether a PoC can be made / whether evidence is sufficient
  -> promote to confirmed/dormant/novel/rejected
  -> update ledger by FID
  -> write report/indexes from promoted findings only
  -> preserve traceability and dedupe behavior
```

So the CLI should not be only a set of primitive ledger operations. It should expose both:

1. **Primitive commands** for lower-level integration/debugging:
   - `ledger check`
   - `ledger add`
   - `ledger patch`
   - `ledger get/list`

2. **Pipeline commands** that mirror the team backend flow:
   - `finding submit`
   - `finding review`
   - `finding promote`
   - eventually `finding finalize` or `pipeline run`

## Proposed Higher-Level CLI Surface

### `finding submit`

Accept a manual/agent finding, validate schema, reserve/dedupe in the ledger, and return a FID or duplicate result.

```bash
bounty-core finding submit \
  --program notion \
  --family web_bounty \
  --lane web \
  --json-file finding.json
```

Responsibilities:

- validate rich finding schema
- normalize storage/family/lane
- reserve/dedupe through canonical ledger identity
- attach run/snapshot/agent metadata where available
- return canonical stored/reserved finding
- do not mark confirmed yet

### `finding review`

Run the same review gate semantics used by teams against one or more submitted findings.

```bash
bounty-core finding review \
  --program notion \
  --family web_bounty \
  --lane web \
  --fid D07
```

or:

```bash
bounty-core finding review --program notion --input submitted-findings.jsonl
```

Responsibilities:

- use the shared review/report-person logic where possible
- determine `CONFIRMED`, `DORMANT`, `NOVEL`, or `REJECTED`
- capture reviewer notes and PoC/evidence reasoning
- do not write final report indexes until promotion succeeds

### `finding promote`

Patch reviewed finding results into the ledger and update reports/indexes only from successfully promoted FID-backed rows.

```bash
bounty-core finding promote \
  --program notion \
  --family web_bounty \
  --lane web \
  --fid D07 \
  --review-json reviewed-finding.json \
  --write-report \
  --refresh-indexes
```

Responsibilities:

- protect identity fields unless explicitly overridden
- call canonical FID patch/update logic
- write reports/indexes only after successful ledger update
- preserve same traceability behavior as APK/0day promotion helper

### `pipeline run` / `finding finalize` (future)

A single higher-level command may eventually do the whole loop:

```bash
bounty-core pipeline run \
  --program notion \
  --family web_bounty \
  --lane web \
  --json-file finding.json \
  --review
```

This should be delayed until primitive submit/review/promote commands are stable and tested.

## `/me` Skill Should Describe This Team-Like Flow

The `/me` skill should instruct agents to behave like a single team participant:

1. Draft finding JSON using the accepted schema.
2. Submit it:
   `bounty-core finding submit --program {program} --json-file finding.json`
3. If duplicate, use returned FID/context and avoid re-reporting unless there is new evidence.
4. If new, either:
   - ask/trigger review through `bounty-core finding review`, or
   - leave it as pending review for Ghost/report-person flow.
5. Promote reviewed findings only through Bounty Core, not by writing reports or ledger files manually.

This keeps manually coordinated agents, `/me` agents, and orchestrated teams using the same backend lifecycle.

## Implementation Implication

The earlier `ledger check/add/patch` CLI is still useful, but it is not sufficient as the final `/me` interface. The implementation should prioritize a high-level `finding submit` command after or alongside the primitive ledger commands, because `/me` is trying to replicate the team lifecycle, not expose raw ledger plumbing.

Revised recommended implementation order:

1. Implement strict schema validation shared by primitive and pipeline commands.
2. Implement `ledger check/get/list` for diagnostics.
3. Implement `finding submit` as the primary `/me` write path.
4. Implement `finding promote` using the same post-review promotion rules as APK/0day.
5. Decide whether `finding review` can live fully in Bounty Core now or should initially call a harness-provided reviewer adapter until review logic is migrated.
6. Update `/me` to describe the team-like lifecycle and use `finding submit` first, not raw `ledger add` as the primary path.
