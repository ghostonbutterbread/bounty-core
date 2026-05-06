"""Version-aware findings ledger with snapshot sightings."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform as platform_lib
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .finding import VALID_STATUSES, normalize_finding, normalize_severity, slugify, utc_now
from .indexes import refresh_indexes
from .reports import (
    CATEGORY_STUB_GENERATED_MARKER,
    FINDING_REPORT_GENERATED_MARKER,
    REPORT_NAV_GENERATED_MARKER,
    is_generated_safe_finding_report,
    refresh_report_indexes,
    write_finding_report,
)
from .storage import DEFAULT_LANES, VALID_FAMILIES, StorageLayout, normalize_family, normalize_lane, resolve_storage


LEDGER_VERSION = 2
DEFAULT_REVIEW_TIER = "PENDING_REVIEW"
DEFAULT_STATUS = "active"
_SNAPSHOT_CHANNELS = {"stable", "beta", "dev"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_run_id() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%SZ")


def _normalize_version_label(version_label: str | None) -> str:
    explicit = str(version_label or "").strip()
    if explicit:
        return explicit
    return str(os.environ.get("SNAPSHOT_VERSION") or "").strip()


def _normalize_build_id() -> str | None:
    value = str(os.environ.get("SNAPSHOT_BUILD_ID") or "").strip()
    return value or None


def _normalize_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("win"):
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return sys.platform


def _normalize_arch() -> str:
    machine = platform_lib.machine().strip().lower()
    if machine in {"x86_64", "amd64", "x64"}:
        return "x64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine or "unknown"


def _infer_channel(version_label: str) -> str:
    explicit = str(os.environ.get("SNAPSHOT_CHANNEL") or "").strip().lower()
    if explicit in _SNAPSHOT_CHANNELS:
        return explicit

    lowered = version_label.lower()
    if any(token in lowered for token in ("beta", "b.")):
        return "beta"
    if any(token in lowered for token in ("dev", "alpha", "canary", "nightly", "preview")):
        return "dev"
    return "stable"


def _git_head(target_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(target_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    head = result.stdout.strip()
    return head or None


def _manifest_hash(target_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        relpath = path.relative_to(target_root).as_posix()
        digest.update(f"{relpath}:{stat.st_size}\n".encode("utf-8"))
    return digest.hexdigest()


def get_snapshot_identity(target_root: str | Path, version_label: str | None = None) -> dict[str, Any]:
    """Return a structured snapshot identity for version-aware ledger writes."""
    resolved_root = Path(target_root).expanduser().resolve(strict=False)
    normalized_version = _normalize_version_label(version_label)
    git_head = _git_head(resolved_root)
    manifest_hash = None if git_head else _manifest_hash(resolved_root)
    snapshot_id = git_head or manifest_hash or ""

    return {
        "version_label": normalized_version,
        "build_id": _normalize_build_id(),
        "git_head": git_head,
        "manifest_hash": manifest_hash,
        "platform": _normalize_platform(),
        "arch": _normalize_arch(),
        "channel": _infer_channel(normalized_version),
        "snapshot_id": snapshot_id,
    }


def _normalize_program(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip())
    if not cleaned:
        raise ValueError("program is required")
    return cleaned


def _normalize_root_override(
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> Path | None:
    roots = [value for value in (root_override, storage_root) if value is not None]
    if not roots:
        return None
    normalized = [Path(value).expanduser().resolve(strict=False) for value in roots]
    if len({str(value) for value in normalized}) > 1:
        raise ValueError("root_override and storage_root refer to different paths")
    return normalized[0]


def _normalize_relpath(value: Any) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


def _normalize_class_name(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    normalized = normalized.replace("_", "-")
    while "--" in normalized:
        normalized = normalized.replace("--", "-")
    return normalized


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ghost_root(
    program: str,
    lane: str = "apk",
    family: str | None = None,
    *,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> Path:
    root = _normalize_root_override(root_override, storage_root)
    layout = resolve_storage(
        _normalize_program(program),
        family=family,
        lane=lane,
        root_override=root,
        create=False,
    )
    return layout.ledgers_root


def ledger_path(
    program: str,
    lane: str = "apk",
    family: str | None = None,
    *,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> Path:
    return _ghost_root(program, lane=lane, family=family, root_override=root_override, storage_root=storage_root) / "ledger.json"


def _lock_path(
    program: str,
    lane: str = "apk",
    family: str | None = None,
    *,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> Path:
    return _ghost_root(program, lane=lane, family=family, root_override=root_override, storage_root=storage_root) / "ledger.lock"


def _default_payload(program: str) -> dict[str, Any]:
    return {
        "version": LEDGER_VERSION,
        "program": _normalize_program(program),
        "updated_at": _timestamp_iso(),
        "findings": [],
    }


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


@contextmanager
def _locked_payload(
    program: str,
    *,
    exclusive: bool,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> Iterator[dict[str, Any]]:
    program_slug = _normalize_program(program)
    root = _normalize_root_override(root_override, storage_root)
    path = ledger_path(program_slug, lane=lane, family=family, root_override=root)
    lock = _lock_path(program_slug, lane=lane, family=family, root_override=root)

    path.parent.mkdir(parents=True, exist_ok=True)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch(exist_ok=True)

    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    with lock.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), mode)
        try:
            payload = _read_payload(path, program_slug)
            yield payload
            if exclusive:
                payload["updated_at"] = _timestamp_iso()
                _write_json_atomic(path, payload)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _read_payload(path: Path, program: str) -> dict[str, Any]:
    default = _default_payload(program)
    if not path.exists():
        return default

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default

    if not isinstance(payload, dict):
        return default

    migrated = migrate_ledger_payload(program, payload)
    return migrated if isinstance(migrated, dict) else default


def _next_fid(findings: list[dict[str, Any]], prefix: str) -> str:
    normalized_prefix = (prefix or "D").strip().upper() or "D"
    highest = 0
    for finding in findings:
        fid = str(finding.get("fid") or "").strip().upper()
        if not fid.startswith(normalized_prefix):
            continue
        suffix = fid[len(normalized_prefix) :]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return f"{normalized_prefix}{highest + 1:02d}"


def _finding_key(file_value: Any, line: Any, class_name: Any, finding_type: Any) -> tuple[str, int, str, str]:
    return (
        _normalize_relpath(file_value),
        _safe_int(line),
        _normalize_class_name(class_name),
        str(finding_type or "").strip().lower(),
    )


def _finding_key_for(entry: dict[str, Any]) -> tuple[str, int, str, str]:
    return _finding_key(
        entry.get("file"),
        entry.get("line"),
        entry.get("class_name") or entry.get("vuln_class"),
        entry.get("type") or entry.get("title"),
    )


def _core_identity(program: str, family: str, lane: str, fid: str) -> str:
    return f"harness-fid:{_normalize_program(program)}:{family}:{lane}:{str(fid).strip()}"


def _core_status_for(entry: dict[str, Any]) -> str:
    status = str(entry.get("status") or "").strip().lower()
    if status in {"raw", "confirmed", "dormant", "novel", "complete", "archive"}:
        return status
    review_tier = str(entry.get("review_tier") or entry.get("tier") or "").strip().upper()
    current = entry.get("current")
    if isinstance(current, dict) and not review_tier:
        review_tier = str(current.get("review_tier") or "").strip().upper()
    if review_tier == "CONFIRMED":
        return "confirmed"
    if review_tier.startswith("DORMANT"):
        return "dormant"
    if _normalize_class_name(entry.get("class_name") or entry.get("vuln_class")) == "novel":
        return "novel"
    return "raw"


def _review_tier_for(finding: dict[str, Any]) -> str:
    for key in ("review_tier", "tier"):
        value = str(finding.get(key) or "").strip()
        if value:
            return value
    status = str(finding.get("status") or "").strip().upper()
    if status and status not in {"ACTIVE", "FIXED", "REGRESSION", "HISTORICAL"}:
        return str(finding.get("status") or "").strip()
    return DEFAULT_REVIEW_TIER


def _status_for(finding: dict[str, Any]) -> str:
    value = str(finding.get("status") or "").strip()
    return value or DEFAULT_STATUS


def _has_explicit_status(finding: dict[str, Any]) -> bool:
    return "status" in finding and bool(str(finding.get("status") or "").strip())


def _has_explicit_review_tier(finding: dict[str, Any]) -> bool:
    return any(
        key in finding and bool(str(finding.get(key) or "").strip())
        for key in ("review_tier", "tier")
    )


def _is_source_style_finding(finding: dict[str, Any]) -> bool:
    return bool(
        str(finding.get("file") or "").strip()
        and str(finding.get("class_name") or finding.get("vuln_class") or "").strip()
    )


def _fid_prefix_for(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("fid_prefix") or "").strip().upper()
    if explicit:
        return explicit
    category = str(finding.get("category") or "").strip().lower()
    class_name = _normalize_class_name(finding.get("class_name") or finding.get("vuln_class"))
    return "N" if category == "novel" or class_name == "novel" else "D"


def _normalize_sighting(sighting: Any) -> dict[str, Any] | None:
    if not isinstance(sighting, dict):
        return None

    normalized = dict(sighting)
    normalized.update(
        {
            "snapshot_id": str(sighting.get("snapshot_id") or "").strip(),
            "version_label": str(sighting.get("version_label") or "").strip(),
            "run_id": str(sighting.get("run_id") or "").strip(),
            "seen_at": str(sighting.get("seen_at") or "").strip() or _timestamp_iso(),
            "status": str(sighting.get("status") or "").strip() or DEFAULT_STATUS,
            "review_tier": str(sighting.get("review_tier") or "").strip() or DEFAULT_REVIEW_TIER,
            "agent": str(sighting.get("agent") or "").strip(),
        }
    )
    return normalized


def _current_from_sightings(sightings: list[dict[str, Any]]) -> dict[str, Any]:
    if not sightings:
        return {
            "review_tier": DEFAULT_REVIEW_TIER,
            "status": DEFAULT_STATUS,
            "version_label": "",
        }

    latest = sightings[-1]
    return {
        "review_tier": str(latest.get("review_tier") or DEFAULT_REVIEW_TIER),
        "status": str(latest.get("status") or DEFAULT_STATUS),
        "version_label": str(latest.get("version_label") or ""),
    }


def _top_level_base(entry: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    merged = dict(entry)
    merged["type"] = str(
        finding.get("type")
        or finding.get("title")
        or entry.get("type")
        or "Unknown finding"
    ).strip()
    merged["class_name"] = _normalize_class_name(
        finding.get("class_name") or finding.get("vuln_class") or entry.get("class_name")
    )
    merged["file"] = _normalize_relpath(finding.get("file") or entry.get("file"))
    merged["line"] = _safe_int(finding.get("line") if "line" in finding else entry.get("line"))
    merged["severity"] = str(finding.get("severity") or entry.get("severity") or "UNKNOWN").strip().upper()
    return merged


def _merge_extra_fields(entry: dict[str, Any], finding: dict[str, Any]) -> None:
    reserved = {
        "fid",
        "type",
        "class_name",
        "vuln_class",
        "file",
        "line",
        "severity",
        "first_seen",
        "first_snapshot",
        "last_seen",
        "last_snapshot",
        "sightings",
        "current",
        "snapshot_id",
        "version_label",
    }
    for key, value in finding.items():
        if key in reserved:
            continue
        entry[key] = value


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None

    fid = str(entry.get("fid") or "").strip()
    if not fid:
        return None

    normalized = {
        "fid": fid,
        "type": str(entry.get("type") or entry.get("title") or "Unknown finding").strip(),
        "class_name": _normalize_class_name(entry.get("class_name") or entry.get("vuln_class")),
        "file": _normalize_relpath(entry.get("file")),
        "line": _safe_int(entry.get("line")),
        "severity": str(entry.get("severity") or "UNKNOWN").strip().upper(),
        "first_seen": str(entry.get("first_seen") or entry.get("discovered_date") or _timestamp_iso()).strip(),
        "first_snapshot": str(entry.get("first_snapshot") or "").strip(),
        "last_seen": str(entry.get("last_seen") or entry.get("first_seen") or _timestamp_iso()).strip(),
        "last_snapshot": str(entry.get("last_snapshot") or entry.get("first_snapshot") or "").strip(),
    }

    sightings: list[dict[str, Any]] = []
    for raw_sighting in entry.get("sightings", []):
        normalized_sighting = _normalize_sighting(raw_sighting)
        if normalized_sighting is not None:
            sightings.append(normalized_sighting)

    normalized["sightings"] = sightings
    current = entry.get("current")
    if not isinstance(current, dict):
        current = _current_from_sightings(sightings)
    normalized["current"] = {
        "review_tier": str(current.get("review_tier") or DEFAULT_REVIEW_TIER),
        "status": str(current.get("status") or DEFAULT_STATUS),
        "version_label": str(current.get("version_label") or ""),
    }

    for key, value in entry.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def migrate_legacy_finding(entry: dict[str, Any]) -> dict[str, Any]:
    timestamp = str(entry.get("added_at") or entry.get("first_seen") or _timestamp_iso())
    review_tier = str(entry.get("review_tier") or entry.get("tier") or DEFAULT_REVIEW_TIER).strip()
    status = str(entry.get("status") or DEFAULT_STATUS).strip() or DEFAULT_STATUS
    snapshot_id = str(entry.get("snapshot_id") or entry.get("first_snapshot") or "legacy").strip()
    version_label = str(entry.get("version_label") or "").strip()
    agent = str(entry.get("agent") or "").strip()

    migrated = {
        "fid": str(entry.get("fid") or "").strip(),
        "type": str(entry.get("type") or entry.get("title") or "Unknown finding").strip(),
        "class_name": _normalize_class_name(entry.get("class_name") or entry.get("vuln_class")),
        "file": _normalize_relpath(entry.get("file")),
        "line": _safe_int(entry.get("line")),
        "severity": str(entry.get("severity") or "UNKNOWN").strip().upper(),
        "first_seen": timestamp,
        "first_snapshot": snapshot_id,
        "last_seen": str(entry.get("last_seen") or timestamp),
        "last_snapshot": str(entry.get("last_snapshot") or snapshot_id),
        "sightings": [
            {
                "snapshot_id": snapshot_id,
                "version_label": version_label,
                "run_id": str(entry.get("run_id") or "legacy").strip() or "legacy",
                "seen_at": str(entry.get("last_seen") or timestamp),
                "status": status,
                "review_tier": review_tier,
                "agent": agent,
            }
        ],
        "current": {
            "review_tier": review_tier,
            "status": status,
            "version_label": version_label,
        },
    }

    _merge_extra_fields(migrated, entry)
    return migrated


def migrate_ledger_payload(program: str, payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    migrated_findings: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("sightings"), list):
            if not str(item.get("fid") or "").strip():
                item = dict(item)
                item["fid"] = _next_fid(migrated_findings, _fid_prefix_for(item))
            normalized = _normalize_entry(item)
            if normalized is not None:
                migrated_findings.append(normalized)
            continue
        migrated = migrate_legacy_finding(item)
        if not str(migrated.get("fid") or "").strip():
            migrated["fid"] = _next_fid(migrated_findings, _fid_prefix_for(migrated))
        normalized = _normalize_entry(migrated)
        if normalized is not None:
            migrated_findings.append(normalized)

    migrated_payload = dict(payload)
    migrated_payload.update(
        {
            "version": LEDGER_VERSION,
            "program": _normalize_program(program),
            "updated_at": str(payload.get("updated_at") or _timestamp_iso()),
            "findings": migrated_findings,
        }
    )
    return migrated_payload


def _find_existing(findings: list[dict[str, Any]], finding: dict[str, Any]) -> dict[str, Any] | None:
    target = _finding_key_for(finding)
    for finding in findings:
        if _finding_key_for(finding) == target:
            return finding
    return None


def _make_sighting(
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
    *,
    seen_at: str | None = None,
) -> dict[str, Any]:
    return {
        "snapshot_id": str(snapshot_id or "").strip(),
        "version_label": str(version_label or "").strip(),
        "run_id": str(run_id or "").strip() or _default_run_id(),
        "seen_at": str(seen_at or finding.get("seen_at") or _timestamp_iso()),
        "status": _status_for(finding),
        "review_tier": _review_tier_for(finding),
        "agent": str(agent or finding.get("agent") or "").strip(),
    }


def _upsert_sighting(existing: dict[str, Any], sighting: dict[str, Any]) -> None:
    sightings = existing.setdefault("sightings", [])
    if not isinstance(sightings, list):
        sightings = []
        existing["sightings"] = sightings

    for current in sightings:
        if not isinstance(current, dict):
            continue
        if (
            str(current.get("snapshot_id") or "") == sighting["snapshot_id"]
            and str(current.get("run_id") or "") == sighting["run_id"]
        ):
            current.update(sighting)
            existing["current"] = _current_from_sightings(sightings)
            return

    sightings.append(sighting)
    existing["current"] = _current_from_sightings(sightings)


def _merge_finding(existing: dict[str, Any], finding: dict[str, Any], *, snapshot_id: str, sighting: dict[str, Any]) -> None:
    _top_level_base(existing, finding)
    updated = _top_level_base(existing, finding)
    existing.update(updated)
    _merge_extra_fields(existing, finding)
    existing["last_seen"] = sighting["seen_at"]
    existing["last_snapshot"] = snapshot_id
    if not str(existing.get("first_seen") or "").strip():
        existing["first_seen"] = sighting["seen_at"]
    if not str(existing.get("first_snapshot") or "").strip():
        existing["first_snapshot"] = snapshot_id

    current = existing.get("current")
    if isinstance(current, dict):
        if not _has_explicit_status(finding) and str(current.get("status") or "").strip():
            sighting["status"] = str(current.get("status") or "").strip()
        if not _has_explicit_review_tier(finding) and str(current.get("review_tier") or "").strip():
            sighting["review_tier"] = str(current.get("review_tier") or "").strip()

    _upsert_sighting(existing, sighting)


def _reserve_candidate(
    program: str,
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> tuple[bool, str]:
    with _locked_payload(
        program,
        exclusive=True,
        lane=lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
    ) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        existing = _find_existing(findings, finding)
        if existing is not None:
            return False, str(existing.get("fid") or "").strip()

        prefix = _fid_prefix_for(finding)
        fid = str(finding.get("fid") or "").strip() or _next_fid(findings, prefix)
        sighting = _make_sighting(finding, snapshot_id, version_label, run_id, agent)
        entry = {
            "fid": fid,
            "type": str(finding.get("type") or finding.get("title") or "Unknown finding").strip(),
            "class_name": _normalize_class_name(finding.get("class_name") or finding.get("vuln_class")),
            "file": _normalize_relpath(finding.get("file")),
            "line": _safe_int(finding.get("line")),
            "severity": str(finding.get("severity") or "UNKNOWN").strip().upper(),
            "first_seen": sighting["seen_at"],
            "first_snapshot": snapshot_id,
            "last_seen": sighting["seen_at"],
            "last_snapshot": snapshot_id,
            "sightings": [sighting],
            "current": _current_from_sightings([sighting]),
        }
        _merge_extra_fields(entry, finding)
        findings.append(entry)
        return True, fid


def ledger_add(
    program: str,
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> tuple[bool, str | None]:
    """Add or update a finding. Returns (is_new_fid, fid). Dedup is global across snapshots."""
    with _locked_payload(program, exclusive=True, lane=lane, family=family, root_override=root_override, storage_root=storage_root) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        existing = _find_existing(findings, finding)
        sighting = _make_sighting(finding, snapshot_id, version_label, run_id, agent)

        if existing is not None:
            _merge_finding(existing, finding, snapshot_id=snapshot_id, sighting=sighting)
            return False, str(existing.get("fid") or "").strip()

        prefix = _fid_prefix_for(finding)
        fid = str(finding.get("fid") or "").strip() or _next_fid(findings, prefix)
        entry = {
            "fid": fid,
            "type": str(finding.get("type") or finding.get("title") or "Unknown finding").strip(),
            "class_name": _normalize_class_name(finding.get("class_name") or finding.get("vuln_class")),
            "file": _normalize_relpath(finding.get("file")),
            "line": _safe_int(finding.get("line")),
            "severity": str(finding.get("severity") or "UNKNOWN").strip().upper(),
            "first_seen": sighting["seen_at"],
            "first_snapshot": snapshot_id,
            "last_seen": sighting["seen_at"],
            "last_snapshot": snapshot_id,
            "sightings": [sighting],
            "current": _current_from_sightings([sighting]),
        }
        _merge_extra_fields(entry, finding)
        findings.append(entry)
        return True, fid


def ledger_check(
    program: str,
    file: str,
    class_name: str,
    snapshot_id: str | None = None,
    line: Any | None = None,
    finding_type: Any | None = None,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> tuple[bool, str | None]:
    """Check if finding exists. Returns (exists, fid)."""
    with _locked_payload(program, exclusive=False, lane=lane, family=family, root_override=root_override, storage_root=storage_root) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return False, None

        if line is not None or finding_type is not None:
            existing = _find_existing(
                findings,
                {
                    "file": file,
                    "line": line,
                    "class_name": class_name,
                    "type": finding_type,
                },
            )
        else:
            target = (_normalize_relpath(file), _normalize_class_name(class_name))
            existing = next(
                (
                    finding
                    for finding in findings
                    if (_normalize_relpath(finding.get("file")), _normalize_class_name(finding.get("class_name")))
                    == target
                ),
                None,
            )
        if existing is None:
            return False, None

        if snapshot_id:
            sightings = existing.get("sightings", [])
            if not any(str(item.get("snapshot_id") or "") == str(snapshot_id) for item in sightings if isinstance(item, dict)):
                return False, None
        return True, str(existing.get("fid") or "").strip() or None


def _snapshot_match_score(entry: dict[str, Any], snapshot_id: str | None, version_label: str | None) -> tuple[int, int]:
    sightings = entry.get("sightings", [])
    has_snapshot = 0
    has_version = 0
    if isinstance(sightings, list):
        for sighting in sightings:
            if not isinstance(sighting, dict):
                continue
            if snapshot_id and str(sighting.get("snapshot_id") or "") == str(snapshot_id):
                has_snapshot = 1
            if version_label and str(sighting.get("version_label") or "") == str(version_label):
                has_version = 1
    return has_snapshot, has_version


def _sort_sightings(sightings: list[dict[str, Any]], snapshot_id: str | None, version_label: str | None) -> list[dict[str, Any]]:
    def _key(item: dict[str, Any]) -> tuple[int, int, str]:
        snapshot_match = 1 if snapshot_id and str(item.get("snapshot_id") or "") == str(snapshot_id) else 0
        version_match = 1 if version_label and str(item.get("version_label") or "") == str(version_label) else 0
        return (-snapshot_match, -version_match, str(item.get("seen_at") or ""))

    return sorted((dict(item) for item in sightings), key=_key, reverse=False)


def ledger_list(
    program: str,
    snapshot_id: str | None = None,
    version_label: str | None = None,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """List findings. If snapshot_id given, prioritize that snapshot's sightings."""
    with _locked_payload(program, exclusive=False, lane=lane, family=family, root_override=root_override, storage_root=storage_root) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return []

        result: list[dict[str, Any]] = []
        for item in findings:
            normalized = _normalize_entry(item)
            if normalized is None:
                continue
            sightings = normalized.get("sightings", [])
            if isinstance(sightings, list):
                normalized["sightings"] = _sort_sightings(sightings, snapshot_id, version_label)
            result.append(normalized)

    def _key(entry: dict[str, Any]) -> tuple[int, int, str, str]:
        has_snapshot, has_version = _snapshot_match_score(entry, snapshot_id, version_label)
        return (-has_snapshot, -has_version, str(entry.get("last_seen") or ""), str(entry.get("fid") or ""))

    return sorted(result, key=_key, reverse=False)


def ledger_get(
    program: str,
    fid: str,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> dict[str, Any] | None:
    """Get a specific finding by FID."""
    target = str(fid or "").strip()
    if not target:
        return None

    with _locked_payload(program, exclusive=False, lane=lane, family=family, root_override=root_override, storage_root=storage_root) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return None
        for finding in findings:
            if str(finding.get("fid") or "").strip() != target:
                continue
            return _normalize_entry(finding)
    return None


_FID_PATCH_PROTECTED_FIELDS = {
    "fid",
    "first_seen",
    "first_snapshot",
    "last_seen",
    "last_snapshot",
    "sightings",
    "sighting_count",
    "current",
    "snapshot_id",
    "version_label",
    "run_id",
}


def patch_finding_by_fid(
    program: str,
    fid: str,
    patch: dict[str, Any],
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    write_report: bool = False,
    refresh: bool = False,
    update_current: bool = False,
    update_sighting: bool = False,
) -> dict[str, Any] | None:
    """Patch one finding by FID without touching observation metadata by default."""
    target = str(fid or "").strip()
    if not target:
        raise ValueError("fid is required")

    root = _normalize_root_override(root_override, storage_root)
    layout = (
        resolve_storage(program, family=family, lane=lane, root_override=root, create=True)
        if write_report or refresh
        else None
    )
    normalized_patch = {
        key: value
        for key, value in _normalize_patch(patch).items()
        if key not in _FID_PATCH_PROTECTED_FIELDS
    }

    with _locked_payload(program, exclusive=True, lane=lane, family=family, root_override=root) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("fid") or "").strip() != target:
                continue
            old_report_path = Path(str(finding.get("report_path"))).expanduser() if finding.get("report_path") else None
            finding.update(normalized_patch)
            finding["fid"] = target
            if layout is not None:
                finding.setdefault("identity", _core_identity(layout.program, layout.family, layout.lane, target))
                finding.setdefault("harness_fid", target)
                finding.setdefault("program", layout.program)
                finding.setdefault("family", layout.family)
                finding.setdefault("lane", layout.lane)
                finding.setdefault("title", str(finding.get("type") or "Unknown finding").strip())
                finding.setdefault("asset", str(finding.get("file") or finding.get("url") or finding.get("endpoint") or "unknown").strip())
                finding.setdefault("source_tool", str(finding.get("agent") or "bug-bounty-harness").strip())
                if not str(finding.get("status") or "").strip():
                    finding["status"] = _core_status_for(finding)
            if update_current:
                current = finding.get("current")
                if not isinstance(current, dict):
                    current = {}
                else:
                    current = dict(current)
                review_tier = str(finding.get("review_tier") or finding.get("tier") or "").strip()
                if review_tier:
                    current["review_tier"] = review_tier
                status = str(finding.get("status") or "").strip()
                if status:
                    current["status"] = status
                finding["current"] = current
            if update_sighting:
                sightings = finding.get("sightings")
                if isinstance(sightings, list):
                    latest = next((item for item in reversed(sightings) if isinstance(item, dict)), None)
                    if latest is not None:
                        review_tier = str(finding.get("review_tier") or finding.get("tier") or "").strip()
                        if review_tier:
                            latest["review_tier"] = review_tier
                        status = str(finding.get("status") or "").strip()
                        if status:
                            latest["status"] = status
                        finding["current"] = _current_from_sightings([item for item in sightings if isinstance(item, dict)])
            if write_report and layout is not None:
                report_path = write_finding_report(layout, finding)
                finding["report_path"] = str(report_path)
                _delete_report_if_under_reports_root(layout, old_report_path, replacement=report_path)
            if refresh and layout is not None:
                refresh_indexes(layout, findings)
                refresh_report_indexes(layout, findings)
            return dict(finding)
    return None


def update_coverage_state(
    program: str,
    *,
    agent_name: str,
    surface: str,
    finding_count: int,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> dict[str, Any]:
    """Update top-level coverage support metadata without changing findings."""
    with _locked_payload(
        program,
        exclusive=True,
        lane=lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
    ) as payload:
        coverage = payload.setdefault("coverage", {})
        if not isinstance(coverage, dict):
            coverage = {}
            payload["coverage"] = coverage

        agents_run = coverage.setdefault("agents_run", {})
        if not isinstance(agents_run, dict):
            agents_run = {}
            coverage["agents_run"] = agents_run
        agents_run[str(agent_name)] = _timestamp_iso()

        surfaces_tested = coverage.setdefault("surfaces_tested", [])
        if not isinstance(surfaces_tested, list):
            surfaces_tested = []
            coverage["surfaces_tested"] = surfaces_tested
        normalized_surface = str(surface or "").strip()
        if normalized_surface and normalized_surface not in surfaces_tested:
            surfaces_tested.append(normalized_surface)
        coverage["surfaces_tested"] = sorted(str(item).strip() for item in surfaces_tested if str(item).strip())

        findings = payload.get("findings")
        finding_total = len(findings) if isinstance(findings, list) else 0
        coverage["total_findings"] = max(
            _safe_int(coverage.get("total_findings")),
            finding_total,
            max(0, int(finding_count)),
        )
        return dict(coverage)


def ledger_sightings(
    program: str,
    fid: str,
    *,
    lane: str = "apk",
    family: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> list[dict]:
    """Get all sightings for a finding."""
    finding = ledger_get(program, fid, lane=lane, family=family, root_override=root_override, storage_root=storage_root)
    if finding is None:
        return []
    sightings = finding.get("sightings", [])
    return [dict(item) for item in sightings if isinstance(item, dict)]


def _annotate_core_identity(
    program: str,
    fid: str,
    *,
    family: str,
    lane: str,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> dict[str, Any] | None:
    identity = _core_identity(program, family, lane, fid)
    with _locked_payload(program, exclusive=True, lane=lane, family=family, root_override=root_override, storage_root=storage_root) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return None
        for finding in findings:
            if str(finding.get("fid") or "").strip() != str(fid).strip():
                continue
            finding.setdefault("identity", identity)
            finding.setdefault("harness_fid", str(fid).strip())
            finding.setdefault("program", _normalize_program(program))
            finding.setdefault("family", family)
            finding.setdefault("lane", lane)
            finding.setdefault("title", str(finding.get("type") or "Unknown finding").strip())
            finding.setdefault("asset", str(finding.get("file") or finding.get("url") or finding.get("endpoint") or "unknown").strip())
            finding.setdefault("source_tool", str(finding.get("agent") or "bug-bounty-harness").strip())
            return dict(finding)
    return None


def _persist_reviewed_to_bounty_core(
    program: str,
    entry: dict[str, Any],
    *,
    family: str,
    lane: str,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> None:
    fid = str(entry.get("fid") or "").strip()
    if not fid:
        return

    _annotate_core_identity(
        program,
        fid,
        family=family,
        lane=lane,
        root_override=root_override,
        storage_root=storage_root,
    )


class VersionedFindingsLedger:
    """Compatibility wrapper for snapshot-aware ledger workflows."""

    def __init__(
        self,
        program: str,
        *,
        target_root: str | Path,
        version_label: str | None = None,
        snapshot_identity: dict[str, Any] | None = None,
        run_id: str | None = None,
        agent: str = "codex",
        lane: str = "apk",
        family: str | None = None,
        root_override: str | Path | None = None,
        storage_root: str | Path | None = None,
    ) -> None:
        self.program = _normalize_program(program)
        self.target_root = Path(target_root).expanduser().resolve(strict=False)
        self.snapshot_identity = snapshot_identity or get_snapshot_identity(
            self.target_root,
            version_label=version_label,
        )
        self.snapshot_id = str(self.snapshot_identity.get("snapshot_id") or "").strip()
        self.version_label = str(self.snapshot_identity.get("version_label") or "").strip()
        self.run_id = str(run_id or "").strip() or _default_run_id()
        self.agent = str(agent or "").strip() or "codex"
        self.lane = str(lane or "apk").strip() or "apk"
        self.family = str(family or "").strip() or None
        self.root_override = _normalize_root_override(root_override, storage_root)
        layout = resolve_storage(
            self.program,
            family=self.family,
            lane=self.lane,
            root_override=self.root_override,
            create=False,
        )
        self.storage = layout
        self.family = layout.family
        self.lane = layout.lane
        self.path = ledger_path(
            self.program,
            lane=self.lane,
            family=self.family,
            root_override=self.root_override,
        )

    def check(self, finding_dict: dict[str, Any]) -> tuple[bool, str | None, dict[str, Any]]:
        exists, fid = ledger_check(
            self.program,
            _normalize_relpath(finding_dict.get("file")),
            _normalize_class_name(finding_dict.get("class_name") or finding_dict.get("vuln_class")),
            line=finding_dict.get("line"),
            finding_type=finding_dict.get("type") or finding_dict.get("title"),
            lane=self.lane,
            family=self.family,
            root_override=self.root_override,
        )
        if exists and fid:
            current = ledger_get(self.program, fid, lane=self.lane, family=self.family, root_override=self.root_override) or {}
            merged = dict(finding_dict)
            merged.update({"fid": fid, **current})
            return True, fid, merged

        reserved, fid = _reserve_candidate(
            self.program,
            dict(finding_dict),
            self.snapshot_id,
            self.version_label,
            str(finding_dict.get("run_id") or self.run_id),
            str(finding_dict.get("agent") or self.agent),
            lane=self.lane,
            family=self.family,
            root_override=self.root_override,
        )
        merged = dict(finding_dict)
        if fid:
            merged["fid"] = fid
            merged["snapshot_id"] = self.snapshot_id
            merged["version_label"] = self.version_label
            merged["run_id"] = str(merged.get("run_id") or self.run_id)
        return (not reserved), fid, merged

    def update(self, finding_with_fid: dict[str, Any]) -> dict[str, Any]:
        _, fid = ledger_add(
            self.program,
            dict(finding_with_fid),
            self.snapshot_id,
            self.version_label,
            str(finding_with_fid.get("run_id") or self.run_id),
            str(finding_with_fid.get("agent") or self.agent),
            lane=self.lane,
            family=self.family,
            root_override=self.root_override,
        )
        target_fid = str(fid or finding_with_fid.get("fid") or "")
        entry = ledger_get(self.program, target_fid, lane=self.lane, family=self.family, root_override=self.root_override)
        if entry:
            _persist_reviewed_to_bounty_core(
                self.program,
                entry,
                family=str(self.family),
                lane=self.lane,
                root_override=self.root_override,
            )
            entry = ledger_get(self.program, target_fid, lane=self.lane, family=self.family, root_override=self.root_override)
        merged = dict(finding_with_fid)
        if entry:
            merged.update(entry)
        return merged

    def fingerprint_for(self, finding_dict: dict[str, Any]) -> str:
        return "\x1f".join(
            str(item)
            for item in _finding_key(
                finding_dict.get("file") or finding_dict.get("asset"),
                finding_dict.get("line"),
                finding_dict.get("class_name") or finding_dict.get("vuln_class"),
                finding_dict.get("type") or finding_dict.get("title"),
            )
        )

    def list_all(self) -> list[dict[str, Any]]:
        return ledger_list(
            self.program,
            snapshot_id=self.snapshot_id,
            version_label=self.version_label,
            lane=self.lane,
            family=self.family,
            root_override=self.root_override,
        )

    def get_class_context(self, vuln_class: str) -> str:
        target_class = _normalize_class_name(vuln_class)
        lines = [f"PRIOR FINDINGS FOR {target_class}:"]
        matches = [
            finding
            for finding in self.list_all()
            if _normalize_class_name(finding.get("class_name")) == target_class
        ]
        if not matches:
            lines.append("- None.")
            return "\n".join(lines)

        for finding in matches:
            current = finding.get("current", {})
            lines.append(
                f"- {finding.get('file', '')} | {finding.get('type', 'Unknown finding')} | "
                f"{current.get('version_label', '') or self.version_label} | {finding.get('last_seen', '')}"
            )
        return "\n".join(lines)


def _layout_ledger_path(layout: StorageLayout) -> Path:
    return layout.ledgers_root / "ledger.json"


def _findings_jsonl_path(layout: StorageLayout) -> Path:
    return layout.ledgers_root / "findings.jsonl"


def _append_jsonl_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=False) + "\n")


def _candidate_layouts(
    *,
    program: str | None = None,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> list[StorageLayout]:
    root = _normalize_root_override(root_override, storage_root)
    base_root = Path(root).expanduser().resolve(strict=False) if root is not None else (Path.home() / "Shared").resolve(strict=False)

    def lanes_for(item_family: str, item_program: str) -> list[str]:
        if lane is not None:
            return [normalize_lane(lane)]
        program_root = base_root / item_family / _normalize_program(item_program)
        if program_root.exists():
            lanes = sorted(path.name for path in program_root.iterdir() if path.is_dir() and path.name != "shared")
            if lanes:
                return lanes
        return sorted(DEFAULT_LANES[item_family])

    if program is not None:
        if family is not None:
            normalized_family = normalize_family(family)
            return [
                resolve_storage(program, family=normalized_family, lane=item_lane, root_override=root, create=False)
                for item_lane in lanes_for(normalized_family, program)
            ]
        layouts: list[StorageLayout] = []
        for item_family in sorted(VALID_FAMILIES):
            for item_lane in lanes_for(item_family, program):
                layouts.append(resolve_storage(program, family=item_family, lane=item_lane, root_override=root, create=False))
        return layouts

    families = [normalize_family(family)] if family else sorted(VALID_FAMILIES)
    layouts = []
    for item_family in families:
        family_root = base_root / item_family
        if not family_root.exists():
            continue
        for program_root in sorted(path for path in family_root.iterdir() if path.is_dir()):
            normalized_program = _normalize_program(program_root.name)
            for item_lane in lanes_for(item_family, normalized_program):
                layouts.append(resolve_storage(normalized_program, family=item_family, lane=item_lane, root_override=root, create=False))
    return layouts


def _filter_findings(findings: list[dict[str, Any]], filters: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not filters:
        return list(findings)

    def matches(finding: dict[str, Any]) -> bool:
        for key, expected in filters.items():
            actual = finding.get(key)
            if isinstance(expected, (set, list, tuple)):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    return [finding for finding in findings if matches(finding)]


def _same_report_path(left: Any, right: Path) -> bool:
    if not left:
        return False
    left_path = Path(str(left)).expanduser()
    try:
        return left_path.resolve(strict=False) == right.resolve(strict=False)
    except OSError:
        return str(left_path) == str(right)


def _delete_report_if_under_reports_root(layout: StorageLayout, path: Path | None, *, replacement: Path | None = None) -> None:
    if path is None:
        return
    try:
        candidate = path.expanduser().resolve(strict=False)
        reports_root = layout.reports_root.resolve(strict=False)
        replacement_resolved = replacement.resolve(strict=False) if replacement is not None else None
    except OSError:
        return
    if replacement_resolved is not None and candidate == replacement_resolved:
        return
    if not candidate.is_relative_to(reports_root):
        return
    if candidate.exists() and candidate.is_file():
        text = candidate.read_text(encoding="utf-8", errors="replace")
        if (
            REPORT_NAV_GENERATED_MARKER in text
            or CATEGORY_STUB_GENERATED_MARKER in text
            or (FINDING_REPORT_GENERATED_MARKER in text and is_generated_safe_finding_report(candidate))
        ):
            candidate.unlink()


def _normalize_patch(patch: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(patch or {})
    if "status" in normalized:
        normalized["status"] = str(normalized.get("status") or "").strip() or DEFAULT_STATUS
    if "severity" in normalized:
        normalized["severity"] = normalize_severity(normalized.get("severity"))
    if "type" in normalized:
        normalized["type"] = str(normalized.get("type") or "Unknown finding").strip()
    return normalized


def _compat_sighting(finding: dict[str, Any], *, seen_at: str) -> dict[str, Any]:
    return {
        "snapshot_id": str(finding.get("snapshot_id") or "").strip(),
        "version_label": str(finding.get("version_label") or "").strip(),
        "run_id": str(finding.get("run_id") or "").strip(),
        "seen_at": seen_at,
        "status": str(finding.get("status") or DEFAULT_STATUS).strip() or DEFAULT_STATUS,
        "review_tier": str(finding.get("review_tier") or finding.get("tier") or DEFAULT_REVIEW_TIER).strip() or DEFAULT_REVIEW_TIER,
        "agent": str(finding.get("agent") or finding.get("source_tool") or "").strip(),
        "source_tool": finding.get("source_tool"),
        "source_repo": finding.get("source_repo"),
        "url": finding.get("url"),
    }


def _ensure_v2_observation_fields(entry: dict[str, Any], *, findings: list[dict[str, Any]]) -> None:
    entry.setdefault("fid", _next_fid(findings, _fid_prefix_for(entry)))
    now = str(entry.get("updated_at") or entry.get("created_at") or utc_now())
    entry.setdefault("first_seen", now)
    entry.setdefault("first_snapshot", str(entry.get("snapshot_id") or "").strip())
    entry.setdefault("last_seen", now)
    entry.setdefault("last_snapshot", str(entry.get("snapshot_id") or "").strip())
    sightings = entry.get("sightings")
    if not isinstance(sightings, list):
        sightings = [_compat_sighting(entry, seen_at=now)]
        entry["sightings"] = sightings
    entry.setdefault("current", _current_from_sightings([item for item in sightings if isinstance(item, dict)]))


def _add_source_style_finding(
    finding: dict[str, Any],
    *,
    program: str | None = None,
    family: str = "web_bounty",
    lane: str = "web",
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    write_report: bool = True,
    refresh: bool = True,
) -> dict[str, Any]:
    root = _normalize_root_override(root_override, storage_root)
    entry = dict(finding or {})
    entry["program"] = _normalize_program(program or entry.get("program") or "ghost")
    entry["family"] = str(entry.get("family") or family or "web_bounty").strip()
    entry["lane"] = str(entry.get("lane") or lane or "web").strip()
    entry.setdefault("status", "raw")
    entry.setdefault("title", str(entry.get("type") or entry.get("title") or "Unknown finding").strip())
    entry.setdefault("asset", str(entry.get("asset") or entry.get("url") or entry.get("endpoint") or entry.get("file") or "unknown").strip())
    entry.setdefault("source_tool", str(entry.get("source_tool") or entry.get("agent") or "unknown").strip())
    entry.setdefault("source_repo", str(entry.get("source_repo") or "unknown").strip())
    entry.setdefault("created_at", str(entry.get("created_at") or utc_now()))
    entry["updated_at"] = str(entry.get("updated_at") or utc_now())

    is_new, fid = ledger_add(
        entry["program"],
        entry,
        str(entry.get("snapshot_id") or entry.get("first_snapshot") or "compat"),
        str(entry.get("version_label") or ""),
        str(entry.get("run_id") or "compat"),
        str(entry.get("agent") or entry.get("source_tool") or "bounty-core"),
        family=entry["family"],
        lane=entry["lane"],
        root_override=root,
    )
    if not fid:
        raise ValueError("ledger_add did not return a fid")

    layout = resolve_storage(entry["program"], family=entry["family"], lane=entry["lane"], root_override=root, create=True)
    old_report_path = None
    with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family, root_override=root) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings
        stored = next((item for item in findings if str(item.get("fid") or "") == str(fid)), None)
        if stored is None:
            return {"is_new": is_new, "finding": {}, "layout": layout.to_dict()}

        old_report_path = Path(str(stored.get("report_path"))).expanduser() if stored.get("report_path") else None
        stored.setdefault("identity", _core_identity(entry["program"], entry["family"], entry["lane"], fid))
        stored.setdefault("harness_fid", fid)
        stored.setdefault("program", entry["program"])
        stored.setdefault("family", entry["family"])
        stored.setdefault("lane", entry["lane"])
        stored.setdefault("title", entry.get("title"))
        stored.setdefault("asset", entry.get("asset"))
        stored.setdefault("source_tool", entry.get("source_tool"))
        stored.setdefault("source_repo", entry.get("source_repo"))
        stored.setdefault("created_at", entry.get("created_at"))
        stored["updated_at"] = entry.get("updated_at")

        _append_jsonl_event(_findings_jsonl_path(layout), {"event": "finding_seen", "is_new": is_new, "finding": dict(stored)})

        if write_report:
            report_path = write_finding_report(layout, stored)
            stored["report_path"] = str(report_path)
            _delete_report_if_under_reports_root(layout, old_report_path, replacement=report_path)

        if refresh:
            refresh_indexes(layout, findings)
            refresh_report_indexes(layout, findings)

        return {"is_new": is_new, "finding": dict(stored), "layout": layout.to_dict()}


def add_finding(
    finding: dict[str, Any],
    *,
    program: str | None = None,
    family: str = "web_bounty",
    lane: str = "web",
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    write_report: bool = True,
    refresh: bool = True,
) -> dict[str, Any]:
    """Normalize and add/update one finding while using the Ledger V2 store."""
    if _is_source_style_finding(finding or {}):
        return _add_source_style_finding(
            finding,
            program=program,
            family=family,
            lane=lane,
            root_override=root_override,
            storage_root=storage_root,
            write_report=write_report,
            refresh=refresh,
        )

    root = _normalize_root_override(root_override, storage_root)
    normalized = normalize_finding(finding, program=program or finding.get("program") or "ghost", family=family, lane=lane)
    layout = resolve_storage(normalized["program"], family=normalized["family"], lane=normalized["lane"], root_override=root, create=True)

    with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family, root_override=root) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        existing = next((item for item in findings if item.get("identity") == normalized["identity"]), None)
        is_new = existing is None
        old_report_path = None
        now = str(normalized.get("updated_at") or utc_now())
        if existing is None:
            _ensure_v2_observation_fields(normalized, findings=findings)
            findings.append(normalized)
            stored = normalized
        else:
            old_report_path = Path(str(existing.get("report_path"))).expanduser() if existing.get("report_path") else None
            existing.update({k: v for k, v in normalized.items() if k not in {"created_at", "first_seen", "first_snapshot", "sightings", "fid"}})
            existing.setdefault("sightings", []).append(_compat_sighting(normalized, seen_at=now))
            existing["last_seen"] = now
            existing["last_snapshot"] = str(normalized.get("snapshot_id") or existing.get("last_snapshot") or "").strip()
            existing["current"] = _current_from_sightings([item for item in existing.get("sightings", []) if isinstance(item, dict)])
            stored = existing

        _append_jsonl_event(_findings_jsonl_path(layout), {"event": "finding_seen", "is_new": is_new, "finding": normalized})

        if write_report:
            report_path = write_finding_report(layout, stored)
            stored["report_path"] = str(report_path)
            _delete_report_if_under_reports_root(layout, old_report_path, replacement=report_path)

        if refresh:
            refresh_indexes(layout, findings)
            refresh_report_indexes(layout, findings)

    return {"is_new": is_new, "finding": stored, "layout": layout.to_dict()}


def list_findings(
    program: str | None = None,
    family: str | None = None,
    lane: str | None = None,
    filters: dict[str, Any] | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """List findings from matching program/lane ledgers."""
    findings: list[dict[str, Any]] = []
    for layout in _candidate_layouts(program=program, family=family, lane=lane, root_override=root_override, storage_root=storage_root):
        payload = _read_payload(_layout_ledger_path(layout), layout.program)
        findings.extend(item for item in payload.get("findings", []) if isinstance(item, dict))
    return _filter_findings(findings, filters)


def get_finding(
    identity: str | None = None,
    report_path: str | Path | None = None,
    program: str | None = None,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> dict[str, Any] | None:
    """Return one finding by identity or report path."""
    if identity is None and report_path is None:
        raise ValueError("identity or report_path is required")

    target_report = Path(report_path).expanduser() if report_path is not None else None
    for finding in list_findings(program=program, family=family, lane=lane, root_override=root_override, storage_root=storage_root):
        if identity is not None and str(finding.get("identity") or "") == str(identity):
            return finding
        if target_report is not None and _same_report_path(finding.get("report_path"), target_report):
            return finding
    return None


def update_finding(
    identity: str,
    patch: dict[str, Any],
    program: str,
    family: str,
    lane: str,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    refresh: bool = True,
) -> dict[str, Any]:
    """Patch one finding while preserving immutable observation metadata."""
    root = _normalize_root_override(root_override, storage_root)
    layout = resolve_storage(program, family=family, lane=lane, root_override=root, create=True)
    protected = {"identity", "program", "family", "lane", "created_at", "first_seen", "first_snapshot", "sightings", "provenance", "fid"}
    normalized_patch = {key: value for key, value in _normalize_patch(patch).items() if key not in protected}
    now = utc_now()

    with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family, root_override=root) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings
        finding = next((item for item in findings if item.get("identity") == identity), None)
        if finding is None:
            return {"ok": False, "finding": {}, "layout": layout.to_dict()}

        before = {key: finding.get(key) for key in normalized_patch}
        old_report_path = Path(str(finding.get("report_path"))).expanduser() if finding.get("report_path") else None
        finding.update(normalized_patch)
        finding["updated_at"] = now

        report_path = write_finding_report(layout, finding)
        finding["report_path"] = str(report_path)
        _delete_report_if_under_reports_root(layout, old_report_path, replacement=report_path)

        _append_jsonl_event(
            _findings_jsonl_path(layout),
            {
                "event": "finding_updated",
                "identity": identity,
                "updated_at": now,
                "patch": normalized_patch,
                "before": before,
                "finding": finding,
            },
        )

        if refresh:
            refresh_indexes(layout, findings)
            refresh_report_indexes(layout, findings)

        return {"ok": True, "finding": finding, "layout": layout.to_dict()}


__all__ = [
    "LEDGER_VERSION",
    "VersionedFindingsLedger",
    "add_finding",
    "get_finding",
    "get_snapshot_identity",
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
    "ledger_sightings",
    "list_findings",
    "migrate_ledger_payload",
    "migrate_legacy_finding",
    "patch_finding_by_fid",
    "update_coverage_state",
    "update_finding",
]
