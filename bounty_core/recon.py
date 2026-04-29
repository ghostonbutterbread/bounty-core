"""Recon run layout helpers for bounty-core."""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from datetime import date as date_type
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex
from typing import Any

from .storage import StorageLayout, resolve_storage


def _safe_component(value: Any, *, default: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned or default


def _validate_run_date(value: str) -> str:
    run_date = str(value or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", run_date):
        raise ValueError("date must be in YYYY-MM-DD format")
    try:
        date_type.fromisoformat(run_date)
    except ValueError as exc:
        raise ValueError("date must be a valid YYYY-MM-DD date") from exc
    return run_date


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


@dataclass(slots=True)
class ReconRun:
    tool: str
    target: str
    date: str
    run_id: str
    started_at: str
    layout: StorageLayout
    run_dir: Path
    manifest_path: Path
    raw_dir: Path
    parsed_dir: Path
    command_path: Path
    stdout_path: Path
    stderr_path: Path


def start_run(
    tool: str,
    target: str,
    program: str,
    family: str,
    lane: str,
    date: str | None = None,
    run_id: str | None = None,
    root_override: str | Path | None = None,
) -> ReconRun:
    """Create and return canonical paths for one recon tool run."""
    layout = resolve_storage(program, family=family, lane=lane, root_override=root_override, create=True)
    run_date = _validate_run_date(date or date_type.today().isoformat())
    normalized_tool = _safe_component(tool, default="tool")
    normalized_target = _safe_component(target, default="target")
    now = datetime.now(timezone.utc)
    normalized_run_id = _safe_component(run_id or f"{now.strftime('%Y%m%dT%H%M%SZ')}_{token_hex(4)}", default="run")
    started_at = now.isoformat(timespec="seconds").replace("+00:00", "Z")

    run_dir = layout.lane_root / "recon" / normalized_tool / normalized_target / "runs" / run_date / normalized_run_id
    raw_dir = run_dir / "raw"
    parsed_dir = run_dir / "parsed"
    for path in (raw_dir, parsed_dir):
        path.mkdir(parents=True, exist_ok=True)

    return ReconRun(
        tool=normalized_tool,
        target=normalized_target,
        date=run_date,
        run_id=normalized_run_id,
        started_at=started_at,
        layout=layout,
        run_dir=run_dir,
        manifest_path=run_dir / "manifest.json",
        raw_dir=raw_dir,
        parsed_dir=parsed_dir,
        command_path=run_dir / "command.txt",
        stdout_path=run_dir / "stdout.txt",
        stderr_path=run_dir / "stderr.txt",
    )


def write_manifest(run: ReconRun, manifest: dict[str, Any]) -> Path:
    """Write a manifest with required run metadata and return its path."""
    payload = dict(manifest or {})
    counts = {
        "raw_records": 0,
        "parsed_records": 0,
        "promotion_candidates": 0,
        "promoted_findings": 0,
    }
    counts.update(payload.get("counts") or {})
    payload.update(
        {
            "tool": run.tool,
            "target": run.target,
            "program": run.layout.program,
            "family": run.layout.family,
            "lane": run.layout.lane,
            "date": run.date,
            "run_id": run.run_id,
            "started_at": payload.get("started_at", run.started_at),
            "finished_at": payload.get("finished_at"),
            "exit_code": payload.get("exit_code"),
            "run_dir": str(run.run_dir),
            "raw_dir": str(run.raw_dir),
            "parsed_dir": str(run.parsed_dir),
            "command_file": str(run.command_path),
            "stdout_file": str(run.stdout_path),
            "stderr_file": str(run.stderr_path),
            "command_path": str(run.command_path),
            "stdout_path": str(run.stdout_path),
            "stderr_path": str(run.stderr_path),
            "raw_files": payload.get("raw_files", []),
            "parsed_files": payload.get("parsed_files", []),
            "counts": counts,
            "layout": run.layout.to_dict(),
        }
    )
    _write_json_atomic(run.manifest_path, payload)
    return run.manifest_path
