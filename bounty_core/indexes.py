"""Small agent-readable index generation for bounty-core ledgers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .finding import slugify
from .storage import StorageLayout


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def refresh_indexes(layout: StorageLayout, findings: list[dict[str, Any]], *, active_limit: int = 100) -> dict[str, Path]:
    """Refresh by_type, by_status, and active_slice indexes for a lane."""
    written: dict[str, Path] = {}
    by_type: dict[str, list[dict[str, Any]]] = {}
    by_status: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        by_type.setdefault(slugify(finding.get("type") or "unknown"), []).append(finding)
        by_status.setdefault(slugify(finding.get("status") or "raw", default="raw"), []).append(finding)

    for root in (layout.ledgers_root / "indexes" / "by_type", layout.ledgers_root / "indexes" / "by_status"):
        root.mkdir(parents=True, exist_ok=True)
        for path in root.glob("*.json"):
            path.unlink()

    for vuln_type, items in by_type.items():
        path = layout.ledgers_root / "indexes" / "by_type" / f"{vuln_type}.json"
        write_json(path, items)
        written[f"by_type/{vuln_type}"] = path

    for status, items in by_status.items():
        path = layout.ledgers_root / "indexes" / "by_status" / f"{status}.json"
        write_json(path, items)
        written[f"by_status/{status}"] = path

    active = [f for f in findings if slugify(f.get("status") or "raw", default="raw") not in {"complete", "archive"}]
    active = sorted(active, key=lambda f: str(f.get("updated_at") or f.get("created_at") or ""), reverse=True)[:active_limit]
    active_path = layout.ledgers_root / "indexes" / "active_slice.json"
    write_json(active_path, active)
    written["active_slice"] = active_path
    return written
