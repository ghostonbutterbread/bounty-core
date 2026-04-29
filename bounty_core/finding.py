"""Finding normalization for shared bug bounty tooling."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

VALID_STATUSES = {"raw", "confirmed", "dormant", "novel", "complete", "archive"}
SEVERITY_ORDER = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def slugify(value: Any, *, default: str = "unknown") -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip().lower()).strip("-._")
    return slug or default


def normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().upper()
    if severity in SEVERITY_ORDER:
        return severity
    aliases = {
        "P1": "CRITICAL",
        "P2": "HIGH",
        "P3": "MEDIUM",
        "P4": "LOW",
        "P5": "INFO",
        "INFORMATIONAL": "INFO",
    }
    return aliases.get(severity, "UNKNOWN")


def infer_asset(finding: dict[str, Any]) -> str:
    for key in ("asset", "url", "endpoint", "target"):
        value = str(finding.get(key) or "").strip()
        if value:
            return value
    return "unknown"


def finding_identity(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("program") or ""),
        str(finding.get("family") or ""),
        str(finding.get("lane") or ""),
        str(finding.get("type") or ""),
        str(finding.get("asset") or ""),
        str(finding.get("url") or ""),
        str(finding.get("method") or ""),
        str(finding.get("parameter") or ""),
        str(finding.get("status_code") or ""),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:20]


def normalize_finding(finding: dict[str, Any], **defaults: Any) -> dict[str, Any]:
    """Return a normalized finding without mutating the input."""
    now = utc_now()
    merged = {**defaults, **(finding or {})}

    program = str(merged.get("program") or "ghost").strip() or "ghost"
    family = str(merged.get("family") or "web_bounty").strip() or "web_bounty"
    lane = str(merged.get("lane") or "web").strip() or "web"
    vuln_type = slugify(merged.get("type") or merged.get("vuln_type") or merged.get("category") or "unknown")
    status = str(merged.get("status") or "raw").strip() or "raw"

    url = str(merged.get("url") or merged.get("endpoint") or "").strip()
    parsed = urlparse(url) if url else None
    asset = str(merged.get("asset") or "").strip()
    if not asset:
        asset = infer_asset({**merged, "url": url})
    if parsed and parsed.netloc and not merged.get("asset"):
        asset = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    normalized = dict(merged)
    normalized.update({
        "program": program,
        "family": family,
        "lane": lane,
        "type": vuln_type,
        "status": status,
        "severity": normalize_severity(merged.get("severity")),
        "title": str(merged.get("title") or f"{vuln_type.upper()} candidate on {asset}").strip(),
        "asset": asset,
        "url": url,
        "evidence": list(merged.get("evidence") or []),
        "source_tool": str(merged.get("source_tool") or "unknown").strip(),
        "source_repo": str(merged.get("source_repo") or "unknown").strip(),
        "agent": str(merged.get("agent") or merged.get("source_tool") or "unknown").strip(),
        "created_at": str(merged.get("created_at") or now),
        "updated_at": now,
    })
    normalized["identity"] = str(merged.get("identity") or finding_identity(normalized))
    return normalized
