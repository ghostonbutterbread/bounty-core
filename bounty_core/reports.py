"""Human-readable report and report-navigation helpers for bounty-core."""

from __future__ import annotations

import hashlib
import re
import shutil
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

from .finding import normalize_severity, slugify
from .storage import REPORT_STATES, VULN_TYPES, StorageLayout

DAILY_REPORT_DATE_FORMAT = "%m-%d-%Y"
REPORT_NAV_GENERATED_MARKER = "<!-- generated: bounty-core-report-navigation -->"
CATEGORY_STUB_GENERATED_MARKER = "<!-- generated: bounty-core-category-link-stub -->"
FINDING_REPORT_GENERATED_MARKER = "<!-- generated: bounty-core-finding-report -->"
FINDING_REPORT_CHECKSUM_RE = re.compile(r"^<!-- generated-checksum: sha256:([0-9a-f]{64}) -->$")
LEGACY_FINDINGS_DIRNAME = "findings"
REPORT_FILENAME = "REPORT.md"
FINALIZED_REPORT_FILENAME = "FINALIZED.md"
POC_DIRNAME = "poc"
EVIDENCE_DIRNAME = "evidence"
META_DIRNAME = "_meta"
DAILY_DIRNAME = "daily"
CATEGORIES_DIRNAME = "categories"
SEVERITY_DIRNAME = "severity"
LIFECYCLE_BUCKETS = ("active", "dormant", "confirmed", "completed")
DAILY_VIEW_BUCKETS = ("active", "confirmed", "dormant", "novel", "completed")
SEVERITY_GROUPS = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_VIEW_BUCKETS = ("high", "medium", "low")
NAV_ALIASES_KEY = "_navigation_aliases"
LIFECYCLE_PRIORITY = {"confirmed": 0, "active": 1, "dormant": 2, "completed": 3}
SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def _short(value: Any, limit: int = 160) -> str:
    text = str(value or "").strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


def report_filename(finding: dict[str, Any]) -> str:
    fid = str(finding.get("fid") or finding.get("harness_fid") or "").strip()
    if fid:
        safe_fid = _safe_filename_part(fid, default="finding")
        severity = _safe_filename_part(_severity_label_for(finding), default="UNKNOWN")
        title = _safe_filename_part(_title_for(finding), default="Finding", limit=96)
        return f"{safe_fid} - {severity} - {title}.md"
    identity = slugify(finding.get("identity") or "finding", default="finding")[:12]
    title = slugify(finding.get("title") or finding.get("asset") or identity)
    return f"{identity}-{title[:80]}.md"


def _title_for(finding: dict[str, Any]) -> str:
    return str(
        finding.get("title")
        or finding.get("vulnerability_name")
        or finding.get("type")
        or "Finding"
    ).strip() or "Finding"


def _status_for(finding: dict[str, Any]) -> str:
    status = str(finding.get("status") or "").strip().lower()
    if status:
        return status
    tier = str(finding.get("review_tier") or finding.get("tier") or "").strip().upper()
    if tier == "CONFIRMED":
        return "confirmed"
    if tier.startswith("DORMANT"):
        return "dormant"
    return ""


def lifecycle_for_finding(finding: dict[str, Any]) -> str:
    status = _status_for(finding)
    tier = _review_tier_for(finding).upper()
    if status in {"complete", "completed", "archive", "archived"}:
        return "completed"
    if tier == "COMPLETED" or tier.startswith("COMPLETE") or tier.startswith("ARCHIVE"):
        return "completed"
    if status == "confirmed" or tier == "CONFIRMED":
        return "confirmed"
    if status == "dormant" or tier.startswith("DORMANT"):
        return "dormant"
    return "active"


def _review_tier_for(finding: dict[str, Any]) -> str:
    current = finding.get("current")
    for source in (finding, current if isinstance(current, dict) else {}):
        for key in ("review_tier", "tier"):
            value = str(source.get(key) or "").strip()
            if value:
                return value
    return ""


def _category_label_for(finding: dict[str, Any]) -> str:
    explicit = str(
        finding.get("report_category")
        or finding.get("category_group")
        or finding.get("surface_category")
        or ""
    ).strip()
    if explicit:
        return explicit

    haystack = " ".join(
        str(finding.get(key) or "")
        for key in (
            "agent",
            "class_name",
            "type",
            "vulnerability_name",
            "title",
            "file",
            "source",
            "sink",
            "trust_boundary",
            "flow_path",
        )
    ).lower()

    if any(marker in haystack for marker in ("renderer", "main-world", "main world", "host rpc", "bridge", "ipc", "preload")):
        return "Renderer / Privileged Bridge"
    if any(marker in haystack for marker in ("external protocol", "deeplink", "deep link", "openexternal", "protocol")):
        return "External Protocol Abuse"
    if any(marker in haystack for marker in ("information disclosure", "leak", "exfil", "screenshot", "recording", "thumbnail")):
        return "Information Disclosure"
    if any(marker in haystack for marker in ("download", "file write", "arbitrary file", "path traversal", "file read")):
        return "File / Download Abuse"
    if any(marker in haystack for marker in ("auth", "session", "login", "callback", "oauth")):
        return "Authentication / Session Flow"
    if any(marker in haystack for marker in ("update", "relaunch", "installer")):
        return "Updater / Lifecycle Abuse"

    class_name = str(finding.get("class_name") or finding.get("vuln_class") or "").strip()
    if class_name and class_name.lower() not in {"unknown", "class"}:
        return class_name.replace("-", " ").replace("_", " ").title()
    return "Other"


def _category_key_label_for(finding: dict[str, Any]) -> str:
    explicit = str(
        finding.get("report_category")
        or finding.get("category_group")
        or finding.get("surface_category")
        or finding.get("category")
        or ""
    ).strip()
    return explicit or _category_label_for(finding)


def category_report_slug(finding: dict[str, Any]) -> str:
    return slugify(_category_label_for(finding), default="other")


def canonical_finding_report_dir(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    """Return the immutable packet directory for one finding.

    Lifecycle and severity are intentionally projections, not directory names:
    a status transition must never invalidate a ledger pointer.
    """
    return layout.reports_root / _safe_fid_for(finding)


def canonical_finding_report_path(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    return canonical_finding_report_dir(layout, finding) / REPORT_FILENAME


def canonical_finalized_report_path(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    return canonical_finding_report_dir(layout, finding) / FINALIZED_REPORT_FILENAME


def _canonical_finding_report_path_for_reports_root(reports_root: Path, finding: dict[str, Any]) -> Path:
    return reports_root / _safe_fid_for(finding) / REPORT_FILENAME


def severity_report_index_path(layout: StorageLayout, severity: str) -> Path:
    slug = str(severity or "").strip().lower()
    if slug not in SEVERITY_VIEW_BUCKETS:
        raise ValueError(f"unsupported severity view: {severity!r}")
    return layout.reports_root / SEVERITY_DIRNAME / slug / "index.md"


def _coerce_report_date(value: date | datetime | str | None) -> str:
    if value is None:
        return datetime.now().strftime(DAILY_REPORT_DATE_FORMAT)
    if isinstance(value, datetime):
        return value.strftime(DAILY_REPORT_DATE_FORMAT)
    if isinstance(value, date):
        return value.strftime(DAILY_REPORT_DATE_FORMAT)
    text = str(value).strip()
    for fmt in (DAILY_REPORT_DATE_FORMAT, "%Y-%m-%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(text, fmt).strftime(DAILY_REPORT_DATE_FORMAT)
        except ValueError:
            pass
    raise ValueError(f"invalid report date: {value!r}")


def daily_report_paths(layout: StorageLayout, date_value: date | datetime | str | None = None) -> dict[str, Path]:
    daily_root = layout.reports_root / DAILY_DIRNAME / _coerce_report_date(date_value)
    paths = {
        "root": daily_root,
        "index": daily_root / "index.md",
    }
    for bucket in DAILY_VIEW_BUCKETS:
        paths[bucket] = daily_root / f"{bucket}.md"
    return paths


def obsidian_report_link(from_path: Path, to_path: Path, label: str) -> str:
    rel = _relative_path(from_path.parent, to_path)
    destination = rel.as_posix().replace("\\", "/")
    if destination.endswith(".md"):
        destination = destination[:-3]
    return obsidian_wikilink(destination, label)


def canonical_report_wikilink(to_path: Path, label: str) -> str:
    return obsidian_wikilink(to_path.stem, label)


def obsidian_wikilink(target: str, label: str) -> str:
    return f"[[{_escape_wikilink_part(target)}|{_escape_wikilink_label(label)}]]"


def relative_markdown_link(from_path: Path, to_path: Path, label: str) -> str:
    return obsidian_report_link(from_path, to_path, label)


def _escape_wikilink_part(value: Any) -> str:
    return str(value or "").strip().replace("|", "\\|").replace("]", "\\]")


def _escape_wikilink_label(value: Any) -> str:
    return _short(value, 140).replace("|", "\\|").replace("]", "\\]")


def _relative_path(from_dir: Path, to_path: Path) -> Path:
    try:
        return Path(to_path).resolve(strict=False).relative_to(Path(from_dir).resolve(strict=False))
    except ValueError:
        import os

        return Path(os.path.relpath(Path(to_path).resolve(strict=False), Path(from_dir).resolve(strict=False)))


def _reports_root_for(path: Path) -> Path | None:
    for candidate in [path, *path.parents]:
        if candidate.name == "reports":
            return candidate
    return None


def _is_under(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=False).is_relative_to(root.resolve(strict=False))
    except OSError:
        return False


def safe_symlink_or_link_stub(link_path: Path, target_path: Path, *, reports_root: Path | None = None) -> str:
    reports_root = reports_root or _reports_root_for(link_path)
    if reports_root is None:
        raise ValueError("could not infer reports_root for category link")
    link_path = link_path.expanduser()
    target_path = target_path.expanduser()
    if not _is_under(link_path, reports_root) or not _is_under(target_path, reports_root):
        raise ValueError("category link and target must stay under reports_root")

    link_path.parent.mkdir(parents=True, exist_ok=True)
    if link_path.is_symlink():
        try:
            if link_path.resolve(strict=False) == target_path.resolve(strict=False):
                return "symlink"
        except OSError:
            pass
        link_path.unlink()
    elif link_path.exists():
        if link_path.is_file() and CATEGORY_STUB_GENERATED_MARKER in link_path.read_text(encoding="utf-8", errors="replace"):
            link_path.unlink()
        else:
            return "existing"

    rel_target = _relative_path(link_path.parent, target_path)
    try:
        link_path.symlink_to(rel_target)
        return "symlink"
    except OSError:
        stub = "\n".join(
            [
                CATEGORY_STUB_GENERATED_MARKER,
                f"# {target_path.stem}",
                "",
                f"Canonical finding: {canonical_report_wikilink(target_path, target_path.stem)}",
                "",
            ]
        )
        link_path.write_text(stub, encoding="utf-8")
        return "stub"


def _render_finding_report_body(finding: dict[str, Any]) -> str:
    category = _category_label_for(finding)
    title = _title_for(finding)
    lines = [
        f"# {title}",
        "",
        f"- **FID:** {finding.get('fid') or finding.get('harness_fid') or ''}",
        f"- **Program:** {finding.get('program', '')}",
        f"- **Family/Lane:** {finding.get('family', '')}/{finding.get('lane', '')}",
        f"- **Type:** {finding.get('type', '')}",
        f"- **Status:** {_status_for(finding)}",
        f"- **Review Tier:** {_review_tier_for(finding)}",
        f"- **Category:** {category}",
        f"- **Category Slug:** {category_report_slug(finding)}",
        f"- **Severity:** {finding.get('severity', '')}",
        f"- **Class:** {finding.get('class_name') or finding.get('vuln_class') or ''}",
        f"- **File:** {finding.get('file', '')}",
        f"- **Asset:** {finding.get('asset', '')}",
        f"- **URL:** {finding.get('url', '')}",
        f"- **Source Agent/Tool:** {finding.get('agent') or finding.get('source_tool') or ''}",
        f"- **Source Repo:** {finding.get('source_repo', '')}",
        f"- **Identity:** {finding.get('identity', '')}",
        f"- **First Seen:** {finding.get('first_seen') or finding.get('created_at') or ''}",
        f"- **Last Updated:** {finding.get('last_seen') or finding.get('updated_at') or ''}",
        "",
        "## Summary",
        "",
        str(finding.get("summary") or finding.get("description") or "Candidate finding generated by tooling. Review before submission."),
        "",
        "## Source -> Sink",
        "",
        f"Source: {str(finding.get('source') or '').strip()}",
        f"Trust boundary: {str(finding.get('trust_boundary') or '').strip()}",
        f"Flow: {str(finding.get('flow_path') or '').strip()}",
        f"Sink: {str(finding.get('sink') or '').strip()}",
        "",
        "## Impact",
        "",
        str(finding.get("impact") or "None provided."),
        "",
        "## Blocking / Chain Requirements",
        "",
        f"Blocked reason: {str(finding.get('blocked_reason') or '').strip()}",
        f"Chain requirements: {str(finding.get('chain_requirements') or '').strip()}",
        "",
        "## Review Notes",
        "",
        str(finding.get("review_notes") or "None provided."),
        "",
        "## Remediation",
        "",
        str(finding.get("remediation") or "None provided."),
        "",
        "## Evidence",
        "",
    ]
    evidence = finding.get("evidence") or []
    if evidence:
        for item in evidence:
            lines.append(f"- {item}")
    else:
        lines.append("- No evidence entries were attached.")
    if finding.get("repro_steps"):
        lines.extend(["", "## Reproduction Steps", ""])
        for i, step in enumerate(finding.get("repro_steps") or [], start=1):
            lines.append(f"{i}. {step}")
    return "\n".join(lines).rstrip() + "\n"


def _generated_report_checksum(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def render_finding_report(finding: dict[str, Any]) -> str:
    body = _render_finding_report_body(finding)
    checksum = _generated_report_checksum(body)
    return f"{FINDING_REPORT_GENERATED_MARKER}\n<!-- generated-checksum: sha256:{checksum} -->\n{body}"


def is_generated_safe_finding_report(path: Path) -> bool:
    """Return True when an existing finding report is safe to regenerate."""
    if not path.exists():
        return True
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    if len(lines) < 3 or lines[0].strip() != FINDING_REPORT_GENERATED_MARKER:
        return False
    match = FINDING_REPORT_CHECKSUM_RE.match(lines[1].strip())
    if match is None:
        return False
    body = "".join(lines[2:])
    return _generated_report_checksum(body) == match.group(1)


def _safe_filename_part(value: Any, *, default: str, limit: int = 120) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[\\/:*?\"<>|\x00-\x1f]+", "-", text)
    text = re.sub(r"\s+", " ", text).strip(" .-")
    if not text:
        text = default
    return text[:limit].rstrip(" .-") or default


def _severity_label_for(finding: dict[str, Any]) -> str:
    return normalize_severity(finding.get("severity")).upper()


def _severity_group_for(finding: dict[str, Any]) -> str:
    severity = _severity_label_for(finding)
    if severity in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    if severity in {"LOW", "INFO"}:
        return "LOW"
    return "UNKNOWN"


def _finding_fid(finding: dict[str, Any]) -> str:
    return str(finding.get("fid") or finding.get("harness_fid") or "").strip()


def _safe_fid_for(finding: dict[str, Any]) -> str:
    return _safe_filename_part(_finding_fid(finding), default=Path(report_filename(finding)).stem)


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=False) == right.resolve(strict=False)
    except OSError:
        return str(left) == str(right)


def _cleanup_stale_canonical_reports(layout: StorageLayout, finding: dict[str, Any], keep_path: Path) -> None:
    fid = _safe_fid_for(finding)
    findings_root = layout.reports_root / LEGACY_FINDINGS_DIRNAME
    if not findings_root.is_dir():
        return
    for bucket in LIFECYCLE_BUCKETS:
        bucket_root = findings_root / bucket
        if not bucket_root.is_dir():
            continue
        for candidate in bucket_root.glob("*.md"):
            if not candidate.name.startswith(f"{fid} - "):
                continue
            if _same_path(candidate, keep_path):
                continue
            if is_generated_safe_finding_report(candidate):
                candidate.unlink()


def _candidate_paths_for_fid(layout: StorageLayout, finding: dict[str, Any]) -> list[Path]:
    fid = _safe_fid_for(finding)
    candidates: list[Path] = []
    for key in ("report_path", "finalized_report_path"):
        current = finding.get(key)
        if current:
            candidates.append(Path(str(current)).expanduser())
    findings_root = layout.reports_root / LEGACY_FINDINGS_DIRNAME
    packet_report = canonical_finding_report_path(layout, finding)
    if packet_report.exists():
        candidates.append(packet_report)
    if findings_root.is_dir():
        # Legacy lifecycle folders are read/migration inputs only. New writes go
        # to the stable per-FID packet above.
        for bucket in LIFECYCLE_BUCKETS:
            bucket_root = findings_root / bucket
            if bucket_root.is_dir():
                candidates.extend(sorted(bucket_root.glob(f"{fid} - *.md")))

    seen: set[str] = set()
    unique: list[Path] = []
    for path in candidates:
        try:
            key = str(path.resolve(strict=False))
        except OSError:
            key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _hand_edited_report_candidates(layout: StorageLayout, finding: dict[str, Any], desired_path: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in _candidate_paths_for_fid(layout, finding):
        if not _is_under(path, layout.reports_root):
            continue
        if not path.exists() or not path.is_file():
            continue
        if is_generated_safe_finding_report(path):
            continue
        if _same_path(path, desired_path):
            candidates.insert(0, path)
        else:
            candidates.append(path)
    return candidates


def _preserve_hand_edited_report(layout: StorageLayout, finding: dict[str, Any], desired_path: Path) -> Path | None:
    edited = _hand_edited_report_candidates(layout, finding, desired_path)
    if not edited:
        finding.pop("report_path_conflict", None)
        return None

    selected = edited[0]
    if _same_path(selected, desired_path):
        if len(edited) > 1:
            finding["report_path_conflict"] = {
                "fid": _finding_fid(finding),
                "desired_path": str(desired_path),
                "preserved_path": str(selected),
                "other_preserved_paths": [str(path) for path in edited[1:]],
                "reason": "multiple hand-authored reports exist for this FID",
            }
        else:
            finding.pop("report_path_conflict", None)
        return desired_path

    desired_path.parent.mkdir(parents=True, exist_ok=True)
    if not desired_path.exists() or is_generated_safe_finding_report(desired_path):
        if desired_path.exists():
            desired_path.unlink()
        selected.rename(desired_path)
        if len(edited) > 1:
            finding["report_path_conflict"] = {
                "fid": _finding_fid(finding),
                "desired_path": str(desired_path),
                "preserved_path": str(desired_path),
                "other_preserved_paths": [str(path) for path in edited[1:]],
                "reason": "multiple hand-authored reports exist for this FID",
            }
        else:
            finding.pop("report_path_conflict", None)
        return desired_path

    finding["report_path_conflict"] = {
        "fid": _finding_fid(finding),
        "desired_path": str(desired_path),
        "preserved_path": str(selected),
        "conflicting_path": str(desired_path),
        "other_preserved_paths": [str(path) for path in edited[1:]],
        "reason": "desired report path already contains hand-authored content",
    }
    return selected


def _ensure_finding_packet(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    """Create the stable, agent-facing container for a finding report."""
    packet_dir = canonical_finding_report_dir(layout, finding)
    for child in (packet_dir, packet_dir / POC_DIRNAME, packet_dir / EVIDENCE_DIRNAME, packet_dir / META_DIRNAME):
        child.mkdir(parents=True, exist_ok=True)
    finding["report_dir"] = str(packet_dir)
    return packet_dir


def write_finding_report(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    """Write or preserve the canonical report inside its stable packet.

    ``REPORT.md`` is the editable source; ``FINALIZED.md`` is reserved for a
    submission-ready copy. Status/severity navigation is regenerated elsewhere
    and never affects either path.
    """
    packet_dir = _ensure_finding_packet(layout, finding)
    path = packet_dir / REPORT_FILENAME
    preserved_path = _preserve_hand_edited_report(layout, finding, path)
    if preserved_path is not None:
        _cleanup_stale_canonical_reports(layout, finding, preserved_path)
        return preserved_path

    if is_generated_safe_finding_report(path):
        path.write_text(render_finding_report(finding), encoding="utf-8")
    _cleanup_stale_canonical_reports(layout, finding, path)
    return path


def finalize_finding_report(layout: StorageLayout, finding: dict[str, Any]) -> Path:
    """Create or refresh the explicit submission-ready copy of ``REPORT.md``.

    This is deliberately opt-in: drafts remain editable and agents never
    silently claim that a report is submission-ready.
    """
    report_path = write_finding_report(layout, finding)
    finalized_path = canonical_finalized_report_path(layout, finding)
    shutil.copyfile(report_path, finalized_path)
    finding["finalized_report_path"] = str(finalized_path)
    return finalized_path


def _escape_table(value: Any) -> str:
    return _short(value, 140).replace("|", "\\|")


def _index_rows(findings: list[dict[str, Any]]) -> list[str]:
    rows = ["| Severity | Type | Status | Title | Asset | Source |", "|---|---|---|---|---|---|"]
    for finding in findings:
        rows.append(
            "| {severity} | {type} | {status} | {title} | `{asset}` | {source} |".format(
                severity=finding.get("severity", ""),
                type=finding.get("type", ""),
                status=finding.get("status", ""),
                title=_short(finding.get("title"), 90).replace("|", "\\|"),
                asset=_short(finding.get("asset") or finding.get("url"), 90).replace("|", "\\|"),
                source=f"{finding.get('source_repo', '')}/{finding.get('source_tool', '')}",
            )
        )
    return rows


_DATED_BUCKET_RE = re.compile(r"^(?:\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})$")


def _is_dated_report_bucket(path: Path) -> bool:
    return bool(_DATED_BUCKET_RE.match(path.name))


def _canonical_link_for(index_path: Path, finding: dict[str, Any]) -> str:
    reports_root = _reports_root_for(index_path) or index_path.parent
    target = _report_path_for_navigation(reports_root, finding)
    label = str(finding.get("fid") or finding.get("harness_fid") or _title_for(finding)).strip()
    return canonical_report_wikilink(target, label)


def _report_path_for_navigation(reports_root: Path, finding: dict[str, Any]) -> Path:
    report_path = finding.get("report_path")
    if report_path:
        candidate = Path(str(report_path)).expanduser()
        if _is_under(candidate, reports_root):
            return candidate
    return _canonical_finding_report_path_for_reports_root(reports_root, finding)


def _link_list_item(index_path: Path, finding: dict[str, Any]) -> str:
    source = str(finding.get("agent") or finding.get("source_tool") or "").strip()
    status = _review_tier_for(finding) or _status_for(finding) or lifecycle_for_finding(finding)
    parts = [
        _short(_title_for(finding), 90),
        _severity_label_for(finding),
        _category_label_for(finding),
        status,
    ]
    if source:
        parts.append(source)
    aliases = finding.get(NAV_ALIASES_KEY) or []
    if aliases:
        parts.append(f"Aliases: {', '.join(str(alias) for alias in aliases)}")
    return f"- {_canonical_link_for(index_path, finding)} - " + " | ".join(_escape_link_text(part) for part in parts)


def _escape_link_text(value: Any) -> str:
    return _short(value, 140).replace("[", "\\[").replace("]", "\\]")


def _legacy_seeded_index_titles(path: Path) -> set[str]:
    reports_root = _reports_root_for(path)
    if reports_root is None:
        return set()
    try:
        rel = path.resolve(strict=False).relative_to(reports_root.resolve(strict=False))
    except ValueError:
        return set()

    parts = rel.parts
    if len(parts) == 2 and parts[0] == "index" and path.suffix == ".md":
        index_name = path.stem
        titles = {f"# {index_name.replace('_', ' ').title()}"}
        if index_name in REPORT_STATES:
            titles.add(f"# {index_name.title()} Findings")
            return titles
        if index_name in REPORT_STATES or index_name in VULN_TYPES:
            titles.add(f"# {index_name.upper()} Findings")
            return titles

    if len(parts) == 3 and parts[2] == "index.md":
        status, vuln_type = parts[0], parts[1]
        if status in REPORT_STATES and vuln_type in VULN_TYPES:
            return {f"# {status.title()} {vuln_type.upper()}"}

    return set()


def _is_legacy_generated_navigation(path: Path, text: str) -> bool:
    titles = _legacy_seeded_index_titles(path)
    if not titles:
        return False
    lines = [line.rstrip() for line in text.splitlines()]
    if not lines or lines[0] not in titles:
        return False
    nonblank = [line for line in lines[1:] if line.strip()]
    if not nonblank:
        return True
    table_header = ["| Severity | Type | Status | Title | Asset | Source |", "|---|---|---|---|---|---|"]
    if nonblank[:2] != table_header:
        return False
    return all(line.startswith("|") and line.endswith("|") for line in nonblank[2:])


def _is_generated_navigation_file(path: Path) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return REPORT_NAV_GENERATED_MARKER in text


def _write_generated_navigation(path: Path, text: str) -> bool:
    if REPORT_NAV_GENERATED_MARKER not in text:
        text = f"{REPORT_NAV_GENERATED_MARKER}\n{text}"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file():
            return False
        existing = path.read_text(encoding="utf-8", errors="replace")
        if REPORT_NAV_GENERATED_MARKER not in existing and not _is_legacy_generated_navigation(path, existing):
            return False
    path.write_text(text, encoding="utf-8")
    return True


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    group = _severity_group_for(finding)
    return (SEVERITY_GROUPS.index(group), _safe_fid_for(finding), _title_for(finding).lower())


def _normalize_duplicate_part(value: Any) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", str(value or "").casefold()))


def _line_duplicate_part(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        number = float(text)
    except ValueError:
        return _normalize_duplicate_part(text)
    if number.is_integer():
        return str(int(number))
    return _normalize_duplicate_part(text)


def _duplicate_group_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        _normalize_duplicate_part(_title_for(finding)),
        _normalize_duplicate_part(finding.get("file")),
        _line_duplicate_part(finding.get("line")),
        _normalize_duplicate_part(_category_key_label_for(finding)),
    )


def _natural_fid_key(finding: dict[str, Any]) -> tuple[tuple[int, Any], ...]:
    fid = _finding_fid(finding).casefold()
    if not fid:
        return ((1, ""),)
    parts: list[tuple[int, Any]] = []
    for part in re.findall(r"\d+|\D+", fid):
        if part.isdigit():
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return tuple(parts)


def _representative_sort_key(finding: dict[str, Any]) -> tuple[int, int, tuple[tuple[int, Any], ...], str]:
    lifecycle = lifecycle_for_finding(finding)
    severity = _severity_label_for(finding)
    return (
        LIFECYCLE_PRIORITY.get(lifecycle, LIFECYCLE_PRIORITY["active"]),
        SEVERITY_PRIORITY.get(severity, SEVERITY_PRIORITY["UNKNOWN"]),
        _natural_fid_key(finding),
        _title_for(finding).casefold(),
    )


def _alias_fids(findings: Iterable[dict[str, Any]], representative: dict[str, Any]) -> list[str]:
    representative_fid = _finding_fid(representative)
    aliases = {
        fid
        for finding in findings
        if (fid := _finding_fid(finding)) and fid != representative_fid
    }
    return sorted(aliases, key=lambda fid: _natural_fid_key({"fid": fid}))


def _dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for finding in findings:
        key = _safe_fid_for(finding) if _finding_fid(finding) else str(finding.get("identity") or id(finding))
        if key in seen:
            continue
        seen.add(key)
        rows.append(finding)
    return rows


def _navigation_rows(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_concept: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in _dedupe_findings(findings):
        by_concept[_duplicate_group_key(finding)].append(finding)

    rows: list[dict[str, Any]] = []
    for group in by_concept.values():
        representative = min(group, key=_representative_sort_key)
        row = dict(representative)
        aliases = sorted(
            {*_alias_fids(group, representative), *(str(alias) for alias in representative.get(NAV_ALIASES_KEY) or [])},
            key=lambda fid: _natural_fid_key({"fid": fid}),
        )
        if aliases:
            row[NAV_ALIASES_KEY] = aliases
        rows.append(row)
    return rows


def _severity_grouped_link_lines(index_path: Path, findings: Iterable[dict[str, Any]]) -> list[str]:
    rows = sorted(_dedupe_findings(findings), key=_finding_sort_key)
    by_severity: dict[str, list[dict[str, Any]]] = {group: [] for group in SEVERITY_GROUPS}
    for finding in rows:
        by_severity[_severity_group_for(finding)].append(finding)

    lines: list[str] = []
    for group in SEVERITY_GROUPS:
        items = by_severity[group]
        lines.extend([f"## {group}", ""])
        if items:
            lines.extend(_link_list_item(index_path, finding) for finding in items)
        else:
            lines.append("- None")
        lines.append("")
    return lines


def _is_novel_view_finding(finding: dict[str, Any]) -> bool:
    category = str(finding.get("category") or "").strip().lower()
    class_name = str(finding.get("class_name") or finding.get("vuln_class") or "").strip().lower()
    return category == "novel" or class_name == "novel" or _status_for(finding) == "novel"


def _date_for_finding(finding: dict[str, Any], fallback: str) -> str:
    for key in ("last_seen", "updated_at", "first_seen", "created_at"):
        value = str(finding.get(key) or "").strip()
        if not value:
            continue
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).strftime(DAILY_REPORT_DATE_FORMAT)
        except ValueError:
            try:
                return _coerce_report_date(value[:10])
            except ValueError:
                pass
    return fallback


def write_daily_report_views(
    layout: StorageLayout,
    *,
    active: list[dict[str, Any]] | None = None,
    confirmed: list[dict[str, Any]],
    dormant: list[dict[str, Any]],
    novel: list[dict[str, Any]],
    completed: list[dict[str, Any]] | None = None,
    date_value: date | datetime | str | None = None,
) -> dict[str, Path]:
    active = active or []
    completed = completed or []
    if not active and not confirmed and not dormant and not novel and not completed:
        return {}

    paths = daily_report_paths(layout, date_value)
    paths["root"].mkdir(parents=True, exist_ok=True)
    navigation_rows = _navigation_rows([*active, *confirmed, *dormant, *novel, *completed])
    buckets = {bucket: [] for bucket in DAILY_VIEW_BUCKETS}
    for finding in navigation_rows:
        buckets[lifecycle_for_finding(finding)].append(finding)
        if _is_novel_view_finding(finding):
            buckets["novel"].append(finding)
    counts = {name: len(rows) for name, rows in buckets.items()}
    all_findings = _dedupe_findings(navigation_rows)

    index_lines = [
        REPORT_NAV_GENERATED_MARKER,
        f"# Daily Reports - {paths['root'].name}",
        "",
        f"- Active: {counts['active']}",
        f"- Confirmed: {counts['confirmed']}",
        f"- Dormant: {counts['dormant']}",
        f"- Novel: {counts['novel']}",
        f"- Completed: {counts['completed']}",
        "",
        "## Views",
        "",
        f"- {obsidian_report_link(paths['index'], paths['active'], 'Active')}",
        f"- {obsidian_report_link(paths['index'], paths['confirmed'], 'Confirmed')}",
        f"- {obsidian_report_link(paths['index'], paths['dormant'], 'Dormant')}",
        f"- {obsidian_report_link(paths['index'], paths['novel'], 'Novel')}",
        f"- {obsidian_report_link(paths['index'], paths['completed'], 'Completed')}",
        "",
        "## Findings",
        "",
        *_severity_grouped_link_lines(paths["index"], all_findings),
        "",
        "## Categories",
        "",
    ]
    category_slugs = sorted({category_report_slug(finding) for finding in all_findings})
    if category_slugs:
        for slug in category_slugs:
            category_index = layout.reports_root / CATEGORIES_DIRNAME / slug / "index.md"
            index_lines.append(f"- {obsidian_report_link(paths['index'], category_index, slug)}")
    else:
        index_lines.append("- None")
    written: dict[str, Path] = {"root": paths["root"]}
    if _write_generated_navigation(paths["index"], "\n".join(index_lines).rstrip() + "\n"):
        written["index"] = paths["index"]

    for bucket, rows in buckets.items():
        path = paths[bucket]
        lines = [
            REPORT_NAV_GENERATED_MARKER,
            f"# {bucket.title()} Findings - {paths['root'].name}",
            "",
            f"Count: {len(rows)}",
            "",
            *_severity_grouped_link_lines(path, rows),
            "",
        ]
        if _write_generated_navigation(path, "\n".join(lines)):
            written[bucket] = path
    return written


def _cleanup_stale_daily_views(layout: StorageLayout, desired_dates: set[str]) -> None:
    daily_root = layout.reports_root / DAILY_DIRNAME
    if not daily_root.is_dir():
        return
    expected_names = {"index.md", *(f"{bucket}.md" for bucket in DAILY_VIEW_BUCKETS)}
    for date_root in daily_root.iterdir():
        if not date_root.is_dir():
            continue
        should_keep_date = date_root.name in desired_dates
        for path in date_root.glob("*.md"):
            if should_keep_date and path.name in expected_names:
                continue
            if _is_generated_navigation_file(path):
                path.unlink()
        try:
            date_root.rmdir()
        except OSError:
            pass


def _write_daily_groups(layout: StorageLayout, findings: list[dict[str, Any]], *, date_value: date | datetime | str | None = None) -> dict[str, Path]:
    fallback = _coerce_report_date(date_value)
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {bucket: [] for bucket in DAILY_VIEW_BUCKETS})
    for finding in _navigation_rows(findings):
        report_date = fallback if date_value is not None else _date_for_finding(finding, fallback)
        lifecycle = lifecycle_for_finding(finding)
        grouped[report_date][lifecycle].append(finding)
        if _is_novel_view_finding(finding):
            grouped[report_date]["novel"].append(finding)

    _cleanup_stale_daily_views(layout, set(grouped))

    written: dict[str, Path] = {}
    for report_date, buckets in grouped.items():
        paths = write_daily_report_views(layout, date_value=report_date, **buckets)
        for name, path in paths.items():
            if name != "root":
                written[f"daily/{report_date}/{name}"] = path
    return written


def _category_rows(index_path: Path, findings: list[dict[str, Any]]) -> list[str]:
    rows = ["| FID | Status | Severity | Last Seen | Title | Aliases |", "|---|---|---|---|---|---|"]
    for finding in findings:
        rows.append(
            "| {fid} | {status} | {severity} | {last_seen} | {title} | {aliases} |".format(
                fid=_canonical_link_for(index_path, finding),
                status=_escape_table(_review_tier_for(finding) or _status_for(finding)),
                severity=_escape_table(finding.get("severity", "")),
                last_seen=_escape_table(finding.get("last_seen") or finding.get("updated_at") or ""),
                title=_escape_table(_title_for(finding)),
                aliases=_escape_table(", ".join(str(alias) for alias in finding.get(NAV_ALIASES_KEY) or [])),
            )
        )
    return rows


def _cleanup_stale_category_entries(categories_root: Path, desired: dict[str, str]) -> None:
    if not categories_root.is_dir():
        return
    for entry in categories_root.glob("*/*.md"):
        if entry.name == "index.md":
            continue
        fid = entry.stem
        desired_slug = desired.get(fid)
        if desired_slug == entry.parent.name:
            continue
        if entry.is_symlink():
            entry.unlink()
            continue
        if entry.is_file() and CATEGORY_STUB_GENERATED_MARKER in entry.read_text(encoding="utf-8", errors="replace"):
            entry.unlink()
    desired_slugs = set(desired.values())
    for category_root in categories_root.iterdir():
        if not category_root.is_dir() or category_root.name in desired_slugs:
            continue
        index_path = category_root / "index.md"
        if _is_generated_navigation_file(index_path):
            index_path.unlink()
        try:
            category_root.rmdir()
        except OSError:
            pass


def _write_category_views(layout: StorageLayout, findings: list[dict[str, Any]]) -> dict[str, Path]:
    categories_root = layout.reports_root / CATEGORIES_DIRNAME
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    desired: dict[str, str] = {}
    for finding in _navigation_rows(findings):
        fid = str(finding.get("fid") or finding.get("harness_fid") or "").strip()
        if not fid:
            continue
        slug = category_report_slug(finding)
        by_category[slug].append(finding)
        desired[_safe_filename_part(fid, default="finding")] = slug

    _cleanup_stale_category_entries(categories_root, desired)
    written: dict[str, Path] = {}
    for slug, rows in sorted(by_category.items()):
        category_root = categories_root / slug
        category_root.mkdir(parents=True, exist_ok=True)
        index_path = category_root / "index.md"
        lines = [
            REPORT_NAV_GENERATED_MARKER,
            f"# {slug}",
            "",
            f"Count: {len(rows)}",
            "",
            *_category_rows(index_path, rows),
            "",
        ]
        if _write_generated_navigation(index_path, "\n".join(lines)):
            written[f"category/{slug}"] = index_path
        for finding in rows:
            fid = _safe_fid_for(finding)
            link_path = category_root / f"{fid}.md"
            target = _report_path_for_navigation(layout.reports_root, finding)
            safe_symlink_or_link_stub(link_path, target, reports_root=layout.reports_root)
            written[f"category/{slug}/{fid}"] = link_path
    return written


def _write_global_lifecycle_views(layout: StorageLayout, findings: list[dict[str, Any]]) -> dict[str, Path]:
    by_lifecycle: dict[str, list[dict[str, Any]]] = {bucket: [] for bucket in LIFECYCLE_BUCKETS}
    for finding in _navigation_rows(findings):
        by_lifecycle[lifecycle_for_finding(finding)].append(finding)

    written: dict[str, Path] = {}
    layout.reports_root.mkdir(parents=True, exist_ok=True)
    for bucket in LIFECYCLE_BUCKETS:
        rows = by_lifecycle[bucket]
        path = layout.reports_root / f"{bucket}.md"
        lines = [
            REPORT_NAV_GENERATED_MARKER,
            f"# {bucket.title()} Findings",
            "",
            f"Count: {len(rows)}",
            "",
            *_severity_grouped_link_lines(path, rows),
        ]
        if _write_generated_navigation(path, "\n".join(lines).rstrip() + "\n"):
            written[f"global/{bucket}"] = path
    return written


def _write_severity_views(layout: StorageLayout, findings: list[dict[str, Any]]) -> dict[str, Path]:
    by_severity: dict[str, list[dict[str, Any]]] = {bucket: [] for bucket in SEVERITY_VIEW_BUCKETS}
    for finding in _navigation_rows(findings):
        group = _severity_group_for(finding).lower()
        if group in by_severity:
            by_severity[group].append(finding)

    written: dict[str, Path] = {}
    for bucket in SEVERITY_VIEW_BUCKETS:
        rows = by_severity[bucket]
        path = severity_report_index_path(layout, bucket)
        lines = [
            REPORT_NAV_GENERATED_MARKER,
            f"# {bucket.title()} Severity Findings",
            "",
            f"Count: {len(rows)}",
            "",
            *_severity_grouped_link_lines(path, rows),
        ]
        if _write_generated_navigation(path, "\n".join(lines).rstrip() + "\n"):
            written[f"severity/{bucket}"] = path
    return written


def write_legacy_deprecation_markers(layout: StorageLayout) -> dict[str, Path]:
    written: dict[str, Path] = {}
    text = (
        "> Deprecated: New report navigation lives under `../daily/`, `../findings/`, `../categories/`, and `../severity/`.\n"
        "> This legacy status-first tree is retained for compatibility and historical runs.\n"
    )
    for bucket in ("confirmed", "dormant", "novel"):
        root = layout.reports_root / bucket
        if not root.exists():
            continue
        path = root / "README.md"
        if _write_generated_navigation(path, f"{REPORT_NAV_GENERATED_MARKER}\n{text}"):
            written[f"legacy/{bucket}/README"] = path
    return written


def _legacy_status_type_index_text(status: str, vuln_type: str, items: list[dict[str, Any]]) -> str:
    return f"{REPORT_NAV_GENERATED_MARKER}\n# {status.title()} {vuln_type.upper()}\n\n" + "\n".join(_index_rows(items)) + "\n"


def refresh_report_indexes(layout: StorageLayout, findings: list[dict[str, Any]]) -> dict[str, Path]:
    written: dict[str, Path] = {}
    by_status: dict[str, list[dict[str, Any]]] = {}
    by_type: dict[str, list[dict[str, Any]]] = {}
    status_type: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for finding in findings:
        status = slugify(finding.get("status") or "raw")
        vuln_type = slugify(finding.get("type") or "unknown")
        by_status.setdefault(status, []).append(finding)
        by_type.setdefault(vuln_type, []).append(finding)
        status_type.setdefault((status, vuln_type), []).append(finding)

    index_root = layout.reports_root / "index"
    index_root.mkdir(parents=True, exist_ok=True)

    statuses = set(REPORT_STATES) | set(by_status)
    vuln_types = set(VULN_TYPES) | set(by_type)

    for status in sorted(statuses):
        items = by_status.get(status, [])
        path = index_root / f"{status}.md"
        text = f"{REPORT_NAV_GENERATED_MARKER}\n# {status.title()} Findings\n\n" + "\n".join(_index_rows(items)) + "\n"
        if _write_generated_navigation(path, text):
            written[f"status/{status}"] = path

    for vuln_type in sorted(vuln_types):
        items = by_type.get(vuln_type, [])
        path = index_root / f"{vuln_type}.md"
        text = f"{REPORT_NAV_GENERATED_MARKER}\n# {vuln_type.upper()} Findings\n\n" + "\n".join(_index_rows(items)) + "\n"
        if _write_generated_navigation(path, text):
            written[f"type/{vuln_type}"] = path

    for status in sorted(statuses):
        if _is_dated_report_bucket(Path(status)):
            continue
        for vuln_type in sorted(vuln_types):
            items = status_type.get((status, vuln_type), [])
            path = layout.reports_root / status / vuln_type / "index.md"
            if _write_generated_navigation(path, _legacy_status_type_index_text(status, vuln_type, items)):
                written[f"status_type/{status}/{vuln_type}"] = path

    written.update(_write_global_lifecycle_views(layout, findings))
    written.update(_write_daily_groups(layout, findings))
    written.update(_write_category_views(layout, findings))
    written.update(_write_severity_views(layout, findings))
    written.update(write_legacy_deprecation_markers(layout))
    return written


def refresh_report_navigation_from_ledger(layout: StorageLayout) -> dict[str, Path]:
    import json

    ledger_path = layout.ledgers_root / "ledger.json"
    if not ledger_path.exists():
        return refresh_report_indexes(layout, [])
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    rows = [item for item in findings if isinstance(item, dict)]
    for finding in rows:
        report_path = write_finding_report(layout, finding)
        finding["report_path"] = str(report_path)
    if isinstance(payload, dict):
        ledger_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return refresh_report_indexes(layout, rows)
