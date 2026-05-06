"""Resolve canonical target storage identity from explicit and inferred signals."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .storage import (
    BINARIES_FAMILY,
    DEFAULT_LANES,
    WEB_FAMILY,
    normalize_family,
    normalize_lane,
    normalize_program,
    resolve_family_lane,
)


@dataclass(frozen=True, slots=True)
class TargetIdentityEvidence:
    """A single signal used while routing a target to canonical storage."""

    source: str
    family: str
    lane: str
    detail: str
    target_kind: str | None = None
    path: Path | None = None
    storage_root: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source": self.source,
            "family": self.family,
            "lane": self.lane,
            "detail": self.detail,
        }
        if self.target_kind:
            payload["target_kind"] = self.target_kind
        if self.path is not None:
            payload["path"] = str(self.path)
        if self.storage_root is not None:
            payload["storage_root"] = str(self.storage_root)
        return payload


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """Canonical target identity selected for storage and report routing."""

    program: str
    family: str
    lane: str
    target_kind: str | None
    evidence: tuple[TargetIdentityEvidence, ...]
    storage_root: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "program": self.program,
            "family": self.family,
            "lane": self.lane,
            "evidence": [item.to_dict() for item in self.evidence],
        }
        if self.target_kind:
            payload["target_kind"] = self.target_kind
        if self.storage_root is not None:
            payload["storage_root"] = str(self.storage_root)
        return payload


_TARGET_KIND_ROUTES: dict[str, tuple[str, str, str]] = {
    "web": (WEB_FAMILY, "web", "web"),
    "website": (WEB_FAMILY, "web", "web"),
    "web-app": (WEB_FAMILY, "web", "web"),
    "webapp": (WEB_FAMILY, "web", "web"),
    "api": (WEB_FAMILY, "api", "api"),
    "rest-api": (WEB_FAMILY, "api", "api"),
    "graphql": (WEB_FAMILY, "api", "api"),
    "apk": (BINARIES_FAMILY, "apk", "apk"),
    "aab": (BINARIES_FAMILY, "apk", "apk"),
    "android": (BINARIES_FAMILY, "apk", "apk"),
    "exe": (BINARIES_FAMILY, "exe", "exe"),
    "pe": (BINARIES_FAMILY, "exe", "exe"),
    "windows": (BINARIES_FAMILY, "exe", "exe"),
    "windows-exe": (BINARIES_FAMILY, "exe", "exe"),
    "electron": (BINARIES_FAMILY, "exe", "electron-exe"),
    "electron-exe": (BINARIES_FAMILY, "exe", "electron-exe"),
    "desktop-exe": (BINARIES_FAMILY, "exe", "exe"),
    "mac": (BINARIES_FAMILY, "mac", "mac"),
    "macos": (BINARIES_FAMILY, "mac", "mac"),
    "darwin": (BINARIES_FAMILY, "mac", "mac"),
    "dmg": (BINARIES_FAMILY, "mac", "mac"),
    "app": (BINARIES_FAMILY, "mac", "mac"),
    "mac-app": (BINARIES_FAMILY, "mac", "mac"),
}

_IMPRECISE_HINTS = {"", "auto", "source", "binary", "binaries", "0day", "0day_team", "zero_day_team"}


def resolve_target_identity(
    *,
    program: str,
    family: str | None = None,
    lane: str | None = None,
    target_kind: str | None = None,
    wrapper_hint: str | None = None,
    intent_text: str | None = None,
    target_path: str | Path | None = None,
    output_root: str | Path | None = None,
    default_family: str | None = None,
    default_lane: str | None = None,
    hunt_type: str | None = None,
) -> TargetIdentity:
    """Resolve the canonical family/lane for a target.

    Precedence is intentionally ordered from explicit caller intent to weak
    wrapper defaults:
    explicit family/lane, precise kind hints, natural language intent,
    canonical path shape, artifact markers, then wrapper/default fallback.
    """

    program_slug = normalize_program(program)
    family_filter = normalize_family(family) if family else None

    if lane:
        resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane)
        evidence = TargetIdentityEvidence(
            source="explicit",
            family=resolved_family,
            lane=resolved_lane,
            detail="explicit family/lane" if family else "explicit lane",
            target_kind=_canonical_kind(target_kind),
        )
        return _identity(program_slug, evidence)

    kind_evidence = _evidence_from_kind(target_kind, source="target_kind")
    if _matches_family_filter(kind_evidence, family_filter):
        return _identity(program_slug, kind_evidence)

    intent_evidence = _evidence_from_intent(intent_text)
    if _matches_family_filter(intent_evidence, family_filter):
        return _identity(program_slug, intent_evidence)

    for path_value, label in ((target_path, "target_path"), (output_root, "output_root")):
        path_evidence = _evidence_from_canonical_path(program_slug, path_value, label=label)
        if _matches_family_filter(path_evidence, family_filter):
            return _identity(program_slug, path_evidence)

    url_evidence = _evidence_from_url(target_path)
    if _matches_family_filter(url_evidence, family_filter):
        return _identity(program_slug, url_evidence)

    artifact_evidence = _evidence_from_artifacts(target_path)
    if _matches_family_filter(artifact_evidence, family_filter):
        return _identity(program_slug, artifact_evidence)

    wrapper_kind_evidence = _evidence_from_kind(wrapper_hint, source="wrapper_hint")
    if _matches_family_filter(wrapper_kind_evidence, family_filter):
        return _identity(program_slug, wrapper_kind_evidence)

    default_evidence = _evidence_from_default(
        default_family=default_family or family_filter,
        default_lane=default_lane,
        hunt_type=hunt_type,
        wrapper_hint=wrapper_hint,
    )
    return _identity(program_slug, default_evidence)


def _matches_family_filter(
    evidence: TargetIdentityEvidence | None,
    family_filter: str | None,
) -> bool:
    return evidence is not None and (family_filter is None or evidence.family == family_filter)


def _identity(program: str, evidence: TargetIdentityEvidence) -> TargetIdentity:
    return TargetIdentity(
        program=program,
        family=evidence.family,
        lane=evidence.lane,
        target_kind=evidence.target_kind,
        evidence=(evidence,),
        storage_root=evidence.storage_root,
    )


def _canonical_kind(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    return re.sub(r"[^a-z0-9]+", "-", raw).strip("-") or None


def _route_from_kind(value: str | None) -> tuple[str, str, str] | None:
    kind = _canonical_kind(value)
    if kind is None or kind in _IMPRECISE_HINTS:
        return None
    return _TARGET_KIND_ROUTES.get(kind)


def _evidence_from_kind(value: str | None, *, source: str) -> TargetIdentityEvidence | None:
    route = _route_from_kind(value)
    if route is None:
        return None
    family, lane, canonical_kind = route
    return TargetIdentityEvidence(
        source=source,
        family=family,
        lane=lane,
        target_kind=canonical_kind,
        detail=f"{source}={value}",
    )


def _evidence_from_intent(intent_text: str | None) -> TargetIdentityEvidence | None:
    text = str(intent_text or "").strip().lower()
    if not text:
        return None

    intent_patterns: tuple[tuple[re.Pattern[str], tuple[str, str, str], str], ...] = (
        (
            re.compile(r"\b(electron|windows|desktop)\b.{0,40}\b(exe|app|application)\b|\bexe\b"),
            (BINARIES_FAMILY, "exe", "electron-exe" if "electron" in text else "exe"),
            "intent mentions an EXE/desktop application",
        ),
        (
            re.compile(r"\b(android|apk|aab)\b"),
            (BINARIES_FAMILY, "apk", "apk"),
            "intent mentions Android/APK",
        ),
        (
            re.compile(r"\b(mac|macos|darwin|dmg|\.app)\b"),
            (BINARIES_FAMILY, "mac", "mac"),
            "intent mentions macOS",
        ),
        (
            re.compile(r"\b(api|rest|graphql|endpoint)\b"),
            (WEB_FAMILY, "api", "api"),
            "intent mentions API testing",
        ),
        (
            re.compile(r"\b(website|web\s*app|webapp|browser app)\b"),
            (WEB_FAMILY, "web", "web"),
            "intent mentions website/web app",
        ),
    )
    for pattern, route, detail in intent_patterns:
        if pattern.search(text):
            family, lane, kind = route
            return TargetIdentityEvidence(
                source="intent",
                family=family,
                lane=lane,
                target_kind=kind,
                detail=detail,
            )
    return None


def _evidence_from_canonical_path(
    program: str,
    path_value: str | Path | None,
    *,
    label: str,
) -> TargetIdentityEvidence | None:
    if path_value is None:
        return None
    path = Path(path_value).expanduser().resolve(strict=False)
    for candidate in (path, *path.parents):
        if len(candidate.parents) < 2:
            continue
        try:
            family = normalize_family(candidate.parent.parent.name)
        except ValueError:
            continue
        program_dir = candidate.parent.name
        if program_dir != program:
            continue
        lane = normalize_lane(candidate.name)
        if lane not in DEFAULT_LANES.get(family, set()):
            continue
        storage_root = _storage_root_override(candidate.parent.parent.parent)
        return TargetIdentityEvidence(
            source="canonical_path",
            family=family,
            lane=lane,
            target_kind=_kind_for_route(family, lane),
            path=path,
            storage_root=storage_root,
            detail=f"{label} is under canonical {family}/{program}/{lane}",
        )
    return None


def _storage_root_override(base_root: Path) -> Path | None:
    resolved_base = base_root.expanduser().resolve(strict=False)
    default_base = (Path.home() / "Shared").expanduser().resolve(strict=False)
    if resolved_base == default_base:
        return None
    return resolved_base


def _kind_for_route(family: str, lane: str) -> str:
    if family == WEB_FAMILY:
        return "api" if lane == "api" else "web"
    if lane == "apk":
        return "apk"
    if lane == "mac":
        return "mac"
    return "exe"


def _evidence_from_url(target_path: str | Path | None) -> TargetIdentityEvidence | None:
    raw = str(target_path or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host.startswith("api.") or "/api" in path or "graphql" in path:
        return TargetIdentityEvidence(
            source="url",
            family=WEB_FAMILY,
            lane="api",
            target_kind="api",
            detail="URL hostname/path indicates API surface",
        )
    return TargetIdentityEvidence(
        source="url",
        family=WEB_FAMILY,
        lane="web",
        target_kind="web",
        detail="HTTP(S) URL indicates web surface",
    )


def _evidence_from_artifacts(target_path: str | Path | None) -> TargetIdentityEvidence | None:
    if target_path is None:
        return None
    path = Path(target_path).expanduser().resolve(strict=False)
    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix in {".apk", ".aab"}:
        return _artifact(BINARIES_FAMILY, "apk", "apk", path, "target filename is an Android package")
    if suffix == ".exe":
        return _artifact(BINARIES_FAMILY, "exe", "exe", path, "target filename is a Windows executable")
    if suffix == ".dmg" or suffix == ".app" or name.endswith(".app"):
        return _artifact(BINARIES_FAMILY, "mac", "mac", path, "target filename is a macOS application artifact")

    if (path / "AndroidManifest.xml").exists():
        return _artifact(BINARIES_FAMILY, "apk", "apk", path, "AndroidManifest.xml marker exists")
    if (path / "Contents" / "Info.plist").exists():
        return _artifact(BINARIES_FAMILY, "mac", "mac", path, "macOS Contents/Info.plist marker exists")

    electron_detail = _electron_marker_detail(path)
    if electron_detail is not None:
        return _artifact(BINARIES_FAMILY, "exe", "electron-exe", path, electron_detail)

    if _api_marker_exists(path):
        return _artifact(WEB_FAMILY, "api", "api", path, "OpenAPI/GraphQL marker exists")
    return None


def _artifact(
    family: str,
    lane: str,
    target_kind: str,
    path: Path,
    detail: str,
) -> TargetIdentityEvidence:
    return TargetIdentityEvidence(
        source="artifact",
        family=family,
        lane=lane,
        target_kind=target_kind,
        path=path,
        detail=detail,
    )


def _electron_marker_detail(path: Path) -> str | None:
    marker_paths = {
        "resources/app.asar": path / "resources" / "app.asar",
        "app.asar": path / "app.asar",
        "dist/main.js": path / "dist" / "main.js",
        "dist/preload.js": path / "dist" / "preload.js",
    }
    for label, marker in marker_paths.items():
        if marker.exists():
            return f"Electron marker {label} exists"

    if path.name.lower() in {"app_asar", "app.asar"}:
        return "target path name indicates an extracted Electron app.asar"

    package_path = path / "package.json"
    if not package_path.exists():
        return None
    try:
        package_text = package_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    package_data: dict[str, Any] = {}
    try:
        parsed = json.loads(package_text)
        if isinstance(parsed, dict):
            package_data = parsed
    except json.JSONDecodeError:
        if "electron" in package_text.lower():
            return "package.json text mentions Electron"
        return None

    dependency_values: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        value = package_data.get(key)
        if isinstance(value, dict):
            dependency_values.extend(str(item).lower() for item in value.keys())
    script_text = json.dumps(package_data.get("scripts", {}), sort_keys=True).lower()
    main_value = str(package_data.get("main") or "").lower()
    if "electron" in dependency_values or "electron" in script_text:
        return "package.json declares Electron"
    if main_value in {"dist/main.js", "main.js"} or "preload" in package_text.lower():
        return "package.json contains Electron main/preload markers"
    return None


def _api_marker_exists(path: Path) -> bool:
    return any(
        (path / marker).exists()
        for marker in (
            "openapi.json",
            "openapi.yaml",
            "swagger.json",
            "swagger.yaml",
            "schema.graphql",
        )
    )


def _evidence_from_default(
    *,
    default_family: str | None,
    default_lane: str | None,
    hunt_type: str | None,
    wrapper_hint: str | None,
) -> TargetIdentityEvidence:
    if default_lane:
        family, lane = resolve_family_lane(family=default_family, lane=default_lane)
        detail = "explicit default family/lane"
    elif default_family:
        family = normalize_family(default_family)
        lane = "web" if family == WEB_FAMILY else "apk"
        detail = "explicit default family"
    else:
        route_hint = hunt_type or wrapper_hint or "0day_team"
        try:
            family, lane = resolve_family_lane(hunt_type=route_hint)
            detail = f"wrapper default {route_hint}"
        except ValueError:
            family, lane = WEB_FAMILY, "web"
            detail = "legacy generic zero-day default"
    return TargetIdentityEvidence(
        source="wrapper_default",
        family=family,
        lane=lane,
        target_kind=_kind_for_route(family, lane),
        detail=detail,
    )
