from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from bounty_core.target_identity import resolve_target_identity


def test_shared_binaries_exe_path_routes_to_binaries_exe(tmp_path: Path) -> None:
    target = tmp_path / "Shared" / "binaries" / "canva" / "exe" / "input" / "app_asar"
    target.mkdir(parents=True)

    with patch.object(Path, "home", return_value=tmp_path):
        identity = resolve_target_identity(program="canva", target_path=target)

    assert identity.family == "binaries"
    assert identity.lane == "exe"
    assert identity.target_kind == "exe"
    assert identity.evidence[0].source == "canonical_path"


def test_electron_markers_route_to_exe(tmp_path: Path) -> None:
    target = tmp_path / "app_asar"
    (target / "dist").mkdir(parents=True)
    (target / "package.json").write_text(
        '{"main":"dist/main.js","devDependencies":{"electron":"^31.0.0"}}\n',
        encoding="utf-8",
    )
    (target / "dist" / "preload.js").write_text("// preload\n", encoding="utf-8")

    identity = resolve_target_identity(program="canva", target_path=target)

    assert identity.family == "binaries"
    assert identity.lane == "exe"
    assert identity.target_kind == "electron-exe"
    assert identity.evidence[0].source == "artifact"


def test_intent_text_routes_common_lanes(tmp_path: Path) -> None:
    api_identity = resolve_target_identity(program="demo", intent_text="Focus on the public API")
    web_identity = resolve_target_identity(program="demo", intent_text="Audit the website web app")
    exe_identity = resolve_target_identity(program="demo", intent_text="Electron EXE application")

    assert (api_identity.family, api_identity.lane) == ("web_bounty", "api")
    assert (web_identity.family, web_identity.lane) == ("web_bounty", "web")
    assert (exe_identity.family, exe_identity.lane) == ("binaries", "exe")


def test_url_targets_route_to_web_or_api() -> None:
    api_identity = resolve_target_identity(program="demo", target_path="https://api.example.com/v1/users")
    path_api_identity = resolve_target_identity(program="demo", target_path="https://example.com/api/v1/users")
    web_identity = resolve_target_identity(program="demo", target_path="https://www.example.com/")
    wrapped_api_identity = resolve_target_identity(
        program="demo",
        target_path="https://api.example.com/v1/users",
        wrapper_hint="web",
    )

    assert (api_identity.family, api_identity.lane, api_identity.evidence[0].source) == ("web_bounty", "api", "url")
    assert (path_api_identity.family, path_api_identity.lane, path_api_identity.evidence[0].source) == ("web_bounty", "api", "url")
    assert (web_identity.family, web_identity.lane, web_identity.evidence[0].source) == ("web_bounty", "web", "url")
    assert (wrapped_api_identity.family, wrapped_api_identity.lane, wrapped_api_identity.evidence[0].source) == ("web_bounty", "api", "url")


def test_explicit_family_lane_override_inference(tmp_path: Path) -> None:
    target = tmp_path / "Shared" / "binaries" / "canva" / "exe" / "input" / "app_asar"
    target.mkdir(parents=True)

    identity = resolve_target_identity(
        program="canva",
        family="web_bounty",
        lane="api",
        target_path=target,
        intent_text="Electron EXE application",
    )

    assert identity.family == "web_bounty"
    assert identity.lane == "api"
    assert identity.evidence[0].source == "explicit"


def test_family_only_constrains_later_inference() -> None:
    identity = resolve_target_identity(
        program="demo",
        family="binaries",
        intent_text="Focus on the public API",
    )

    assert identity.family == "binaries"
    assert identity.lane == "apk"
    assert identity.evidence[0].source == "wrapper_default"


def test_generic_zero_day_falls_back_to_legacy_web() -> None:
    identity = resolve_target_identity(program="canva", wrapper_hint="0day_team")

    assert identity.family == "web_bounty"
    assert identity.lane == "web"
    assert identity.evidence[0].source == "wrapper_default"
