"""Quality and community metadata tests."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def test_translation_and_icon_files_are_valid_json() -> None:
    translations = json.loads(
        (ROOT / "custom_components/gwm_ora/translations/en.json").read_text(encoding="utf-8")
    )
    icons = json.loads((ROOT / "custom_components/gwm_ora/icons.json").read_text(encoding="utf-8"))

    assert "charging_control_unavailable" in translations["exceptions"]
    assert "set_charging_plan" in translations["services"]
    assert icons["entity"]["switch"]["charging_schedule"]["default"] == "mdi:calendar-clock"


def test_charging_services_require_explicit_window() -> None:
    services = (ROOT / "custom_components/gwm_ora/services.yaml").read_text(encoding="utf-8")

    assert "set_charging_plan:" in services
    assert "clear_charging_plan:" in services
    assert services.count("required: true") >= 4
    assert "enable:" not in services


def test_community_health_files_exist() -> None:
    for path in (
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "SUPPORT.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
    ):
        assert (ROOT / path).is_file()


def test_quality_scale_tracker_exists() -> None:
    quality_scale = ROOT / "custom_components/gwm_ora/quality_scale.yaml"
    text = quality_scale.read_text(encoding="utf-8")

    assert "config-flow: done" in text
    assert "diagnostics: done" in text
    assert "reconfiguration-flow: done" in text
    assert "test-coverage:" in text


def test_integration_only_tree_has_no_retired_addon_or_dotnet_workflows() -> None:
    assert not (ROOT / "addons").exists()
    assert not (ROOT / "tests/GwmOra.Addon.Tests").exists()
    assert not (ROOT / "GwmOra.sln").exists()
    assert not (ROOT / "global.json").exists()
    assert not (ROOT / "repository.yaml").exists()
    assert not (ROOT / ".github/workflows/addon-build.yml").exists()
    assert not (ROOT / ".github/workflows/dotnet.yml").exists()


def test_device_tracker_uses_public_home_assistant_api() -> None:
    source = (ROOT / "custom_components/gwm_ora/device_tracker.py").read_text(
        encoding="utf-8"
    )

    assert "from homeassistant.components.device_tracker import TrackerEntity" in source
    assert "except ImportError:" in source
    assert "from homeassistant.components.device_tracker.config_entry import TrackerEntity" in source


def test_integration_presentation_assets_exist() -> None:
    brand_dir = ROOT / "custom_components/gwm_ora/brand"

    icon_width, icon_height = _png_size(brand_dir / "icon.png")
    assert icon_width == icon_height
    assert icon_width >= 128
    logo_width, logo_height = _png_size(brand_dir / "logo.png")
    assert logo_width >= 200
    assert logo_height >= 80


def test_hacs_default_repository_readiness_files_exist() -> None:
    hacs = json.loads((ROOT / "hacs.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "custom_components/gwm_ora/manifest.json").read_text(encoding="utf-8"))

    assert hacs == {
        "name": "GWM",
        "homeassistant": "2026.1.0",
    }
    assert manifest["documentation"] == "https://github.com/moryoav/ha-gwm-ev"
    assert manifest["issue_tracker"] == "https://github.com/moryoav/ha-gwm-ev/issues"
    assert manifest["codeowners"] == ["@moryoav"]
    assert manifest["domain"] == "gwm_ora"
    assert manifest["name"] == "GWM"
    assert manifest["version"] == "0.16.19"
    assert manifest["integration_type"] == "hub"
    assert manifest["loggers"] == ["gwm_client"]
    assert manifest["requirements"] == [
        "gwm-client@https://github.com/moryoav/ha-gwm-ev/archive/refs/tags/"
        "v0.16.19.zip"
    ]

    custom_components = [path.name for path in (ROOT / "custom_components").iterdir() if path.is_dir()]
    assert custom_components == ["gwm_ora"]
    assert (ROOT / "custom_components/gwm_ora/brand/icon.png").is_file()

    hacs_workflow = (ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
    hassfest_workflow = (ROOT / ".github/workflows/hassfest.yml").read_text(encoding="utf-8")

    assert "uses: hacs/action@main" in hacs_workflow
    assert "category: integration" in hacs_workflow
    assert "ignore:" not in hacs_workflow
    assert "uses: home-assistant/actions/hassfest@master" in hassfest_workflow


def test_translations_match_english_structure() -> None:
    translations = ROOT / "custom_components/gwm_ora/translations"
    english = json.loads((translations / "en.json").read_text(encoding="utf-8"))
    simplified_chinese = json.loads(
        (translations / "zh-Hans.json").read_text(encoding="utf-8")
    )

    def leaf_paths(value, prefix="") -> set[str]:
        if not isinstance(value, dict):
            return {prefix}
        return {
            path
            for key, child in value.items()
            for path in leaf_paths(child, f"{prefix}.{key}" if prefix else key)
        }

    assert leaf_paths(simplified_chinese) == leaf_paths(english)
