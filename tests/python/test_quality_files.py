"""User-facing service metadata, translations, icons, and branding contracts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

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
    services = yaml.safe_load((ROOT / "custom_components/gwm_ora/services.yaml").read_text(encoding="utf-8"))
    for service, required in (
        ("set_charging_plan", {"vin", "start_time", "end_time"}),
        ("clear_charging_plan", {"vin"}),
    ):
        fields = services[service]["fields"]
        assert set(fields) == required
        assert all(fields[field]["required"] is True for field in required)


def test_integration_presentation_assets_exist() -> None:
    brand_dir = ROOT / "custom_components/gwm_ora/brand"

    icon_width, icon_height = _png_size(brand_dir / "icon.png")
    assert icon_width == icon_height
    assert icon_width >= 128
    logo_width, logo_height = _png_size(brand_dir / "logo.png")
    assert logo_width >= 200
    assert logo_height >= 80


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
