"""Architectural boundary tests for the standalone protocol package."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from gwm_client.china_crypto import decrypt_g_app

PACKAGE_DIR = Path(__file__).resolve().parents[3] / "gwm_client"
FIXTURE_DIR = Path(__file__).with_name("fixtures")
_SYNTHETIC_STABLE_DEVICE_IDS = frozenset(
    {
        "0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
        "feedface-dead-beef-cafe-0123456789ab",
        "feedfacedeadbeef",
    }
)
_SYNTHETIC_COORDINATE_SENTINELS = frozenset(
    {"-33.8688", "-2.5", "0", "0.0", "1.25", "151.2093"}
)
_SYNTHETIC_NUMERIC_IDENTIFIER_SENTINELS = frozenset(
    {
        9_007_199_254_740_993,
        9_007_199_254_740_995,
    }
)
_SYNTHETIC_PASSWORD_SENTINELS = frozenset({"SYNTHETICPASSWORD"})


def test_client_package_has_no_home_assistant_imports() -> None:
    imported_modules: set[str] = set()
    for source_path in PACKAGE_DIR.rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.add(node.module)

    forbidden = {
        module
        for module in imported_modules
        if module == "homeassistant"
        or module.startswith("homeassistant.")
        or module == "custom_components"
        or module.startswith("custom_components.")
    }
    assert not forbidden


def test_production_client_does_not_import_disposable_live_poc() -> None:
    production_sources = [
        path
        for path in PACKAGE_DIR.rglob("*.py")
        if path.name != "live_poc.py"
    ]

    for source_path in production_sources:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        imported = _absolute_import_targets(tree, source_path)
        assert not {
            target
            for target in imported
            if target == "gwm_client.live_poc"
            or target.startswith("gwm_client.live_poc.")
        }


def test_production_china_client_does_not_import_reuse_only_poc() -> None:
    source_path = PACKAGE_DIR / "china_client.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    imported = _absolute_import_targets(tree, source_path)

    assert not {
        target
        for target in imported
        if target == "gwm_client.china_poc"
        or target.startswith("gwm_client.china_poc.")
    }


def _absolute_import_targets(tree: ast.AST, source_path: Path) -> set[str]:
    relative_parts = source_path.relative_to(PACKAGE_DIR).with_suffix("").parts
    package_parts = ["gwm_client", *relative_parts[:-1]]
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent_count = node.level - 1
                base_parts = package_parts[: len(package_parts) - parent_count]
                module_parts = node.module.split(".") if node.module else []
                module = ".".join([*base_parts, *module_parts])
            else:
                module = node.module or ""
            if module:
                targets.add(module)
                targets.update(f"{module}.{alias.name}" for alias in node.names)
    return targets


def test_client_fixtures_are_versioned_and_explicitly_synthetic() -> None:
    fixture_paths = sorted(FIXTURE_DIR.glob("*.json"))
    assert fixture_paths

    for fixture_path in fixture_paths:
        text = fixture_path.read_text(encoding="utf-8")
        payload = json.loads(text)
        _, separator, filename_version = fixture_path.stem.rpartition("_v")
        assert separator and filename_version.isdecimal()
        assert payload["schema_version"] == int(filename_version)
        _assert_no_raw_identity_text(text)
        _assert_sensitive_fixture_values_are_synthetic(payload)


def _assert_no_raw_identity_text(text: str) -> None:
    assert "-----BEGIN CERTIFICATE-----" not in text
    assert "-----BEGIN PRIVATE KEY-----" not in text
    assert "-----BEGIN RSA PRIVATE KEY-----" not in text


def _assert_sensitive_fixture_values_are_synthetic(value: object) -> None:
    if isinstance(value, dict):
        normalized_keys = {str(key).replace("_", "").replace("-", "").lower() for key in value}
        for key, child in value.items():
            normalized_key = key.replace("_", "").replace("-", "").lower()
            if normalized_key in {
                "accesstoken",
                "authorization",
                "autoaigwid",
                "gtoken",
                "grefreshtoken",
                "beantechaccesstoken",
                "beantechbeanid",
                "beantechrefreshtoken",
                "beantechssotoken",
                "autoaitokenid",
                "autoaiuserid",
                "pttoken",
                "refreshtoken",
                "ssoid",
                "ssotk",
                "ssotoken",
                "token",
                "tokenid",
                "userid",
                "beanid",
            }:
                assert (
                    isinstance(child, str)
                    and (not child or child.startswith("SYNTHETIC-"))
                ) or (
                    normalized_key == "beanid"
                    and isinstance(child, int)
                    and not isinstance(child, bool)
                    and child in _SYNTHETIC_NUMERIC_IDENTIFIER_SENTINELS
                )
            if normalized_key == "password":
                assert isinstance(child, str) and (
                    child.startswith("SYNTHETIC-")
                    or child in _SYNTHETIC_PASSWORD_SENTINELS
                )
            if normalized_key in {"account", "email"}:
                assert isinstance(child, str) and child.startswith("SYNTHETIC-")
            if normalized_key in {"smscode", "verificationcode", "verifycode"} and not isinstance(
                child, dict | list
            ):
                assert child is None or (
                    isinstance(child, str) and child.startswith("SYNTHETIC-")
                )
            if normalized_key == "code" and {"phone", "devicetoken"} <= normalized_keys:
                assert isinstance(child, str) and child.startswith("SYNTHETIC-")
            if normalized_key == "phone":
                assert isinstance(child, str) and (
                    child == "13800138000" or child.startswith("SYNTHETIC-")
                )
            if normalized_key in {"deviceid", "mobileid", "cid"}:
                assert (
                    isinstance(child, str)
                    and (
                        child.startswith("SYNTHETIC")
                        or child in _SYNTHETIC_STABLE_DEVICE_IDS
                    )
                ) or (
                    isinstance(child, int)
                    and not isinstance(child, bool)
                    and child in _SYNTHETIC_NUMERIC_IDENTIFIER_SENTINELS
                )
            if normalized_key == "devicetoken":
                assert isinstance(child, str) and (
                    not child or child.startswith("SYNTHETIC-")
                )
            if normalized_key in {"lat", "latitude", "lon", "lng", "longitude"}:
                assert (
                    isinstance(child, str | int | float)
                    and not isinstance(child, bool)
                    and str(child) in _SYNTHETIC_COORDINATE_SENTINELS
                )
            raw_identity_key = (
                normalized_key in {"cabundle", "keypem", "pkcs8"}
                or (
                    "certificate" in normalized_key
                    and not normalized_key.endswith("sha256")
                )
                or (
                    "privatekey" in normalized_key
                    and not normalized_key.endswith("sha256")
                )
                or (
                    "transformedkey" in normalized_key
                    and not normalized_key.endswith("sha256")
                )
            )
            if raw_identity_key and not isinstance(child, dict | list):
                raise AssertionError("raw certificate and private-key material is forbidden in fixtures")
            if key == "identifier":
                assert isinstance(child, str) and child.startswith("SYNTHETIC")
            if normalized_key == "vin":
                assert isinstance(child, str) and child.upper().startswith(("LGWTEST", "SYNTHETIC"))
            if normalized_key in {"vehicleid", "gwid"}:
                assert (
                    isinstance(child, str)
                    and child.casefold().startswith("synthetic")
                ) or (
                    isinstance(child, int)
                    and not isinstance(child, bool)
                    and child in _SYNTHETIC_NUMERIC_IDENTIFIER_SENTINELS
                )
            if key == "body" and isinstance(child, str) and child.startswith(("{", "[")):
                _assert_sensitive_fixture_values_are_synthetic(json.loads(child))
            _assert_sensitive_fixture_values_are_synthetic(child)
    elif isinstance(value, list):
        for child in value:
            _assert_sensitive_fixture_values_are_synthetic(child)
    elif isinstance(value, str):
        if value.startswith("G_A("):
            _assert_sensitive_fixture_values_are_synthetic(json.loads(decrypt_g_app(value)))
        parsed = urlsplit(value)
        if parsed.query.startswith("p=") and "&" not in parsed.query:
            _assert_sensitive_fixture_values_are_synthetic(
                json.loads(unquote(parsed.query[2:]))
            )


@pytest.mark.parametrize(
    "key",
    [
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "g_token",
        "g_refresh_token",
        "sso_token",
        "pt_token",
        "bean_tech_access_token",
        "bean_tech_refresh_token",
        "bean_tech_sso_token",
        "bean_tech_bean_id",
        "auto_ai_token_id",
        "auto_ai_user_id",
        "auto_ai_gw_id",
        "user_id",
        "bean_id",
        "Authorization",
        "G-TOKEN",
        "token",
        "tokenId",
        "ssoTk",
        "ssoId",
    ],
)
def test_fixture_guard_covers_wire_and_python_token_spellings(key: str) -> None:
    with pytest.raises(AssertionError):
        _assert_sensitive_fixture_values_are_synthetic({key: "REAL-TOKEN-MUST-FAIL"})


@pytest.mark.parametrize(
    "key",
    [
        "accessToken",
        "refreshToken",
        "password",
        "account",
        "email",
        "verifyCode",
        "smsCode",
        "sms_code",
        "deviceToken",
        "privateKey",
        "private_key_data",
        "transformed_private_key",
        "transformed_private_key_data",
        "transformedKey",
        "transformed_key",
        "transformedKeyData",
        "certificate",
        "certificate_data",
        "certificatePem",
        "clientCertificate",
        "bootstrap_certificate",
        "ca_bundle",
    ],
)
def test_fixture_guard_inspects_embedded_wire_bodies(key: str) -> None:
    with pytest.raises(AssertionError):
        _assert_sensitive_fixture_values_are_synthetic({"body": json.dumps({key: "REAL-MATERIAL-MUST-FAIL"})})


@pytest.mark.parametrize(
    "key",
    [
        "transformedKey",
        "transformed_key",
        "transformedKeyData",
        "certificate",
        "certificate_data",
        "certificatePem",
        "clientCertificate",
        "bootstrap_certificate",
        "ca_bundle",
    ],
)
def test_fixture_guard_rejects_top_level_raw_identity_aliases(key: str) -> None:
    with pytest.raises(AssertionError):
        _assert_sensitive_fixture_values_are_synthetic({key: "REAL-MATERIAL-MUST-FAIL"})


def test_fixture_guard_rejects_certificate_pem_under_unknown_key() -> None:
    with pytest.raises(AssertionError):
        _assert_no_raw_identity_text(
            json.dumps({"unrecognized": "-----BEGIN CERTIFICATE-----SENSITIVE"})
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("device_id", "REAL-DEVICE-ID"),
        ("DeviceId", "REAL-DEVICE-ID"),
        ("mobileId", "REAL-MOBILE-ID"),
        ("cid", "REAL-CID"),
        ("deviceToken", "REAL-DEVICE-TOKEN"),
        ("lat", "12.345"),
        ("latitude", 12.345),
        ("lon", "67.890"),
        ("longitude", 67.89),
    ],
)
def test_fixture_guard_rejects_non_synthetic_device_and_coordinate_values(
    key: str,
    value: object,
) -> None:
    with pytest.raises(AssertionError):
        _assert_sensitive_fixture_values_are_synthetic({key: value})


@pytest.mark.parametrize("key", ["beanId", "deviceId", "vehicleId", "gwId"])
@pytest.mark.parametrize("value", [123, True, 9_007_199_254_740_994])
def test_fixture_guard_allows_only_closed_synthetic_numeric_identifiers(
    key: str,
    value: object,
) -> None:
    with pytest.raises(AssertionError):
        _assert_sensitive_fixture_values_are_synthetic({key: value})
