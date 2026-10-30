"""Tests for externally supplied APAC material, using synthetic values."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial, load_apac_material
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


def _synthetic_bootstrap() -> EuBootstrapMaterial:
    return EuBootstrapMaterial(
        certificate_data=b"synthetic-certificate",
        transformed_private_key_data=b"c3ludGhldGljLWtleQ==",
        ca_bundle=b"synthetic-ca",
    )


def test_material_is_private_and_does_not_supply_default_credentials() -> None:
    material = ApacMaterial(_synthetic_bootstrap(), "synthetic-key", "synthetic-secret")
    assert "synthetic" not in repr(material)
    profile = material.signing_profile()
    assert profile.app_key == "synthetic-key"
    assert profile.app_secret == "synthetic-secret"
    assert "synthetic-secret" not in repr(profile)
    assert profile.prefix == "bt"
    assert profile.query_policy == "keep-empty-decoded"
    assert profile.uppercase_nonce is True


@pytest.mark.parametrize("key,secret", [("", "synthetic"), ("synthetic", ""), ("a\nb", "ok")])
def test_invalid_material_fails_without_echoing_values(key: str, secret: str) -> None:
    with pytest.raises(ValueError, match="^apac_material_invalid$") as error:
        ApacMaterial(_synthetic_bootstrap(), key, secret)
    assert "synthetic" not in str(error.value)


def test_requires_bootstrap_material() -> None:
    with pytest.raises(ValueError, match="^apac_material_invalid$"):
        ApacMaterial(None, "synthetic", "synthetic")  # type: ignore[arg-type]


def test_loads_only_explicit_local_files_with_synthetic_material(tmp_path: Path) -> None:
    (tmp_path / "bootstrap.cer").write_bytes(b"synthetic-certificate")
    (tmp_path / "bootstrap.key").write_bytes(b"c3ludGhldGljLWtleQ==")
    (tmp_path / "ca.pem").write_bytes(b"synthetic-ca")
    (tmp_path / "signing.json").write_text(
        json.dumps({"app_key": "synthetic-key", "app_secret": "synthetic-secret"}), encoding="utf-8"
    )
    material = load_apac_material(tmp_path)
    assert material.signing_profile().app_secret == "synthetic-secret"
    assert "synthetic" not in repr(material)


def test_missing_or_relative_private_path_fails_without_disclosure(tmp_path: Path) -> None:
    for path in (tmp_path / "private-name", Path("relative-private-name")):
        with pytest.raises(ValueError, match="^apac_material_invalid$") as error:
            load_apac_material(path)
        assert "private-name" not in str(error.value)
