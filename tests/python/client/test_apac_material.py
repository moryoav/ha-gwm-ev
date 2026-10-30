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


@pytest.mark.parametrize("git_marker", ["directory", "worktree-file"])
def test_private_material_inside_the_repository_is_rejected(tmp_path: Path, monkeypatch, git_marker: str) -> None:
    """Enforce the external directory boundary in regular and linked worktrees."""
    import custom_components.gwm_ora.gwm_client.apac_material as material

    repository = tmp_path / "repository"
    private = repository / "private"
    private.mkdir(parents=True)
    marker = repository / ".git"
    if git_marker == "directory":
        marker.mkdir()
    else:
        marker.write_text("gitdir: external-synthetic-directory", encoding="utf-8")
    monkeypatch.setattr(material, "_SOURCE_DIRECTORY", repository / "package")
    with pytest.raises(ValueError, match="^apac_material_invalid$") as error:
        load_apac_material(private)
    assert str(repository) not in str(error.value)


def test_private_file_symlinks_cannot_escape_the_supplied_directory(tmp_path: Path) -> None:
    """Resolve file aliases before opening any private material."""
    private = tmp_path / "private"
    private.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"app_key":"synthetic-key","app_secret":"synthetic-secret"}', encoding="utf-8")
    try:
        (private / "signing.json").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("File symlinks are unavailable on this platform")
    with pytest.raises(ValueError, match="^apac_material_invalid$"):
        load_apac_material(private)
