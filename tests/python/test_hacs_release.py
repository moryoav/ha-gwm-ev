"""Check that a tagged release can be installed from its HACS ZIP."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build_hacs_release.py"
MANIFEST = ROOT / "custom_components" / "gwm_ora" / "manifest.json"


def test_release_zip_has_integration_files_at_root(tmp_path: Path) -> None:
    """Verify the BeanTech encoder and APAC materials in an isolated HACS install."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    tag = f"v{manifest['version']}"
    result = subprocess.run(
        [sys.executable, str(BUILDER), tag, str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    archive_path = tmp_path / "gwm.zip"
    assert result.stdout.strip() == str(archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        assert {
            "__init__.py",
            "manifest.json",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "gwm_client/__init__.py",
            "gwm_client/client.py",
            "gwm_client/china_client.py",
            "gwm_client/py.typed",
            "resources/beantech_lock_encoder.bin",
            "resources/apac/bootstrap.cer",
            "resources/apac/bootstrap.key",
            "resources/apac/ca.pem",
            "resources/apac/signing.json",
            "resources/br/gwm_general.cer",
            "resources/br/gwm_general.key",
            "resources/br/gwm_root.cer",
        }.issubset(names)
        assert "gwm_ora/manifest.json" not in names
        assert json.loads(archive.read("manifest.json")) == manifest
        assert not manifest.get("requirements")
        assert not any(name.endswith((".pyc", ".whl")) or "__pycache__" in name for name in names)

        config_dir = tmp_path / "config"
        component_dir = config_dir / "custom_components" / "gwm_ora"
        archive.extractall(component_dir)

    # Only the extracted HACS installation is available to this fresh process.
    # Block the old package so an accidental absolute import cannot pass locally.
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            textwrap.dedent(
                """
                import hashlib
                import importlib
                import os
                from pathlib import Path
                import pkgutil
                import sys

                sys.path.insert(0, os.getcwd())
                sys.modules["gwm_client"] = None
                import custom_components.gwm_ora as integration
                from custom_components.gwm_ora import bean_tech_lock, cloud_auth, gwm_client
                from custom_components.gwm_ora.gwm_client import live_poc
                from custom_components.gwm_ora.gwm_client.apac_identity import create_apac_bootstrap_context
                from custom_components.gwm_ora.gwm_client.apac_material import load_installed_apac_material

                installed = Path.cwd() / "custom_components" / "gwm_ora"
                for module in pkgutil.iter_modules(integration.__path__):
                    imported = importlib.import_module(f"{integration.__name__}.{module.name}")
                    assert Path(imported.__file__).is_relative_to(installed), imported.__name__
                assert Path(gwm_client.__file__).is_relative_to(installed)
                assert integration.GwmClientError is gwm_client.GwmClientError
                assert cloud_auth._RESOURCE_DIRECTORY == installed / "resources"
                assert live_poc._default_resource_dir() == installed / "resources"
                assert bean_tech_lock._ENCODER.is_relative_to(installed / "resources")
                encoded = bean_tech_lock._prepare_credential("000123")
                assert hashlib.sha256(encoded.encode("ascii")).hexdigest() == (
                    "f9ec3538c5ca1328d085ff0340cebb4008d379b66b735bc6885e7cc57432808b"
                )
                local_material = Path.cwd() / ".storage" / "gwm_apac_material"
                assert not local_material.exists()
                apac = load_installed_apac_material(local_material)
                assert create_apac_bootstrap_context(apac.bootstrap).check_hostname
                """
            ),
        ],
        cwd=config_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_release_zip_rejects_mismatched_tag(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(BUILDER), "v999.999.999", str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "does not match" in result.stderr
    assert not (tmp_path / "gwm.zip").exists()
