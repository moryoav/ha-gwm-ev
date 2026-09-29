"""Check that a tagged release can be installed from its HACS ZIP."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build_hacs_release.py"
MANIFEST = ROOT / "custom_components" / "gwm_ora" / "manifest.json"


def test_release_zip_has_integration_files_at_root(tmp_path: Path) -> None:
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
        assert {"__init__.py", "manifest.json"}.issubset(names)
        assert "gwm_ora/manifest.json" not in names
        assert json.loads(archive.read("manifest.json")) == manifest


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
