"""Check a release tag and build the HACS integration archive from that tag."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAG_PATTERN = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
DOMAIN = "gwm_ora"
ASSET_NAME = "gwm.zip"


def build(tag: str, output_dir: Path) -> Path:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ValueError(f"Expected a vX.Y.Z tag, got {tag!r}")

    version = tag[1:]
    component_dir = ROOT / "custom_components" / DOMAIN
    manifest = json.loads((component_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("domain") != DOMAIN:
        raise ValueError(f"Integration domain must be {DOMAIN}")
    if manifest.get("version") != version:
        raise ValueError(f"Manifest version {manifest.get('version')!r} does not match {tag}")

    requirement = f"gwm-client@https://github.com/moryoav/ha-gwm-ev/archive/refs/tags/{tag}.zip"
    if manifest.get("requirements") != [requirement]:
        raise ValueError(f"Manifest must pin gwm-client to {tag}")

    hacs = json.loads((ROOT / "hacs.json").read_text(encoding="utf-8"))
    archive_name = ASSET_NAME
    if hacs.get("zip_release") is not True or hacs.get("filename") != archive_name:
        raise ValueError(f"hacs.json must select {archive_name} as its ZIP release")
    if hacs.get("hide_default_branch") is not True:
        raise ValueError("hacs.json must hide the default branch for ZIP releases")

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / archive_name
    subprocess.run(
        [
            "git",
            "archive",
            "--format=zip",
            f"--output={archive_path}",
            f"HEAD:custom_components/{DOMAIN}",
        ],
        cwd=ROOT,
        check=True,
    )

    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        if not {"__init__.py", "manifest.json"}.issubset(names):
            raise ValueError("ZIP is missing integration files at its root")
        if archive.testzip() is not None:
            raise ValueError("ZIP integrity check failed")
        archived_manifest = json.loads(archive.read("manifest.json"))
        if archived_manifest != manifest:
            raise ValueError("Tagged manifest differs from the working tree")

    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Existing vX.Y.Z tag")
    parser.add_argument("output_dir", type=Path, help="Directory outside the repository for the ZIP")
    args = parser.parse_args()
    try:
        print(build(args.tag, args.output_dir))
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print(f"HACS release build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
