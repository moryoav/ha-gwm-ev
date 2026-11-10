"""Load enrollment and signing resources for the APAC client."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .eu_identity import EuBootstrapMaterial
from .signing import SigningProfile

_MAX_FILE_BYTES = 256 * 1024
_SOURCE_DIRECTORY = Path(__file__).resolve().parent


@dataclass(frozen=True, slots=True)
class ApacMaterial:
    """Enrollment and signing material for the APAC region.

    Do not log or persist this object.
    """

    bootstrap: EuBootstrapMaterial = field(repr=False)
    app_key: str = field(repr=False)
    app_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject missing or malformed signing material."""
        if type(self.bootstrap) is not EuBootstrapMaterial:
            raise ValueError("apac_material_invalid")
        for value in (self.app_key, self.app_secret):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 1024
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
            ):
                raise ValueError("apac_material_invalid")

    def signing_profile(self) -> SigningProfile:
        """Build a request-local profile without default credentials."""
        return SigningProfile(
            name="apac-external",
            prefix="bt",
            app_key=self.app_key,
            app_secret=self.app_secret,
            query_policy="keep-empty-decoded",
            uppercase_nonce=True,
        )


def load_installed_apac_material(local_directory: Path) -> ApacMaterial:
    """Use the installed bundle or fall back to private development files.

    An incomplete or unreadable bundle fails setup instead of falling back.
    """
    bundle = _SOURCE_DIRECTORY.parent / "resources" / "apac"
    try:
        bundle.lstat()
    except FileNotFoundError:
        return load_apac_material(local_directory)
    except OSError:
        raise ValueError("apac_material_invalid") from None
    return _read_apac_material(bundle)


def load_apac_material(directory: Path) -> ApacMaterial:
    """Load explicitly supplied local files from outside the Git checkout."""
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise ValueError("apac_material_invalid")
    try:
        directory = directory.resolve(strict=True)
        repository = next((parent for parent in _SOURCE_DIRECTORY.parents if (parent / ".git").exists()), None)
        if repository is not None and directory.is_relative_to(repository):
            raise ValueError("apac_material_invalid")
    except (OSError, RuntimeError, ValueError):
        raise ValueError("apac_material_invalid") from None
    return _read_apac_material(directory)


def _read_apac_material(directory: Path) -> ApacMaterial:
    """Read all four files within the given directory and redact load errors."""
    try:
        directory = directory.resolve(strict=True)

        def read_file(name: str) -> bytes:
            """Read one bounded regular file within the bundle directory."""
            path = (directory / name).resolve(strict=True)
            if not path.is_relative_to(directory) or not path.is_file():
                raise ValueError("apac_material_invalid")
            with path.open("rb") as source:
                data = source.read(_MAX_FILE_BYTES + 1)
            if not data or len(data) > _MAX_FILE_BYTES:
                raise ValueError("apac_material_invalid")
            return data

        signing = json.loads(read_file("signing.json"))
        if not isinstance(signing, dict) or set(signing) != {"app_key", "app_secret"}:
            raise ValueError("apac_material_invalid")
        bootstrap = EuBootstrapMaterial(
            certificate_data=read_file("bootstrap.cer"),
            transformed_private_key_data=read_file("bootstrap.key"),
            ca_bundle=read_file("ca.pem"),
        )
        return ApacMaterial(bootstrap, signing["app_key"], signing["app_secret"])
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError):
        raise ValueError("apac_material_invalid") from None
