"""External material contract for the experimental APAC read-only client.

This module does not distribute app-derived material. Callers may supply
private material explicitly from a directory outside the repository.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .eu_identity import EuBootstrapMaterial
from .signing import SigningProfile

_MAX_FILE_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class ApacMaterial:
    """Caller-supplied private enrollment and signing material.

    Do not log or persist this object. It has no default or bundled material.
    """

    bootstrap: EuBootstrapMaterial = field(repr=False)
    app_key: str = field(repr=False)
    app_secret: str = field(repr=False)

    def __post_init__(self) -> None:
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


def load_apac_material(directory: Path) -> ApacMaterial:
    """Load explicitly provided local files; never log content or file paths.

    The directory must be supplied by the caller; this function has no default,
    does not download material and does not persist anything to the repository.
    """
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise ValueError("apac_material_invalid")
    try:
        def read_file(name: str) -> bytes:
            with (directory / name).open("rb") as source:
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
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError("apac_material_invalid") from None
