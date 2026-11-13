"""Locate and load the BR mTLS material bundled with the component.

The installation ships ``gwm_general.cer``, ``gwm_general.key`` and
``gwm_root.cer`` in ``resources/br/``, as it does for APAC. A missing or corrupt
bundle fails setup without falling back to anything else. Nothing here logs file
contents, and the directory is never created or written by the integration.
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Final

from .br_material import BrMaterial, create_br_ssl_context, load_br_material
from .errors import GwmConfigurationError

_SOURCE_DIRECTORY: Final = Path(__file__).resolve().parent
_DIRECTORY_NAME: Final = ("resources", "br")
_KEY: Final = "gwm_general.key"
_LEAF: Final = "gwm_general.cer"
_ROOT_BUNDLE: Final = "gwm_root.cer"


class GwmBrMaterialMissingError(GwmConfigurationError):
    """The BR mTLS directory or one of the required files is absent."""

    _message = "GWM BR mTLS material is missing"


class GwmBrMaterialInvalidError(GwmConfigurationError):
    """The BR mTLS files exist but are unusable."""

    _message = "GWM BR mTLS material is invalid"


def installed_br_directory() -> Path:
    """Directory of the bundled BR files inside the installed component."""
    return _SOURCE_DIRECTORY.parent.joinpath(*_DIRECTORY_NAME)


def missing_br_files(directory: Path) -> list[str]:
    """Bundled names that are absent, or an empty list when the set is complete."""
    return [name for name in (_LEAF, _KEY, _ROOT_BUNDLE) if not (directory / name).is_file()]


def load_installed_br_material() -> BrMaterial:
    """Load the bundled material from the installed component (blocking I/O)."""
    directory = installed_br_directory()
    if missing_br_files(directory):
        raise GwmBrMaterialMissingError(operation="login")
    try:
        return load_br_material(directory)
    except (OSError, TypeError, ValueError):
        raise GwmBrMaterialInvalidError(operation="login") from None


def load_installed_br_context() -> ssl.SSLContext:
    """Load the material and build the mTLS context (blocking; run in a thread)."""
    material = load_installed_br_material()
    try:
        return create_br_ssl_context(material)
    except (OSError, TypeError, ValueError, ssl.SSLError):
        raise GwmBrMaterialInvalidError(operation="login") from None
