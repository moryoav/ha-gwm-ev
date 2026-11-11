"""Locate and load the BR mTLS material installed with the component.

The material is NOT distributed. The user copies ``gwm_general.cer``,
``gwm_general.key`` and ``gwm_root.cer`` (or ``gwm_client_fullchain.pem`` plus the
key) into ``custom_components/gwm_ora/resources/br/`` once. Nothing here logs file
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
_CHAIN: Final = "gwm_client_fullchain.pem"
_LEAF: Final = "gwm_general.cer"
_ROOT_BUNDLE: Final = "gwm_root.cer"


class GwmBrMaterialMissingError(GwmConfigurationError):
    """The BR mTLS directory or one of the required files is absent."""

    _message = "GWM BR mTLS material is missing"


class GwmBrMaterialInvalidError(GwmConfigurationError):
    """The BR mTLS files exist but are unusable."""

    _message = "GWM BR mTLS material is invalid"


def installed_br_directory() -> Path:
    """Directory inside the installed component where the user places the files."""
    return _SOURCE_DIRECTORY.parent.joinpath(*_DIRECTORY_NAME)


def missing_br_files(directory: Path) -> list[str]:
    """Names still needed, or an empty list when a complete set is present."""
    if not directory.is_dir():
        return [_LEAF, _KEY, _ROOT_BUNDLE]
    has = {name for name in (_KEY, _CHAIN, _LEAF, _ROOT_BUNDLE) if (directory / name).is_file()}
    missing = [] if _KEY in has else [_KEY]
    if _CHAIN not in has:
        missing += [name for name in (_LEAF, _ROOT_BUNDLE) if name not in has]
    return missing


def load_installed_br_material() -> BrMaterial:
    """Load the material from the installed component directory (blocking I/O)."""
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
