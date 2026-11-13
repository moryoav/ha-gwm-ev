"""Load the BR mutual-TLS client identity from a directory of PEM files.

The shared app files ship with the integration in ``resources/br`` (see
``br_installed``). Nothing here writes to that directory, and nothing logs file
contents.
"""

from __future__ import annotations

import os
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

_MAX_FILE_BYTES: Final = 256 * 1024
_CERT_BEGIN: Final = b"-----BEGIN CERTIFICATE-----"
_CERT_END: Final = b"-----END CERTIFICATE-----"


@dataclass(frozen=True, slots=True)
class BrMaterial:
    """Client certificate chain (leaf first) and private key, both PEM.

    Do not log or persist this object.
    """

    chain_pem: bytes = field(repr=False)
    key_pem: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Light textual check only.

        The vendor certificates carry attribute encodings that the strict
        ``cryptography`` parser refuses, so nothing here parses them. The real
        key/leaf match is enforced by OpenSSL in ``load_cert_chain``.
        """
        if (
            not isinstance(self.chain_pem, bytes)
            or not isinstance(self.key_pem, bytes)
            or len(_pem_blocks(self.chain_pem)) < 2
            or b"-----BEGIN " not in self.key_pem
            or b"PRIVATE KEY-----" not in self.key_pem
        ):
            raise ValueError("br_material_invalid")


def _pem_blocks(data: bytes) -> list[bytes]:
    """Split certificate PEM blocks textually, in order."""
    blocks: list[bytes] = []
    position = 0
    while (start := data.find(_CERT_BEGIN, position)) != -1:
        stop = data.find(_CERT_END, start)
        if stop == -1:
            raise ValueError("br_material_invalid")
        stop += len(_CERT_END)
        blocks.append(data[start:stop])
        position = stop
    return blocks


def _read_file(directory: Path, name: str) -> bytes | None:
    """Read one bounded regular file inside the directory; None when absent."""
    path = directory / name
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return None
    if not resolved.is_relative_to(directory) or not resolved.is_file():
        raise ValueError("br_material_invalid")
    with resolved.open("rb") as source:
        data = source.read(_MAX_FILE_BYTES + 1)
    if not data or len(data) > _MAX_FILE_BYTES:
        raise ValueError("br_material_invalid")
    return data


def load_br_material(directory: Path) -> BrMaterial:
    """Load the client identity from an absolute directory.

    The chain is ``gwm_general.cer`` followed by every block of ``gwm_root.cer``;
    the key is ``gwm_general.key``.
    """
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise ValueError("br_material_invalid")
    try:
        directory = directory.resolve(strict=True)
        key = _read_file(directory, "gwm_general.key")
        leaf = _read_file(directory, "gwm_general.cer")
        bundle = _read_file(directory, "gwm_root.cer")
        if key is None or leaf is None or bundle is None:
            raise ValueError("br_material_invalid")
        leaves, extras = _pem_blocks(leaf), _pem_blocks(bundle)
        if len(leaves) != 1 or not extras:
            raise ValueError("br_material_invalid")
        # Leaf first, then the whole bundle: OpenSSL uses what it needs.
        chain = b"\n".join(leaves + extras) + b"\n"
        return BrMaterial(chain, key)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("br_material_invalid") from None


def create_br_ssl_context(material: BrMaterial) -> ssl.SSLContext:
    """Build the mTLS client context presenting the FULL chain.

    The vendor chain uses a weak digest, so OpenSSL security level 0 is scoped
    to this dedicated context. The server certificate is verified against the
    system trust store (no pinning needed); hostname checking stays on.
    """
    if type(material) is not BrMaterial:
        raise ValueError("br_material_invalid")
    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError, ssl.SSLError):
        pass
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        with tempfile.TemporaryDirectory(prefix="gwm-br-identity-") as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            certfile = directory / "client.pem"
            keyfile = directory / "client.key"
            for path, data in ((certfile, material.chain_pem), (keyfile, material.key_pem)):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
            context.load_cert_chain(str(certfile), str(keyfile))
    except (OSError, ssl.SSLError):
        raise ValueError("br_material_invalid") from None
    if context.security_level != 0 or not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("br_material_invalid")
    return context
