"""A dedicated TLS context for GWM endpoints with legacy requirements."""

from __future__ import annotations

import base64
import binascii
import os
import re
import ssl
from collections.abc import Callable

LEGACY_CIPHER_STRING = "DEFAULT@SECLEVEL=0"
_GWM_CA_CERTIFICATE_COUNT = 3
_PEM_CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<payload>.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)
Password = str | bytes | Callable[[], str | bytes]
PathLike = str | bytes | os.PathLike[str] | os.PathLike[bytes]


def create_gwm_ssl_context(
    *,
    ca_data: str | bytes | None = None,
    certfile: PathLike | None = None,
    keyfile: PathLike | None = None,
    password: Password | None = None,
) -> ssl.SSLContext:
    """Build an isolated client context without changing OpenSSL process state.

    The legacy security level is applied only to the returned ``SSLContext``.
    System trust remains enabled; a GWM PEM chain and mutual-TLS identity can be
    added for the regional app gateways.
    """

    if keyfile is not None and certfile is None:
        raise ValueError("certfile is required when keyfile is provided")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.set_ciphers(LEGACY_CIPHER_STRING)

    if ca_data is not None:
        pem_data = ca_data.decode("ascii") if isinstance(ca_data, bytes) else ca_data
        _validate_gwm_ca_bundle(pem_data)
        context.load_verify_locations(cadata=pem_data)
    if certfile is not None:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=password)

    return context


def _validate_gwm_ca_bundle(pem_data: str) -> None:
    matches = list(_PEM_CERTIFICATE.finditer(pem_data))
    if len(matches) != _GWM_CA_CERTIFICATE_COUNT:
        raise ValueError(f"The GWM CA bundle must contain {_GWM_CA_CERTIFICATE_COUNT} certificates")

    cursor = 0
    for match in matches:
        if pem_data[cursor : match.start()].strip():
            raise ValueError("Unexpected data outside GWM CA certificates")
        cursor = match.end()
        payload = "".join(match.group("payload").split())
        try:
            der = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("Invalid base64 in GWM CA bundle") from error
        _validate_der_certificate_envelope(der)

    if pem_data[cursor:].strip():
        raise ValueError("Unexpected data outside GWM CA certificates")


def _validate_der_certificate_envelope(der: bytes) -> None:
    if len(der) < 2 or der[0] != 0x30:
        raise ValueError("Invalid DER certificate in GWM CA bundle")

    first_length = der[1]
    if first_length < 0x80:
        header_length = 2
        content_length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or 2 + length_bytes > len(der):
            raise ValueError("Invalid DER certificate length in GWM CA bundle")
        header_length = 2 + length_bytes
        content_length = int.from_bytes(der[2:header_length], "big")

    if header_length + content_length != len(der):
        raise ValueError("Truncated or trailing DER certificate data in GWM CA bundle")
