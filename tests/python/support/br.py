"""Synthetic helpers for the BR tests: dummy certificates and a fake transport."""

from __future__ import annotations

import base64
import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issue(subject: str, issuer: str, public_key, signing_key) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(signing_key, hashes.SHA256())
    )


def write_dummy_material(directory: Path, *, fullchain: bool = True, key_mismatch: bool = False) -> None:
    """Write throwaway certificates shaped like the real set, never the real material."""
    root_key, mid_key, other_key, leaf_key = (rsa.generate_private_key(65537, 2048) for _ in range(4))
    root = _issue("Dummy Root CA", "Dummy Root CA", root_key.public_key(), root_key)
    other = _issue("Dummy Other SubCA", "Dummy Root CA", other_key.public_key(), root_key)
    mid = _issue("IOV APP General SubCA", "Dummy Root CA", mid_key.public_key(), root_key)
    leaf = _issue("dummy-client", "IOV APP General SubCA", leaf_key.public_key(), mid_key)
    pem = serialization.Encoding.PEM
    leaf_pem, mid_pem = leaf.public_bytes(pem), mid.public_bytes(pem)
    signer = rsa.generate_private_key(65537, 2048) if key_mismatch else leaf_key
    (directory / "gwm_general.key").write_bytes(
        signer.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (directory / "gwm_general.cer").write_bytes(leaf_pem)
    (directory / "gwm_root.cer").write_bytes(b"".join(c.public_bytes(pem) for c in (root, other, mid)))
    if fullchain:
        (directory / "gwm_client_fullchain.pem").write_bytes(leaf_pem + mid_pem)


def fake_jwt(exp: int) -> str:
    """Unsigned three-part token with an exp claim."""
    def part(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part({'exp': exp})}.sig"


class FakeTransport:
    """Scripted responses; records requests; never opens a connection."""

    def __init__(self, *responses: _TransportResponse) -> None:
        self.responses = list(responses)
        self.requests = []
        self.closed = False

    async def execute(self, request, **_kwargs):
        self.requests.append(request)
        return self.responses.pop(0)

    async def aclose(self) -> None:
        self.closed = True


def envelope(data: object, code: str = "000000", description: str = "SUCCESS", status: int = 200) -> _TransportResponse:
    body = json.dumps({"code": code, "description": description, "data": data}).encode()
    return _TransportResponse(status, {"content-type": "application/json"}, body)


def html(status: int, text: str) -> _TransportResponse:
    return _TransportResponse(status, {"content-type": "text/html"}, f"<html><body><center>{text}</center></body></html>".encode())


def write_quirky_material(directory: Path) -> None:
    """Material whose certificates the strict ``cryptography`` parser rejects.

    Mirrors the vendor chain: the subject emailAddress is a PrintableString that
    contains "@". The tag of a freshly built certificate is patched in place;
    OpenSSL does not verify the signature when loading, so it still accepts it.
    """
    root_key, mid_key, leaf_key = (rsa.generate_private_key(65537, 2048) for _ in range(3))
    email = b"dummy@example.invalid"

    def quirky(subject: str, issuer: str, public_key, signing_key) -> bytes:
        """Build a PEM certificate whose subject carries a PrintableString emailAddress that strict parsers reject."""
        now = datetime.now(UTC)
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, subject), x509.NameAttribute(NameOID.EMAIL_ADDRESS, email.decode())]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(_name(issuer))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(signing_key, hashes.SHA256())
        )
        der = certificate.public_bytes(serialization.Encoding.DER)
        marker = b"\x16" + bytes([len(email)]) + email  # IA5String
        assert marker in der
        der = der.replace(marker, b"\x13" + bytes([len(email)]) + email)  # PrintableString
        return ssl.DER_cert_to_PEM_cert(der).encode()

    root = quirky("Dummy Root CA", "Dummy Root CA", root_key.public_key(), root_key)
    mid = quirky("IOV APP General SubCA", "Dummy Root CA", mid_key.public_key(), root_key)
    leaf = quirky("dummy-client", "IOV APP General SubCA", leaf_key.public_key(), mid_key)
    pem = serialization.Encoding.PEM
    (directory / "gwm_general.key").write_bytes(
        leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (directory / "gwm_general.cer").write_bytes(leaf)
    (directory / "gwm_root.cer").write_bytes(root + mid)
