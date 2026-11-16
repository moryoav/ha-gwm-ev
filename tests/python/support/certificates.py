"""Synthetic certificate authorities for offline regional TLS journeys."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class CertificateAuthority:
    certificate: x509.Certificate
    key: rsa.RSAPrivateKey


def authority(name: str, issuer: CertificateAuthority | None = None) -> CertificateAuthority:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.certificate.subject if issuer else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer.key.public_key() if issuer else key.public_key(),
        ), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True)
        .sign(issuer.key if issuer else key, hashes.SHA256())
    )
    return CertificateAuthority(certificate, key)


def sign_csr(csr: str, issuer: CertificateAuthority, *, days: float = 30, server: bool = False) -> x509.Certificate:
    request = x509.load_der_x509_csr(base64.b64decode(csr, validate=True))
    assert request.is_signature_valid
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder().subject_name(request.subject).issuer_name(issuer.certificate.subject)
        .public_key(request.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
    )
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName(name) for name in (
                "localhost", "rus-h5-gateway.gwmcloud.com", "rus-app-gateway-common.gwmcloud.com",
                "rus-app-gateway.gwmcloud.com",
            )
        ]), critical=False)
    return builder.sign(issuer.key, hashes.SHA256())


@dataclass
class RegionalCertificateChain:
    root: CertificateAuthority
    general: CertificateAuthority
    issued: CertificateAuthority

    @classmethod
    def create(cls) -> RegionalCertificateChain:
        root = authority("Synthetic GWM Root CA")
        return cls(root, authority("IOV APP General SubCA", root), authority("IOV APP SubCA", root))

    @property
    def bundle(self) -> bytes:
        return b"".join(ca.certificate.public_bytes(serialization.Encoding.PEM) for ca in (
            self.root, self.general, self.issued,
        ))
