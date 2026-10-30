"""Synthetic APAC certificate chain tests; no real material is used."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.gwm_client.apac_identity import (
    _is_validated_context,
    _scoped_bundle,
    create_apac_issued_context,
)
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_request import prepare_apac_request
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIdentityError, EuIssuedIdentity
from custom_components.gwm_ora.gwm_client.regions import TlsMode

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _authority(name: str):
    """Generate an independent synthetic RSA certificate authority."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _issued(authority, authority_key, *, signing_key=None):
    """Generate a synthetic leaf identity signed by the selected authority."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-leaf")]))
        .issuer_name(authority.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(signing_key or authority_key, hashes.SHA256())
    )
    return EuIssuedIdentity(
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
        base64.b64encode(
            key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        ).decode(),
    )


def test_apac_issuer_chain_is_checked_without_eu_changes() -> None:
    """Verify the APAC issued identity and reject a mismatched signature."""
    authorities = [_authority(n) for n in ("GWM Root CA", "IOV APP General SubCA", "IOV APP SubCA", "IOV APP SubCA2")]
    bundle = b"\n".join(c.public_bytes(serialization.Encoding.PEM) for c, _ in authorities)
    cert, key = authorities[-1]
    context = create_apac_issued_context(_issued(cert, key), ca_bundle=bundle, now=NOW)
    assert context.check_hostname
    assert context.verify_mode.value == 2
    assert _is_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    assert not _is_validated_context(context, TlsMode.APAC_BOOTSTRAP_MTLS)
    request = prepare_apac_request(
        operation="acquire_vehicles",
        material=ApacMaterial(
            EuBootstrapMaterial(b"synthetic-cert", b"c3ludGhldGljLWtleQ==", bundle), "synthetic-key", "synthetic-secret"
        ),
        ssl_context=context,
        device_id="a" * 32,
        country="PK",
        access_token="synthetic-token",
    )
    assert request.ssl_context is context
    assert len(_scoped_bundle(bundle).split(b"-----BEGIN CERTIFICATE-----")) == 4
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(EuIdentityError, match="^identity_chain_invalid$"):
        create_apac_issued_context(_issued(cert, key, signing_key=wrong_key), ca_bundle=bundle, now=NOW)


def test_missing_intermediate_is_rejected() -> None:
    """Reject bundles that omit the required APAC intermediate."""
    authorities = [_authority(n) for n in ("GWM Root CA", "IOV APP General SubCA", "IOV APP SubCA", "incorrect")]
    bundle = b"\n".join(c.public_bytes(serialization.Encoding.PEM) for c, _ in authorities)
    with pytest.raises(EuIdentityError, match="^ca_bundle_invalid$"):
        _scoped_bundle(bundle)
