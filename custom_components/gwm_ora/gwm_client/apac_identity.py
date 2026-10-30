"""Strict APAC client-identity validation without changing EU TLS rules.

The private caller supplies the four-certificate CA bundle. This implementation
never bundles, downloads, or falls back to an unverified certificate.
"""

from __future__ import annotations

import binascii
import ssl
import threading
import weakref
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .eu_identity import (
    EuBootstrapMaterial,
    EuIdentityError,
    EuIssuedIdentity,
    _create_identity_context,
    _decode_canonical_base64,
    _der_subject_common_names,
    _normalized_now,
    _pem_certificate_blocks,
    _validate_leaf_identity,
    create_eu_bootstrap_ssl_context,
)
from .regions import TlsMode

_ROOT = "GWM Root CA"
_GENERAL = "IOV APP General SubCA"
_LEGACY_ISSUED = "IOV APP SubCA"
_APAC_ISSUED = "IOV APP SubCA2"
_CONTEXT_ROLES: weakref.WeakKeyDictionary[ssl.SSLContext, TlsMode] = weakref.WeakKeyDictionary()
_CONTEXT_LOCK = threading.Lock()


def _register_validated_context(context: ssl.SSLContext, mode: TlsMode) -> ssl.SSLContext:
    """Remember a validated identity's role without retaining its context."""
    with _CONTEXT_LOCK:
        _CONTEXT_ROLES[context] = mode
    return context


def _is_validated_context(context: ssl.SSLContext, mode: TlsMode) -> bool:
    """Accept only contexts returned by the matching APAC identity validator."""
    with _CONTEXT_LOCK:
        return _CONTEXT_ROLES.get(context) is mode


def _scoped_bundle(bundle: bytes) -> bytes:
    """Select the validated three authorities required by the APAC flow."""
    blocks = _pem_certificate_blocks(bundle, expected_count=4)
    by_subject: dict[str, bytes] = {}
    for pem, der in blocks:
        names = _der_subject_common_names(der)
        if len(names) != 1 or names[0] in by_subject:
            raise EuIdentityError("ca_bundle_invalid")
        by_subject[names[0]] = pem
    if set(by_subject) != {_ROOT, _GENERAL, _LEGACY_ISSUED, _APAC_ISSUED}:
        raise EuIdentityError("ca_bundle_invalid")
    return b"\n".join(by_subject[name] for name in (_ROOT, _GENERAL, _APAC_ISSUED)) + b"\n"


def create_apac_bootstrap_context(material: EuBootstrapMaterial, *, now: datetime | None = None) -> ssl.SSLContext:
    """Validate the bootstrap key/chain before creating a host-scoped context."""
    if type(material) is not EuBootstrapMaterial:
        raise EuIdentityError("bootstrap_identity_invalid")
    scoped = EuBootstrapMaterial(material.certificate_data, material.transformed_private_key_data, _scoped_bundle(material.ca_bundle))
    context = create_eu_bootstrap_ssl_context(scoped, now=now)
    return _register_validated_context(context, TlsMode.APAC_BOOTSTRAP_MTLS)


def create_apac_issued_context(
    identity: EuIssuedIdentity, *, ca_bundle: bytes, now: datetime | None = None,
) -> ssl.SSLContext:
    """Validate issued identity, issuer and signature without fallback."""
    if type(identity) is not EuIssuedIdentity:
        raise EuIdentityError("issued_identity_invalid")
    try:
        cert_der = _decode_canonical_base64(identity.certificate, maximum_length=64 * 1024, category="issued_certificate_encoding_invalid")
        key_der = _decode_canonical_base64(identity.private_key, maximum_length=64 * 1024, category="issued_private_key_encoding_invalid")
        certificate = x509.load_der_x509_certificate(cert_der)
        key = serialization.load_der_private_key(key_der, password=None)
        if certificate.public_bytes(serialization.Encoding.DER) != cert_der or not isinstance(key, rsa.RSAPrivateKey):
            raise EuIdentityError("issued_identity_invalid")
        if key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) != key_der:
            raise EuIdentityError("issued_private_key_encoding_invalid")
        _validate_leaf_identity(
            certificate, key, expected_issuer=_APAC_ISSUED,
            now=_normalized_now(now), minimum_remaining_validity=timedelta(hours=24),
        )
        context = _create_identity_context(
            certificate=certificate, private_key=key, ca_bundle=_scoped_bundle(ca_bundle), expected_issuer=_APAC_ISSUED,
        )
        return _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    except EuIdentityError:
        raise
    except (TypeError, ValueError, binascii.Error, UnsupportedAlgorithm):
        raise EuIdentityError("issued_identity_invalid") from None
