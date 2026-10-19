"""Secret-safe, offline EU client-certificate identity handling.

The GWM EU gateways require a client certificate and a legacy OpenSSL security
level.  This module keeps that compatibility policy scoped to one dedicated
``SSLContext`` and never persists certificate or private-key material.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from .crypto import recover_transformed_private_key
from .tls import create_gwm_ssl_context

_ISSUED_ISSUER: Final = "IOV APP SubCA"
_BOOTSTRAP_ISSUER: Final = "IOV APP General SubCA"
_MAX_CERTIFICATE_BASE64: Final = 64 * 1024
_MAX_PRIVATE_KEY_BASE64: Final = 64 * 1024
_MAX_CERTIFICATE_DATA: Final = 64 * 1024
_MAX_CA_BUNDLE: Final = 256 * 1024
_MAX_TRANSFORMED_KEY: Final = 64 * 1024
_NOT_BEFORE_SKEW: Final = timedelta(minutes=5)
_MIN_REMAINING_VALIDITY: Final = timedelta(hours=24)
_PEM_BLOCK: Final = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_PEM_BEGIN: Final = b"-----BEGIN CERTIFICATE-----"
_PEM_END: Final = b"-----END CERTIFICATE-----"
_COMMON_NAME_OID_DER: Final = b"\x55\x04\x03"
_SAFE_ERROR_CATEGORIES: Final = frozenset(
    {
        "bootstrap_certificate_encoding_invalid",
        "bootstrap_identity_invalid",
        "bootstrap_private_key_encoding_invalid",
        "ca_bundle_invalid",
        "ca_intermediate_invalid",
        "identity_basic_constraints_invalid",
        "identity_chain_invalid",
        "identity_extended_key_usage_invalid",
        "identity_expired",
        "identity_extensions_invalid",
        "identity_invalid",
        "identity_issuer_invalid",
        "identity_key_mismatch",
        "identity_key_usage_invalid",
        "identity_not_yet_valid",
        "identity_renewal_required",
        "identity_rsa_contract_invalid",
        "issued_certificate_encoding_invalid",
        "issued_identity_invalid",
        "issued_identity_key_invalid",
        "issued_private_key_encoding_invalid",
        "time_invalid",
        "tls_context_invalid",
    }
)


class EuIdentityError(ValueError):
    """A fixed-category failure that never includes certificate material."""

    __slots__ = ("category",)

    def __init__(self, category: object) -> None:
        self.category = (
            category if isinstance(category, str) and category in _SAFE_ERROR_CATEGORIES else "identity_invalid"
        )
        super().__init__(self.category)

    def __repr__(self) -> str:
        return f"EuIdentityError(category={self.category!r})"


@dataclass(frozen=True, slots=True)
class EuIssuedIdentity:
    """Canonical base64 DER certificate and PKCS#8 key returned by GWM."""

    certificate: str = field(repr=False)
    private_key: str = field(repr=False)

    def __post_init__(self) -> None:
        _decode_canonical_base64(
            self.certificate,
            maximum_length=_MAX_CERTIFICATE_BASE64,
            category="issued_certificate_encoding_invalid",
        )
        _decode_canonical_base64(
            self.private_key,
            maximum_length=_MAX_PRIVATE_KEY_BASE64,
            category="issued_private_key_encoding_invalid",
        )


@dataclass(frozen=True, slots=True)
class EuBootstrapMaterial:
    """Bundled EU enrollment identity and its three-certificate trust bundle."""

    certificate_data: bytes = field(repr=False)
    transformed_private_key_data: bytes = field(repr=False)
    ca_bundle: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_bounded_bytes(
            self.certificate_data,
            maximum_length=_MAX_CERTIFICATE_DATA,
            category="bootstrap_certificate_encoding_invalid",
        )
        _require_bounded_bytes(
            self.transformed_private_key_data,
            maximum_length=_MAX_TRANSFORMED_KEY,
            category="bootstrap_private_key_encoding_invalid",
        )
        _require_bounded_bytes(
            self.ca_bundle,
            maximum_length=_MAX_CA_BUNDLE,
            category="ca_bundle_invalid",
        )
        _decode_canonical_base64_bytes(
            self.transformed_private_key_data,
            category="bootstrap_private_key_encoding_invalid",
        )


def is_eu_issued_identity_usable(
    identity: EuIssuedIdentity,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether an issued identity can safely be reused for over 24 hours."""

    instant = _normalized_now(now)
    try:
        _load_and_validate_issued_identity(identity, now=instant)
    except EuIdentityError:
        return False
    return True


def create_eu_issued_ssl_context(
    identity: EuIssuedIdentity,
    *,
    ca_bundle: bytes,
    now: datetime | None = None,
) -> ssl.SSLContext:
    """Create an isolated legacy TLS context for authenticated EU app calls."""

    instant = _normalized_now(now)
    certificate, private_key = _load_and_validate_issued_identity(identity, now=instant)
    return _create_identity_context(
        certificate=certificate,
        private_key=private_key,
        ca_bundle=ca_bundle,
        expected_issuer=_ISSUED_ISSUER,
    )


def create_eu_bootstrap_ssl_context(
    material: EuBootstrapMaterial,
    *,
    now: datetime | None = None,
) -> ssl.SSLContext:
    """Create an isolated legacy TLS context used only for certificate enrollment."""

    instant = _normalized_now(now)
    if not isinstance(material, EuBootstrapMaterial):
        raise EuIdentityError("bootstrap_identity_invalid")
    try:
        certificate = _load_single_certificate(material.certificate_data)
        private_key = recover_transformed_private_key(
            material.certificate_data,
            material.transformed_private_key_data,
        )
        _validate_leaf_identity(
            certificate,
            private_key,
            expected_issuer=_BOOTSTRAP_ISSUER,
            now=instant,
            minimum_remaining_validity=timedelta(0),
        )
    except EuIdentityError:
        raise
    except (TypeError, ValueError, binascii.Error, UnsupportedAlgorithm):
        raise EuIdentityError("bootstrap_identity_invalid") from None
    return _create_identity_context(
        certificate=certificate,
        private_key=private_key,
        ca_bundle=material.ca_bundle,
        expected_issuer=_BOOTSTRAP_ISSUER,
    )


def _load_and_validate_issued_identity(
    identity: EuIssuedIdentity,
    *,
    now: datetime,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    if not isinstance(identity, EuIssuedIdentity):
        raise EuIdentityError("issued_identity_invalid")
    try:
        certificate_der = _decode_canonical_base64(
            identity.certificate,
            maximum_length=_MAX_CERTIFICATE_BASE64,
            category="issued_certificate_encoding_invalid",
        )
        private_key_der = _decode_canonical_base64(
            identity.private_key,
            maximum_length=_MAX_PRIVATE_KEY_BASE64,
            category="issued_private_key_encoding_invalid",
        )
        certificate = x509.load_der_x509_certificate(certificate_der)
        if certificate.public_bytes(serialization.Encoding.DER) != certificate_der:
            raise EuIdentityError("issued_certificate_encoding_invalid")
        loaded_key = serialization.load_der_private_key(private_key_der, password=None)
        if not isinstance(loaded_key, rsa.RSAPrivateKey):
            raise EuIdentityError("issued_identity_key_invalid")
        canonical_key = loaded_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        if canonical_key != private_key_der:
            raise EuIdentityError("issued_private_key_encoding_invalid")
    except EuIdentityError:
        raise
    except (TypeError, ValueError, binascii.Error, UnsupportedAlgorithm):
        raise EuIdentityError("issued_identity_invalid") from None
    try:
        _validate_leaf_identity(
            certificate,
            loaded_key,
            expected_issuer=_ISSUED_ISSUER,
            now=now,
            minimum_remaining_validity=_MIN_REMAINING_VALIDITY,
        )
    except EuIdentityError:
        raise
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise EuIdentityError("issued_identity_invalid") from None
    return certificate, loaded_key


def _validate_leaf_identity(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    *,
    expected_issuer: str,
    now: datetime,
    minimum_remaining_validity: timedelta,
) -> None:
    public_key = certificate.public_key()
    if (
        not isinstance(public_key, rsa.RSAPublicKey)
        or public_key.key_size != 2048
        or public_key.public_numbers().e != 65537
        or private_key.key_size != 2048
        or private_key.public_key().public_numbers().e != 65537
    ):
        raise EuIdentityError("identity_rsa_contract_invalid")
    if public_key.public_numbers() != private_key.public_key().public_numbers():
        raise EuIdentityError("identity_key_mismatch")

    issuer_common_names = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(issuer_common_names) != 1 or issuer_common_names[0].value != expected_issuer:
        raise EuIdentityError("identity_issuer_invalid")

    not_valid_before, not_valid_after = _certificate_validity_utc(certificate)
    if not_valid_before > now + _NOT_BEFORE_SKEW:
        raise EuIdentityError("identity_not_yet_valid")
    if not_valid_after <= now:
        raise EuIdentityError("identity_expired")
    if not_valid_after <= now + minimum_remaining_validity:
        raise EuIdentityError("identity_renewal_required")

    basic_constraints = _optional_extension(certificate, ExtensionOID.BASIC_CONSTRAINTS)
    if basic_constraints is not None and (
        not isinstance(basic_constraints, x509.BasicConstraints) or basic_constraints.ca
    ):
        raise EuIdentityError("identity_basic_constraints_invalid")

    key_usage = _optional_extension(certificate, ExtensionOID.KEY_USAGE)
    if key_usage is not None and (
        not isinstance(key_usage, x509.KeyUsage) or not key_usage.digital_signature or key_usage.key_cert_sign
    ):
        raise EuIdentityError("identity_key_usage_invalid")

    extended_key_usage = _optional_extension(certificate, ExtensionOID.EXTENDED_KEY_USAGE)
    if extended_key_usage is not None and (
        not isinstance(extended_key_usage, x509.ExtendedKeyUsage)
        or not ({ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE} & set(extended_key_usage))
    ):
        raise EuIdentityError("identity_extended_key_usage_invalid")


def _optional_extension(
    certificate: x509.Certificate,
    oid: x509.ObjectIdentifier,
) -> x509.ExtensionType | None:
    try:
        return certificate.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    except ValueError:
        raise EuIdentityError("identity_extensions_invalid") from None


def _certificate_validity_utc(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    not_valid_before = getattr(certificate, "not_valid_before_utc", None)
    not_valid_after = getattr(certificate, "not_valid_after_utc", None)
    if not_valid_before is None or not_valid_after is None:
        not_valid_before = certificate.not_valid_before.replace(tzinfo=UTC)
        not_valid_after = certificate.not_valid_after.replace(tzinfo=UTC)
    return not_valid_before, not_valid_after


def _create_identity_context(
    *,
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    ca_bundle: bytes,
    expected_issuer: str,
) -> ssl.SSLContext:
    try:
        chain = _client_certificate_chain(
            certificate,
            ca_bundle,
            expected_issuer=expected_issuer,
        )
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with tempfile.TemporaryDirectory(prefix="gwm-eu-identity-") as temporary_directory:
            directory = Path(temporary_directory)
            os.chmod(directory, 0o700)
            certfile = directory / "client.pem"
            keyfile = directory / "client.key"
            _write_restricted_file(certfile, chain)
            _write_restricted_file(keyfile, private_key_pem)
            context = create_gwm_ssl_context(
                ca_data=ca_bundle,
                certfile=certfile,
                keyfile=keyfile,
            )
    except EuIdentityError:
        raise
    except (OSError, ssl.SSLError, TypeError, ValueError):
        raise EuIdentityError("tls_context_invalid") from None

    if context.security_level != 0 or not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise EuIdentityError("tls_context_invalid")
    return context


def _write_restricted_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file_handle:
            descriptor = -1
            file_handle.write(data)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _client_certificate_chain(
    certificate: x509.Certificate,
    ca_bundle: bytes,
    *,
    expected_issuer: str,
) -> bytes:
    blocks = _pem_certificate_blocks(ca_bundle, expected_count=3)
    matching: list[tuple[bytes, bytes]] = []
    for block, der in blocks:
        if _der_subject_common_names(der) == (expected_issuer,):
            matching.append((block, der))
    if len(matching) != 1:
        raise EuIdentityError("ca_intermediate_invalid")

    intermediate_block, intermediate_der = matching[0]
    try:
        issuer_public_key = serialization.load_der_public_key(_der_subject_public_key_info(intermediate_der))
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise EuIdentityError("ca_intermediate_invalid") from None
    if not isinstance(issuer_public_key, rsa.RSAPublicKey):
        raise EuIdentityError("ca_intermediate_invalid")

    try:
        parameters = certificate.signature_algorithm_parameters
        hash_algorithm = certificate.signature_hash_algorithm
        if not isinstance(parameters, padding.AsymmetricPadding) or hash_algorithm is None:
            raise EuIdentityError("identity_chain_invalid")
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            parameters,
            hash_algorithm,
        )
    except EuIdentityError:
        raise
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        raise EuIdentityError("identity_chain_invalid") from None

    leaf = certificate.public_bytes(serialization.Encoding.PEM)
    return leaf + intermediate_block.rstrip() + b"\n"


def _pem_certificate_blocks(data: bytes, *, expected_count: int) -> list[tuple[bytes, bytes]]:
    _require_bounded_bytes(data, maximum_length=_MAX_CA_BUNDLE, category="ca_bundle_invalid")
    matches = list(_PEM_BLOCK.finditer(data))
    if len(matches) != expected_count:
        raise EuIdentityError("ca_bundle_invalid")

    cursor = 0
    result: list[tuple[bytes, bytes]] = []
    for match in matches:
        if data[cursor : match.start()].strip():
            raise EuIdentityError("ca_bundle_invalid")
        cursor = match.end()
        block = match.group(0)
        payload = b"".join(block[len(_PEM_BEGIN) : -len(_PEM_END)].split())
        der = _decode_canonical_base64_bytes(payload, category="ca_bundle_invalid")
        _require_single_der_sequence(der, category="ca_bundle_invalid")
        result.append((block, der))
    if data[cursor:].strip():
        raise EuIdentityError("ca_bundle_invalid")
    return result


def _load_single_certificate(data: bytes) -> x509.Certificate:
    _require_bounded_bytes(
        data, maximum_length=_MAX_CERTIFICATE_DATA, category="bootstrap_certificate_encoding_invalid"
    )
    if data.startswith(_PEM_BEGIN):
        normalized = data.rstrip()
        blocks = _pem_certificate_blocks_with_limit(normalized)
        if len(blocks) != 1:
            raise EuIdentityError("bootstrap_certificate_encoding_invalid")
        der = blocks[0][1]
    else:
        der = data
        _require_single_der_sequence(der, category="bootstrap_certificate_encoding_invalid")
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError:
        raise EuIdentityError("bootstrap_certificate_encoding_invalid") from None
    if certificate.public_bytes(serialization.Encoding.DER) != der:
        raise EuIdentityError("bootstrap_certificate_encoding_invalid")
    return certificate


def _pem_certificate_blocks_with_limit(data: bytes) -> list[tuple[bytes, bytes]]:
    matches = list(_PEM_BLOCK.finditer(data))
    if len(matches) != 1 or data[: matches[0].start()].strip() or data[matches[0].end() :].strip():
        raise EuIdentityError("bootstrap_certificate_encoding_invalid")
    block = matches[0].group(0)
    payload = b"".join(block[len(_PEM_BEGIN) : -len(_PEM_END)].split())
    der = _decode_canonical_base64_bytes(payload, category="bootstrap_certificate_encoding_invalid")
    _require_single_der_sequence(der, category="bootstrap_certificate_encoding_invalid")
    return [(block, der)]


def _der_subject_common_names(certificate_der: bytes) -> tuple[str, ...]:
    subject_start, subject_end, _spki_start, _spki_end = _der_subject_and_spki(certificate_der)
    names: list[str] = []
    offset = subject_start
    while offset < subject_end:
        tag, set_start, set_end, offset = _read_der_tlv(certificate_der, offset)
        if tag != 0x31:
            raise EuIdentityError("ca_bundle_invalid")
        attribute_offset = set_start
        while attribute_offset < set_end:
            tag, attribute_start, attribute_end, attribute_offset = _read_der_tlv(
                certificate_der,
                attribute_offset,
            )
            if tag != 0x30:
                raise EuIdentityError("ca_bundle_invalid")
            oid_tag, oid_start, oid_end, value_offset = _read_der_tlv(certificate_der, attribute_start)
            value_tag, value_start, value_end, value_offset = _read_der_tlv(certificate_der, value_offset)
            if oid_tag != 0x06 or value_offset != attribute_end:
                raise EuIdentityError("ca_bundle_invalid")
            if certificate_der[oid_start:oid_end] == _COMMON_NAME_OID_DER:
                if value_tag not in {0x0C, 0x13, 0x16}:
                    raise EuIdentityError("ca_bundle_invalid")
                try:
                    names.append(certificate_der[value_start:value_end].decode("ascii"))
                except UnicodeDecodeError:
                    raise EuIdentityError("ca_bundle_invalid") from None
        if attribute_offset != set_end:
            raise EuIdentityError("ca_bundle_invalid")
    return tuple(names)


def _der_subject_public_key_info(certificate_der: bytes) -> bytes:
    _subject_start, _subject_end, spki_start, spki_end = _der_subject_and_spki(certificate_der)
    return certificate_der[spki_start:spki_end]


def _der_subject_and_spki(certificate_der: bytes) -> tuple[int, int, int, int]:
    tag, certificate_start, certificate_end, end = _read_der_tlv(certificate_der, 0)
    if tag != 0x30 or end != len(certificate_der):
        raise EuIdentityError("ca_bundle_invalid")
    tag, tbs_start, tbs_end, _offset = _read_der_tlv(certificate_der, certificate_start)
    if tag != 0x30:
        raise EuIdentityError("ca_bundle_invalid")

    offset = tbs_start
    tag, _start, _end, next_offset = _read_der_tlv(certificate_der, offset)
    if tag == 0xA0:
        offset = next_offset
    for expected_tag in (0x02, 0x30, 0x30, 0x30):
        tag, _start, _end, offset = _read_der_tlv(certificate_der, offset)
        if tag != expected_tag:
            raise EuIdentityError("ca_bundle_invalid")
    tag, subject_start, subject_end, offset = _read_der_tlv(certificate_der, offset)
    if tag != 0x30:
        raise EuIdentityError("ca_bundle_invalid")
    spki_tlv_start = offset
    tag, _spki_content_start, _spki_content_end, offset = _read_der_tlv(certificate_der, offset)
    if tag != 0x30 or offset > tbs_end:
        raise EuIdentityError("ca_bundle_invalid")
    return subject_start, subject_end, spki_tlv_start, offset


def _require_single_der_sequence(data: bytes, *, category: str) -> None:
    try:
        tag, _start, _end, final_offset = _read_der_tlv(data, 0)
    except EuIdentityError:
        raise EuIdentityError(category) from None
    if tag != 0x30 or final_offset != len(data):
        raise EuIdentityError(category)


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset < 0 or offset + 2 > len(data):
        raise EuIdentityError("ca_bundle_invalid")
    tag = data[offset]
    offset += 1
    first_length = data[offset]
    offset += 1
    if first_length < 0x80:
        length = first_length
    else:
        length_octets = first_length & 0x7F
        if length_octets == 0 or length_octets > 4 or offset + length_octets > len(data):
            raise EuIdentityError("ca_bundle_invalid")
        encoded_length = data[offset : offset + length_octets]
        if encoded_length[0] == 0:
            raise EuIdentityError("ca_bundle_invalid")
        length = int.from_bytes(encoded_length, "big")
        if length < 0x80:
            raise EuIdentityError("ca_bundle_invalid")
        offset += length_octets
    end = offset + length
    if end > len(data):
        raise EuIdentityError("ca_bundle_invalid")
    return tag, offset, end, end


def _decode_canonical_base64(
    value: str,
    *,
    maximum_length: int,
    category: str,
) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum_length or not value.isascii():
        raise EuIdentityError(category)
    try:
        encoded = value.encode("ascii")
        return _decode_canonical_base64_bytes(encoded, category=category)
    except UnicodeEncodeError:
        raise EuIdentityError(category) from None


def _decode_canonical_base64_bytes(value: bytes, *, category: str) -> bytes:
    if not value or len(value) % 4 != 0:
        raise EuIdentityError(category)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise EuIdentityError(category) from None
    if not decoded or base64.b64encode(decoded) != value:
        raise EuIdentityError(category)
    return decoded


def _require_bounded_bytes(value: bytes, *, maximum_length: int, category: str) -> None:
    if type(value) is not bytes or not value or len(value) > maximum_length:
        raise EuIdentityError(category)


def _normalized_now(now: datetime | None) -> datetime:
    instant = datetime.now(UTC) if now is None else now
    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        raise EuIdentityError("time_invalid")
    return instant.astimezone(UTC)


__all__ = [
    "EuBootstrapMaterial",
    "EuIdentityError",
    "EuIssuedIdentity",
    "create_eu_bootstrap_ssl_context",
    "create_eu_issued_ssl_context",
    "is_eu_issued_identity_usable",
]
