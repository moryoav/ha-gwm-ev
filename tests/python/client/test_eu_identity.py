"""Offline contract tests for EU certificate identities and scoped mutual TLS."""

from __future__ import annotations

import base64
import os
import ssl
import stat
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from custom_components.gwm_ora.gwm_client.eu_identity import (
    EuBootstrapMaterial,
    EuIdentityError,
    EuIssuedIdentity,
    create_eu_bootstrap_ssl_context,
    create_eu_issued_ssl_context,
    is_eu_issued_identity_usable,
)
from custom_components.gwm_ora.gwm_client.tls import create_gwm_ssl_context as _base_gwm_ssl_context

NOW = datetime(2030, 6, 1, 12, 0, tzinfo=UTC)
RESOURCE_DIR = Path(__file__).resolve().parents[3] / "custom_components" / "gwm_ora" / "resources"


@dataclass(frozen=True, slots=True)
class _CertificateAuthority:
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey


@dataclass(frozen=True, slots=True)
class _TestChain:
    root: _CertificateAuthority
    issued_intermediate: _CertificateAuthority
    bootstrap_intermediate: _CertificateAuthority

    @property
    def ca_bundle(self) -> bytes:
        return b"".join(
            authority.certificate.public_bytes(serialization.Encoding.PEM)
            for authority in (
                self.root,
                self.bootstrap_intermediate,
                self.issued_intermediate,
            )
        )


@pytest.fixture(scope="module")
def certificate_chain() -> _TestChain:
    root_key = _new_key()
    root_name = _name("Synthetic GWM Root CA")
    root_certificate = _ca_certificate(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        signing_key=root_key,
    )
    root = _CertificateAuthority(root_certificate, root_key)
    return _TestChain(
        root=root,
        issued_intermediate=_new_intermediate("IOV APP SubCA", root),
        bootstrap_intermediate=_new_intermediate("IOV APP General SubCA", root),
    )


def test_material_types_are_immutable_and_hide_every_secret(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    issued = _issued_identity(certificate, private_key)
    bootstrap = _bootstrap_material(certificate_chain)

    assert repr(issued) == "EuIssuedIdentity()"
    assert repr(bootstrap) == "EuBootstrapMaterial()"
    for secret in (
        issued.certificate,
        issued.private_key,
        bootstrap.certificate_data.decode("ascii"),
        bootstrap.transformed_private_key_data.decode("ascii"),
        bootstrap.ca_bundle.decode("ascii"),
    ):
        assert secret not in repr(issued)
        assert secret not in repr(bootstrap)

    with pytest.raises(FrozenInstanceError):
        issued.certificate = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        bootstrap.ca_bundle = b"changed"  # type: ignore[misc]


def test_real_bundled_eu_bootstrap_builds_only_a_scoped_legacy_context() -> None:
    baseline = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    baseline_security = baseline.security_level
    material = EuBootstrapMaterial(
        certificate_data=(RESOURCE_DIR / "gwm_general.cer").read_bytes(),
        transformed_private_key_data=(RESOURCE_DIR / "gwm_general.key").read_bytes(),
        ca_bundle=(RESOURCE_DIR / "gwm_root.pem").read_bytes(),
    )

    context = create_eu_bootstrap_ssl_context(
        material,
        now=datetime(2026, 8, 24, tzinfo=UTC),
    )

    assert context.security_level == 0
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert ssl.create_default_context(ssl.Purpose.SERVER_AUTH).security_level == baseline_security


def test_bootstrap_identity_remains_usable_during_its_final_day(
    certificate_chain: _TestChain,
) -> None:
    final_day = _bootstrap_material(
        certificate_chain,
        not_after=NOW + timedelta(hours=1),
    )
    expired = _bootstrap_material(
        certificate_chain,
        not_after=NOW,
    )

    assert create_eu_bootstrap_ssl_context(final_day, now=NOW).security_level == 0
    with pytest.raises(EuIdentityError, match="^identity_expired$"):
        create_eu_bootstrap_ssl_context(expired, now=NOW)


@pytest.mark.parametrize(
    "replacement",
    [
        pytest.param("not-base64", id="alphabet"),
        pytest.param("YWJj\n", id="whitespace"),
        pytest.param("YWJj====", id="padding"),
        pytest.param("A" * (64 * 1024 + 4), id="oversized"),
    ],
)
def test_issued_material_requires_bounded_canonical_base64(replacement: str) -> None:
    with pytest.raises(EuIdentityError) as raised:
        EuIssuedIdentity(replacement, "YWJj")

    assert raised.value.category == "issued_certificate_encoding_invalid"
    assert replacement not in repr(raised.value)


@pytest.mark.parametrize(
    "replacement",
    [
        pytest.param(b"not-base64", id="alphabet"),
        pytest.param(b"YWJj\n", id="whitespace"),
        pytest.param(b"YWJj====", id="padding"),
        pytest.param(b"A" * (64 * 1024 + 4), id="oversized"),
    ],
)
def test_bootstrap_transformed_key_requires_bounded_canonical_base64(
    replacement: bytes,
    certificate_chain: _TestChain,
) -> None:
    valid = _bootstrap_material(certificate_chain)
    with pytest.raises(EuIdentityError) as raised:
        EuBootstrapMaterial(valid.certificate_data, replacement, valid.ca_bundle)

    assert raised.value.category == "bootstrap_private_key_encoding_invalid"
    assert replacement.decode("ascii", errors="ignore") not in repr(raised.value)


def test_issued_identity_usability_accepts_only_canonical_der(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    valid = _issued_identity(certificate, private_key)
    malformed_der = EuIssuedIdentity(
        base64.b64encode(b"not a DER certificate").decode("ascii"),
        valid.private_key,
    )

    assert is_eu_issued_identity_usable(valid, now=NOW)
    assert not is_eu_issued_identity_usable(malformed_der, now=NOW)


@pytest.mark.parametrize(
    ("not_before", "not_after", "usable"),
    [
        (NOW + timedelta(minutes=5), NOW + timedelta(days=2), True),
        (NOW + timedelta(minutes=5, seconds=1), NOW + timedelta(days=2), False),
        (NOW - timedelta(days=1), NOW + timedelta(hours=24), False),
        (NOW - timedelta(days=1), NOW + timedelta(hours=24, seconds=1), True),
    ],
)
def test_issued_identity_validity_boundaries_are_exact(
    not_before: datetime,
    not_after: datetime,
    usable: bool,
    certificate_chain: _TestChain,
) -> None:
    certificate, private_key = _new_leaf(
        certificate_chain.issued_intermediate,
        not_before=not_before,
        not_after=not_after,
    )

    assert is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW) is usable


def test_issued_context_distinguishes_renewal_window_from_expiry(
    certificate_chain: _TestChain,
) -> None:
    renewing_certificate, renewing_key = _new_leaf(
        certificate_chain.issued_intermediate,
        not_after=NOW + timedelta(hours=1),
    )
    expired_certificate, expired_key = _new_leaf(
        certificate_chain.issued_intermediate,
        not_after=NOW,
    )

    with pytest.raises(EuIdentityError, match="^identity_renewal_required$"):
        create_eu_issued_ssl_context(
            _issued_identity(renewing_certificate, renewing_key),
            ca_bundle=certificate_chain.ca_bundle,
            now=NOW,
        )
    with pytest.raises(EuIdentityError, match="^identity_expired$"):
        create_eu_issued_ssl_context(
            _issued_identity(expired_certificate, expired_key),
            ca_bundle=certificate_chain.ca_bundle,
            now=NOW,
        )


def test_issued_identity_rejects_key_mismatch_and_wrong_issuer(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    _other_certificate, other_key = _new_leaf(certificate_chain.issued_intermediate)
    wrong_issuer_certificate, wrong_issuer_key = _new_leaf(
        certificate_chain.issued_intermediate,
        issuer_name=_name("Unexpected SubCA"),
    )

    assert not is_eu_issued_identity_usable(_issued_identity(certificate, other_key), now=NOW)
    assert not is_eu_issued_identity_usable(
        _issued_identity(wrong_issuer_certificate, wrong_issuer_key),
        now=NOW,
    )
    assert is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW)


@pytest.mark.parametrize(
    ("key_size", "public_exponent"),
    [(1024, 65537), (2048, 3)],
)
def test_issued_identity_enforces_rsa_2048_and_exponent_65537(
    key_size: int,
    public_exponent: int,
    certificate_chain: _TestChain,
) -> None:
    key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate, key=key)

    assert not is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW)


@pytest.mark.parametrize(
    ("basic_ca", "digital_signature", "client_auth", "usable"),
    [
        (False, True, True, True),
        (True, True, True, False),
        (False, False, True, False),
        (False, True, False, False),
        (None, None, None, True),
    ],
)
def test_leaf_extensions_are_enforced_when_present(
    basic_ca: bool | None,
    digital_signature: bool | None,
    client_auth: bool | None,
    usable: bool,
    certificate_chain: _TestChain,
) -> None:
    certificate, private_key = _new_leaf(
        certificate_chain.issued_intermediate,
        basic_ca=basic_ca,
        digital_signature=digital_signature,
        client_auth=client_auth,
    )

    assert is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW) is usable


def test_leaf_key_usage_rejects_certificate_signing(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(
        certificate_chain.issued_intermediate,
        key_cert_sign=True,
    )

    assert not is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW)


def test_any_extended_key_usage_satisfies_client_auth_contract(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(
        certificate_chain.issued_intermediate,
        client_auth=False,
        any_extended_key_usage=True,
    )

    assert is_eu_issued_identity_usable(_issued_identity(certificate, private_key), now=NOW)


def test_issued_context_contains_only_leaf_and_direct_intermediate_and_cleans_files(
    certificate_chain: _TestChain,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    identity = _issued_identity(certificate, private_key)
    temporary_root = tmp_path / "temporary-identities"
    temporary_root.mkdir()
    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.tempfile.tempdir", str(temporary_root))
    original_open = os.open
    creation_modes: list[int] = []
    captured_chain = b""

    def capturing_open(
        path: os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & os.O_CREAT:
            creation_modes.append(mode)
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def capturing_context_factory(**kwargs: Any) -> ssl.SSLContext:
        nonlocal captured_chain
        certfile = Path(kwargs["certfile"])
        keyfile = Path(kwargs["keyfile"])
        captured_chain = certfile.read_bytes()
        assert keyfile.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
        if os.name == "posix":
            assert stat.S_IMODE(certfile.parent.stat().st_mode) == 0o700
            assert stat.S_IMODE(certfile.stat().st_mode) == 0o600
            assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
        return _base_gwm_ssl_context(**kwargs)

    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.os.open", capturing_open)
    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.create_gwm_ssl_context", capturing_context_factory)
    default_before = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    context = create_eu_issued_ssl_context(
        identity,
        ca_bundle=certificate_chain.ca_bundle,
        now=NOW,
    )

    assert context.security_level == 0
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert ssl.create_default_context(ssl.Purpose.SERVER_AUTH).security_level == default_before.security_level
    assert creation_modes == [0o600, 0o600]
    assert list(temporary_root.iterdir()) == []
    chain_blocks = _pem_blocks(captured_chain)
    assert len(chain_blocks) == 2
    assert _der(chain_blocks[0]) == certificate.public_bytes(serialization.Encoding.DER)
    assert _der(chain_blocks[1]) == certificate_chain.issued_intermediate.certificate.public_bytes(
        serialization.Encoding.DER
    )
    assert certificate_chain.root.certificate.public_bytes(serialization.Encoding.DER) not in captured_chain
    assert (
        certificate_chain.bootstrap_intermediate.certificate.public_bytes(serialization.Encoding.DER)
        not in captured_chain
    )


def test_bootstrap_context_recovers_transformed_key_and_uses_general_intermediate(
    certificate_chain: _TestChain,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _bootstrap_material(certificate_chain)
    captured_chain = b""

    def capturing_context_factory(**kwargs: Any) -> ssl.SSLContext:
        nonlocal captured_chain
        captured_chain = Path(kwargs["certfile"]).read_bytes()
        return _base_gwm_ssl_context(**kwargs)

    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.create_gwm_ssl_context", capturing_context_factory)

    context = create_eu_bootstrap_ssl_context(material, now=NOW)

    assert context.security_level == 0
    chain_blocks = _pem_blocks(captured_chain)
    assert len(chain_blocks) == 2
    assert _der(chain_blocks[1]) == certificate_chain.bootstrap_intermediate.certificate.public_bytes(
        serialization.Encoding.DER
    )


def test_context_rejects_missing_ambiguous_or_non_signing_intermediate(
    certificate_chain: _TestChain,
) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    identity = _issued_identity(certificate, private_key)
    two_certificate_bundle = b"".join(
        authority.certificate.public_bytes(serialization.Encoding.PEM)
        for authority in (certificate_chain.root, certificate_chain.issued_intermediate)
    )
    ambiguous_bundle = b"".join(
        authority.certificate.public_bytes(serialization.Encoding.PEM)
        for authority in (
            certificate_chain.root,
            certificate_chain.issued_intermediate,
            certificate_chain.issued_intermediate,
        )
    )
    rogue_key = _new_key()
    rogue_certificate, rogue_private_key = _new_leaf(
        certificate_chain.issued_intermediate,
        signing_key=rogue_key,
    )

    for invalid_identity, invalid_bundle, expected_category in (
        (identity, two_certificate_bundle, "ca_bundle_invalid"),
        (identity, ambiguous_bundle, "ca_intermediate_invalid"),
        (
            _issued_identity(rogue_certificate, rogue_private_key),
            certificate_chain.ca_bundle,
            "identity_chain_invalid",
        ),
    ):
        with pytest.raises(EuIdentityError) as raised:
            create_eu_issued_ssl_context(invalid_identity, ca_bundle=invalid_bundle, now=NOW)
        assert raised.value.category == expected_category


def test_temporary_identity_files_are_cleaned_when_tls_loading_fails(
    certificate_chain: _TestChain,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    temporary_root = tmp_path / "failed-identities"
    temporary_root.mkdir()
    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.tempfile.tempdir", str(temporary_root))

    def fail_context_factory(**_kwargs: Any) -> ssl.SSLContext:
        raise ssl.SSLError("SENSITIVE KEY MATERIAL MUST NOT ESCAPE")

    monkeypatch.setattr("custom_components.gwm_ora.gwm_client.eu_identity.create_gwm_ssl_context", fail_context_factory)

    with pytest.raises(EuIdentityError, match="^tls_context_invalid$") as raised:
        create_eu_issued_ssl_context(
            _issued_identity(certificate, private_key),
            ca_bundle=certificate_chain.ca_bundle,
            now=NOW,
        )

    assert list(temporary_root.iterdir()) == []
    assert "SENSITIVE" not in repr(raised.value)


def test_naive_validation_time_is_rejected_without_material_in_error(certificate_chain: _TestChain) -> None:
    certificate, private_key = _new_leaf(certificate_chain.issued_intermediate)
    identity = _issued_identity(certificate, private_key)

    with pytest.raises(EuIdentityError, match="^time_invalid$") as raised:
        create_eu_issued_ssl_context(
            identity,
            ca_bundle=certificate_chain.ca_bundle,
            now=datetime(2030, 1, 1),
        )

    assert identity.certificate not in repr(raised.value)
    assert identity.private_key not in repr(raised.value)


def test_arbitrary_error_categories_are_sanitized() -> None:
    error = EuIdentityError("SENSITIVE ARBITRARY MATERIAL")

    assert error.category == "identity_invalid"
    assert str(error) == "identity_invalid"
    assert "SENSITIVE" not in repr(error)


def _new_key(*, key_size: int = 2048, public_exponent: int = 65537) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ca_certificate(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key: rsa.RSAPublicKey,
    signing_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(signing_key, hashes.SHA256())
    )


def _new_intermediate(common_name: str, root: _CertificateAuthority) -> _CertificateAuthority:
    private_key = _new_key()
    certificate = _ca_certificate(
        subject=_name(common_name),
        issuer=root.certificate.subject,
        public_key=private_key.public_key(),
        signing_key=root.private_key,
    )
    return _CertificateAuthority(certificate, private_key)


def _new_leaf(
    issuer: _CertificateAuthority,
    *,
    key: rsa.RSAPrivateKey | None = None,
    signing_key: rsa.RSAPrivateKey | None = None,
    issuer_name: x509.Name | None = None,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=30),
    basic_ca: bool | None = False,
    digital_signature: bool | None = True,
    key_cert_sign: bool = False,
    client_auth: bool | None = True,
    any_extended_key_usage: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    private_key = key or _new_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("Synthetic EU Client"))
        .issuer_name(issuer_name or issuer.certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if basic_ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=basic_ca, path_length=None), critical=True)
    if digital_signature is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if client_auth is not None:
        usages = [ExtendedKeyUsageOID.CLIENT_AUTH] if client_auth else [ExtendedKeyUsageOID.SERVER_AUTH]
        if any_extended_key_usage:
            usages.append(ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE)
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
    return builder.sign(signing_key or issuer.private_key, hashes.SHA256()), private_key


def _issued_identity(certificate: x509.Certificate, private_key: rsa.RSAPrivateKey) -> EuIssuedIdentity:
    return EuIssuedIdentity(
        base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        base64.b64encode(
            private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode("ascii"),
    )


def _bootstrap_material(
    chain: _TestChain,
    *,
    not_after: datetime = NOW + timedelta(days=30),
) -> EuBootstrapMaterial:
    certificate, private_key = _new_leaf(
        chain.bootstrap_intermediate,
        not_after=not_after,
    )
    return EuBootstrapMaterial(
        certificate.public_bytes(serialization.Encoding.PEM),
        _transformed_private_key(private_key),
        chain.ca_bundle,
    )


def _transformed_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    numbers = private_key.private_numbers()
    transformed_private_exponent = _transform_private_exponent(numbers.d)
    sequence = b"".join(
        _der_integer(value)
        for value in (
            0,
            numbers.public_numbers.n,
            1,
            transformed_private_exponent,
            1,
            1,
            1,
            1,
            1,
        )
    )
    return base64.b64encode(b"\x30" + _der_length(len(sequence)) + sequence)


def _transform_private_exponent(number: int) -> int:
    group_count = (number.bit_length() + 4) // 5
    groups = [(number >> (5 * (group_count - index - 1))) & 0x1F for index in range(group_count)]
    transformed = groups[0]
    for group in groups[1:]:
        transformed = (transformed << 5) | ((group & 0x18) | ((group - 3) & 0x07))
    return transformed


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _der_length(len(encoded)) + encoded


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _pem_blocks(data: bytes) -> list[bytes]:
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    blocks: list[bytes] = []
    cursor = 0
    while True:
        start = data.find(begin, cursor)
        if start < 0:
            return blocks
        finish = data.find(end, start)
        assert finish >= 0
        finish += len(end)
        blocks.append(data[start:finish])
        cursor = finish


def _der(pem: bytes) -> bytes:
    return base64.b64decode(b"".join(pem.splitlines()[1:-1]), validate=True)
