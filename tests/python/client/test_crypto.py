"""Offline tests for GWM certificate material and enrollment CSRs."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.gwm_client.crypto import (
    generate_client_certificate_request,
    load_certificate,
    recover_transformed_private_key,
)

RESOURCE_DIR = (
    Path(__file__).resolve().parents[3]
    / "custom_components"
    / "gwm_ora"
    / "resources"
)


@pytest.mark.parametrize(
    ("certificate_name", "key_name", "expected_common_name", "expected_country"),
    [
        ("gwm_general.cer", "gwm_general.key", "LGWGWM-AD-EU-GENERAL", "DE"),
        ("gwm_general_rus.cer", "gwm_general_rus.key", "LGWGWM-AD-RU-GENERAL", "RU"),
    ],
)
def test_transformed_private_key_recovery_matches_certificate(
    certificate_name: str,
    key_name: str,
    expected_common_name: str,
    expected_country: str,
) -> None:
    certificate_data = (RESOURCE_DIR / certificate_name).read_bytes()
    certificate = load_certificate(certificate_data)
    private_key = recover_transformed_private_key(
        certificate_data,
        (RESOURCE_DIR / key_name).read_bytes(),
    )

    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    country = certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    assert common_name == expected_common_name
    assert country == expected_country
    assert private_key.key_size == 2048
    assert private_key.public_key().public_numbers() == certificate.public_key().public_numbers()
    private_numbers = private_key.private_numbers()
    assert private_numbers.p * private_numbers.q == private_numbers.public_numbers.n
    assert private_numbers.dmp1 == rsa.rsa_crt_dmp1(private_numbers.d, private_numbers.p)
    assert private_numbers.dmq1 == rsa.rsa_crt_dmq1(private_numbers.d, private_numbers.q)
    assert private_numbers.iqmp == rsa.rsa_crt_iqmp(private_numbers.p, private_numbers.q)

    message = b"offline GWM transformed-key proof"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    certificate.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize(
    ("chain_name", "country"),
    [("gwm_root.pem", b"DE"), ("gwm_root_rus.pem", b"RU")],
)
def test_regional_ca_bundle_contains_expected_legacy_subjects(
    chain_name: str,
    country: bytes,
) -> None:
    bundle = (RESOURCE_DIR / chain_name).read_bytes()
    blocks = re.findall(
        br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        bundle,
        re.DOTALL,
    )
    certificates = [base64.b64decode(b"".join(block.splitlines()[1:-1]), validate=True) for block in blocks]

    # Modern cryptography rejects invalid PrintableString characters in these
    # OEM CAs. Inspect their DER subject values without mutating the signed data;
    # the TLS tests separately prove that OpenSSL loads the complete bundles.
    assert len(certificates) == 3
    assert any(b"IOV APP General SubCA" in certificate for certificate in certificates)
    assert any(b"IOV APP SubCA" in certificate for certificate in certificates)
    country_attribute = b"\x06\x03\x55\x04\x06\x0c\x02" + country
    assert any(country_attribute in certificate for certificate in certificates)


def test_transformed_key_rejects_mismatched_certificate() -> None:
    with pytest.raises(ValueError, match="does not match"):
        recover_transformed_private_key(
            (RESOURCE_DIR / "gwm_general.cer").read_bytes(),
            (RESOURCE_DIR / "gwm_general_rus.key").read_bytes(),
        )


def test_transformed_key_rejects_changed_placeholder() -> None:
    encoded = (RESOURCE_DIR / "gwm_general.key").read_bytes()
    der = bytearray(base64.b64decode(encoded, validate=True))
    assert der[-1] == 1
    der[-1] = 2

    with pytest.raises(ValueError, match="structure"):
        recover_transformed_private_key(
            (RESOURCE_DIR / "gwm_general.cer").read_bytes(),
            base64.b64encode(der),
        )


def test_generate_client_certificate_request_matches_enrollment_contract() -> None:
    now = datetime.fromtimestamp(1786119079, tz=UTC)
    generated = generate_client_certificate_request(
        " il ",
        "01234567-89ab-cdef-0123-456789abcdef",
        now=now,
    )

    csr = x509.load_der_x509_csr(base64.b64decode(generated.csr, validate=True))
    private_key = serialization.load_der_private_key(
        base64.b64decode(generated.private_key, validate=True),
        password=None,
    )

    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048
    assert csr.is_signature_valid
    assert csr.signature_hash_algorithm.name == "sha256"
    assert isinstance(csr.signature_algorithm_parameters, padding.PKCS1v15)
    assert csr.public_key().public_numbers() == private_key.public_key().public_numbers()
    assert [attribute.oid for rdn in csr.subject.rdns for attribute in rdn] == [
        NameOID.COMMON_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
    ]
    assert len(csr.extensions) == 0
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "LGWMy GWM-AD-IL0123456789ABCDEF0123456789ABCDEF1786119079"
    )
    assert csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Great Wall Motor Co., Ltd."
    assert csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "EE System Design Dept"
    assert csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Operational"


def test_generate_client_certificate_request_pads_short_device_id() -> None:
    generated = generate_client_certificate_request(
        "ru",
        "abc-def",
        now=datetime.fromtimestamp(1, tz=UTC),
    )
    csr = x509.load_der_x509_csr(base64.b64decode(generated.csr, validate=True))

    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "LGWMy GWM-AD-RUABCDEF000000000000000000000000001"
    )


def test_sensitive_crypto_material_is_not_in_repr() -> None:
    generated = generate_client_certificate_request(
        "IL",
        "sensitive-device-id",
        now=datetime.fromtimestamp(1, tz=UTC),
    )

    representation = repr(generated)
    assert generated.csr not in representation
    assert generated.private_key not in representation
