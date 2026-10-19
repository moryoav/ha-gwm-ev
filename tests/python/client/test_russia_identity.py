"""Offline contract tests for Russia's static mutual-TLS identity."""

from __future__ import annotations

import ssl
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import custom_components.gwm_ora.gwm_client.russia_identity as russia_identity
from custom_components.gwm_ora.gwm_client.eu_identity import EuIdentityError
from custom_components.gwm_ora.gwm_client.russia_identity import (
    RussiaBootstrapMaterial,
    RussiaIdentityError,
    create_russia_bootstrap_ssl_context,
)

NOW = datetime(2026, 8, 28, tzinfo=UTC)
RESOURCE_DIR = Path(__file__).resolve().parents[3] / "custom_components" / "gwm_ora" / "resources"


def test_material_is_immutable_and_hides_every_identity_byte() -> None:
    material = _real_material()

    assert repr(material) == "RussiaBootstrapMaterial()"
    for identity_data in (
        material.certificate_data,
        material.transformed_private_key_data,
        material.ca_bundle,
    ):
        assert identity_data.decode("ascii") not in repr(material)

    with pytest.raises(FrozenInstanceError):
        material.ca_bundle = b"changed"  # type: ignore[misc]


def test_real_russia_bootstrap_builds_only_a_scoped_legacy_context() -> None:
    baseline_security = ssl.create_default_context(ssl.Purpose.SERVER_AUTH).security_level

    context = create_russia_bootstrap_ssl_context(_real_material(), now=NOW)

    assert context.security_level == 0
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert ssl.create_default_context(ssl.Purpose.SERVER_AUTH).security_level == baseline_security


@pytest.mark.parametrize(
    ("subject_common_name", "country", "issuer_common_name", "category"),
    [
        pytest.param(
            "LGWGWM-AD-EU-GENERAL",
            "RU",
            "IOV APP General SubCA",
            "identity_subject_invalid",
            id="wrong-subject-common-name",
        ),
        pytest.param(
            "LGWGWM-AD-RU-GENERAL",
            "DE",
            "IOV APP General SubCA",
            "identity_subject_invalid",
            id="wrong-subject-country",
        ),
        pytest.param(
            "LGWGWM-AD-RU-GENERAL",
            "RU",
            "Unexpected General SubCA",
            "identity_issuer_invalid",
            id="wrong-issuer",
        ),
    ],
)
def test_bootstrap_name_is_bound_before_key_recovery_or_tls_loading(
    subject_common_name: str,
    country: str,
    issuer_common_name: str,
    category: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = RussiaBootstrapMaterial(
        certificate_data=_certificate(
            subject=_russia_subject(common_name=subject_common_name, country=country),
            issuer=_russia_issuer(common_name=issuer_common_name),
        ).public_bytes(serialization.Encoding.PEM),
        transformed_private_key_data=b"YWJj",
        ca_bundle=b"synthetic-ca-bundle",
    )

    def unexpected_delegation(*_args: object, **_kwargs: object) -> ssl.SSLContext:
        pytest.fail("a name-mismatched identity must not reach key recovery or TLS loading")

    monkeypatch.setattr(russia_identity, "create_eu_bootstrap_ssl_context", unexpected_delegation)

    with pytest.raises(RussiaIdentityError, match=f"^{category}$") as raised:
        create_russia_bootstrap_ssl_context(material, now=NOW)

    assert raised.value.category == category


def test_bootstrap_material_reuses_strict_bounded_key_validation() -> None:
    with pytest.raises(RussiaIdentityError, match="^bootstrap_private_key_encoding_invalid$") as raised:
        RussiaBootstrapMaterial(
            certificate_data=b"synthetic-certificate",
            transformed_private_key_data=b"not canonical base64",
            ca_bundle=b"synthetic-ca-bundle",
        )

    assert raised.value.category == "bootstrap_private_key_encoding_invalid"
    assert "not canonical base64" not in repr(raised.value)


def test_delegated_identity_failures_are_mapped_without_chaining_or_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = _real_material()

    def fail_validation(*_args: object, **_kwargs: object) -> ssl.SSLContext:
        raise EuIdentityError("identity_key_mismatch")

    monkeypatch.setattr(russia_identity, "create_eu_bootstrap_ssl_context", fail_validation)

    with pytest.raises(RussiaIdentityError, match="^identity_key_mismatch$") as raised:
        create_russia_bootstrap_ssl_context(material, now=NOW)

    assert raised.value.__cause__ is None
    assert material.transformed_private_key_data.decode("ascii") not in repr(raised.value)


def test_wrong_public_type_and_arbitrary_categories_fail_closed() -> None:
    with pytest.raises(RussiaIdentityError, match="^bootstrap_identity_invalid$"):
        create_russia_bootstrap_ssl_context(object())  # type: ignore[arg-type]

    error = RussiaIdentityError("SENSITIVE ARBITRARY MATERIAL")
    assert error.category == "identity_invalid"
    assert str(error) == "identity_invalid"
    assert "SENSITIVE" not in repr(error)


def _real_material() -> RussiaBootstrapMaterial:
    return RussiaBootstrapMaterial(
        certificate_data=(RESOURCE_DIR / "gwm_general_rus.cer").read_bytes(),
        transformed_private_key_data=(RESOURCE_DIR / "gwm_general_rus.key").read_bytes(),
        ca_bundle=(RESOURCE_DIR / "gwm_root_rus.pem").read_bytes(),
    )


def _russia_subject(
    *,
    common_name: str = "LGWGWM-AD-RU-GENERAL",
    country: str = "RU",
) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EE System Design Dept."),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Great Wall Motor Co., Ltd."),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Operational"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "APP"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "cybersecurity@gwm.cn"),
        ]
    )


def _russia_issuer(*, common_name: str = "IOV APP General SubCA") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EE System Design Dept."),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Great Wall Motor Co., Ltd."),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "cybersecurity@gwm.cn"),
        ]
    )


def _certificate(*, subject: x509.Name, issuer: x509.Name) -> x509.Certificate:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
