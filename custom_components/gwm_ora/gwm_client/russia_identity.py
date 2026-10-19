"""Secret-safe handling of Russia's static client-certificate identity.

The Russian app gateway uses a bundled regional identity rather than the
enrolled identity used by Europe.  Its legacy TLS mechanics are otherwise the
same, so this module binds the exact Russian bootstrap name and delegates the
key recovery, chain validation, temporary-file handling, and isolated OpenSSL
policy to the already hardened EU bootstrap implementation.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

from .eu_identity import (
    EuBootstrapMaterial,
    EuIdentityError,
    _load_single_certificate,
    create_eu_bootstrap_ssl_context,
)

_RUSSIA_BOOTSTRAP_SUBJECT: Final = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "LGWGWM-AD-RU-GENERAL"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EE System Design Dept."),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Great Wall Motor Co., Ltd."),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Operational"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "APP"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "cybersecurity@gwm.cn"),
    ]
)
_RUSSIA_BOOTSTRAP_ISSUER: Final = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "IOV APP General SubCA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "EE System Design Dept."),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Great Wall Motor Co., Ltd."),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "cybersecurity@gwm.cn"),
    ]
)
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
        "identity_rsa_contract_invalid",
        "identity_subject_invalid",
        "time_invalid",
        "tls_context_invalid",
    }
)


class RussiaIdentityError(ValueError):
    """A fixed-category failure that never includes identity material."""

    __slots__ = ("category",)

    def __init__(self, category: object) -> None:
        self.category = (
            category
            if isinstance(category, str) and category in _SAFE_ERROR_CATEGORIES
            else "identity_invalid"
        )
        super().__init__(self.category)

    def __repr__(self) -> str:
        return f"RussiaIdentityError(category={self.category!r})"


@dataclass(frozen=True, slots=True)
class RussiaBootstrapMaterial:
    """Bundled Russian app identity and its three-certificate trust bundle."""

    certificate_data: bytes = field(repr=False)
    transformed_private_key_data: bytes = field(repr=False)
    ca_bundle: bytes = field(repr=False)

    def __post_init__(self) -> None:
        try:
            _as_eu_bootstrap_material(self)
        except EuIdentityError as error:
            raise RussiaIdentityError(error.category) from None


def create_russia_bootstrap_ssl_context(
    material: RussiaBootstrapMaterial,
    *,
    now: datetime | None = None,
) -> ssl.SSLContext:
    """Create the isolated legacy TLS context for Russian app-gateway calls."""

    if type(material) is not RussiaBootstrapMaterial:
        raise RussiaIdentityError("bootstrap_identity_invalid")
    try:
        delegated_material = _as_eu_bootstrap_material(material)
        certificate = _load_single_certificate(delegated_material.certificate_data)
        _validate_russia_bootstrap_name(certificate)
        return create_eu_bootstrap_ssl_context(delegated_material, now=now)
    except RussiaIdentityError:
        raise
    except EuIdentityError as error:
        raise RussiaIdentityError(error.category) from None
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise RussiaIdentityError("bootstrap_identity_invalid") from None


def _as_eu_bootstrap_material(material: RussiaBootstrapMaterial) -> EuBootstrapMaterial:
    return EuBootstrapMaterial(
        certificate_data=material.certificate_data,
        transformed_private_key_data=material.transformed_private_key_data,
        ca_bundle=material.ca_bundle,
    )


def _validate_russia_bootstrap_name(certificate: x509.Certificate) -> None:
    if certificate.subject != _RUSSIA_BOOTSTRAP_SUBJECT:
        raise RussiaIdentityError("identity_subject_invalid")
    if certificate.issuer != _RUSSIA_BOOTSTRAP_ISSUER:
        raise RussiaIdentityError("identity_issuer_invalid")


__all__ = [
    "RussiaBootstrapMaterial",
    "RussiaIdentityError",
    "create_russia_bootstrap_ssl_context",
]
