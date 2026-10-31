"""APAC gateway policy for the regional read-only integration.

The profile must be supplied by the caller and no credentials are bundled.
This module alone does not implement authentication or make network requests.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .apac_material import ApacMaterial
from .regions import GatewayConfig, GatewayRole, TlsMode

_CALLING_CODES = MappingProxyType({"TH": "+66", "MY": "+60", "ID": "+62", "PK": "+92"})


def apac_gateways(material: ApacMaterial) -> Mapping[GatewayRole, GatewayConfig]:
    """Construct request routing with externally provided signing material."""
    if type(material) is not ApacMaterial:
        raise ValueError("apac_material_invalid")
    profile = material.signing_profile()
    return MappingProxyType(
        {
            GatewayRole.H5_V1: GatewayConfig(
                GatewayRole.H5_V1,
                "https://ap-h5-gateway.gwmcloud.com/app-api/api/v1.0/",
                profile,
                TlsMode.DEFAULT,
            ),
            GatewayRole.AUTH_V2: GatewayConfig(
                GatewayRole.AUTH_V2,
                "https://ap-h5-gateway.gwmcloud.com/app-api/api/v2.0/",
                profile,
                TlsMode.DEFAULT,
            ),
            GatewayRole.APP_V1: GatewayConfig(
                GatewayRole.APP_V1,
                "https://ap-app-gateway.gwmcloud.com/app-api/api/v1.0/",
                profile,
                TlsMode.APAC_ISSUED_MTLS,
            ),
            GatewayRole.CERTIFICATE_V1: GatewayConfig(
                GatewayRole.CERTIFICATE_V1,
                "https://ap-app-gateway-common.gwmcloud.com/app-api/api/v1.0/",
                profile,
                TlsMode.APAC_BOOTSTRAP_MTLS,
            ),
        }
    )


def validate_apac_country(country: str) -> str:
    """Accept the four countries listed by the My GWM APAC app.

    All four use the regional gateways and country-specific request headers.
    """
    if not isinstance(country, str) or country not in _CALLING_CODES:
        raise ValueError("apac_country_invalid")
    return country


def apac_calling_code(country: str) -> str:
    """Return the calling code for an explicitly selected APAC country."""
    return _CALLING_CODES[validate_apac_country(country)]
