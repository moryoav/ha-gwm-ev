"""Pakistan gateway policy, not yet registered as a supported region.

The profile must be supplied by the caller and no credentials are bundled.
This module alone does not implement authentication or make network requests.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .pakistan_material import PakistanMaterial
from .regions import GatewayConfig, GatewayRole, TlsMode


def pakistan_gateways(material: PakistanMaterial) -> Mapping[GatewayRole, GatewayConfig]:
    """Construct request routing with externally provided signing material."""
    if type(material) is not PakistanMaterial:
        raise ValueError("pakistan_material_invalid")
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
                TlsMode.EU_ISSUED_MTLS,
            ),
            GatewayRole.CERTIFICATE_V1: GatewayConfig(
                GatewayRole.CERTIFICATE_V1,
                "https://ap-app-gateway-common.gwmcloud.com/app-api/api/v1.0/",
                profile,
                TlsMode.EU_BOOTSTRAP_MTLS,
            ),
        }
    )


def validate_pakistan_country(country: str) -> str:
    """Restrict the unverified regional integration to the tested country."""
    if country != "PK":
        raise ValueError("pakistan_country_invalid")
    return country
