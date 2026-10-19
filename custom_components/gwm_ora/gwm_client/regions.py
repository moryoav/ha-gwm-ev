"""Immutable regional routing and request-header contracts for GWM cloud APIs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from .signing import (
    ANZ_BT_AUTH,
    EU_BT_AUTH,
    EU_GWM_AUTH,
    RUSSIA_GWM_AUTH,
    SigningProfile,
)

_COUNTRY_CODE = re.compile(r"[A-Z]{2}")
_DEVICE_ID = re.compile(r"[0-9A-Fa-f-]+")
_MAX_DEVICE_ID_LENGTH: Final = 64
_MAX_ACCESS_TOKEN_LENGTH: Final = 16 * 1024


class Region(StrEnum):
    """Supported GWM cloud regions."""

    EU = "eu"
    ANZ = "aus"
    RUSSIA = "rus"


class GatewayRole(StrEnum):
    """Logical GWM gateway roles used by known protocol operations."""

    H5_V1 = "h5_v1"
    AUTH_V2 = "auth_v2"
    APP_V1 = "app_v1"
    CERTIFICATE_V1 = "certificate_v1"


class TlsMode(StrEnum):
    """TLS identity and policy required by one gateway connection."""

    DEFAULT = "default"
    EU_BOOTSTRAP_MTLS = "eu_bootstrap_mtls"
    EU_ISSUED_MTLS = "eu_issued_mtls"
    RUSSIA_BOOTSTRAP_MTLS = "russia_bootstrap_mtls"


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Origin, signing profile, and TLS mode for a logical gateway."""

    role: GatewayRole
    base_url: str
    signing_profile: SigningProfile
    tls_mode: TlsMode


@dataclass(frozen=True, slots=True)
class RegionProtocol:
    """Immutable wire-level policy for one GWM cloud region."""

    region: Region
    gateways: Mapping[GatewayRole, GatewayConfig]
    base_headers: Mapping[str, str]
    device_id_length: int | None
    allowed_countries: frozenset[str] | None

    def __post_init__(self) -> None:
        gateways = dict(self.gateways)
        if any(role != config.role for role, config in gateways.items()):
            raise ValueError("gateway role does not match its configuration")
        object.__setattr__(self, "gateways", MappingProxyType(gateways))
        object.__setattr__(self, "base_headers", MappingProxyType(dict(self.base_headers)))
        object.__setattr__(
            self,
            "allowed_countries",
            None if self.allowed_countries is None else frozenset(self.allowed_countries),
        )

    def gateway(self, role: GatewayRole | str) -> GatewayConfig:
        """Return a supported gateway configuration without leaking input values."""

        try:
            normalized_role = role if isinstance(role, GatewayRole) else GatewayRole(role)
        except (TypeError, ValueError):
            raise ValueError("unsupported gateway role") from None
        try:
            return self.gateways[normalized_role]
        except KeyError:
            raise ValueError("gateway role is not supported by the region") from None

    def validate_country(self, country: str) -> str:
        """Validate an already-normalized uppercase ISO-2 country code."""

        if not isinstance(country, str) or _COUNTRY_CODE.fullmatch(country) is None:
            raise ValueError("country must be an uppercase ISO-2 code")
        if self.allowed_countries is not None and country not in self.allowed_countries:
            raise ValueError("country is not supported by the region")
        return country

    def normalize_device_id(self, device_id: str) -> str:
        """Apply the region's exact device-ID representation."""

        if (
            not isinstance(device_id, str)
            or not device_id
            or len(device_id) > _MAX_DEVICE_ID_LENGTH
            or _DEVICE_ID.fullmatch(device_id) is None
            or not device_id.replace("-", "")
        ):
            raise ValueError("device ID must contain only hexadecimal characters and hyphens")

        if self.device_id_length is None:
            return device_id

        normalized = device_id.replace("-", "")
        return (
            normalized[: self.device_id_length]
            if len(normalized) >= self.device_id_length
            else normalized.ljust(self.device_id_length, "0")
        )

    def authenticated_headers(
        self,
        *,
        country: str,
        device_id: str,
        access_token: str,
    ) -> Mapping[str, str]:
        """Build immutable request-local headers without retaining the token."""

        normalized_country = self.validate_country(country)
        normalized_device_id = self.normalize_device_id(device_id)
        if (
            not isinstance(access_token, str)
            or not access_token
            or len(access_token) > _MAX_ACCESS_TOKEN_LENGTH
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in access_token)
        ):
            raise ValueError("access token must be visible ASCII and within the size limit")

        return MappingProxyType(
            {
                **self.base_headers,
                "country": normalized_country,
                "regionCode": normalized_country,
                "deviceId": normalized_device_id,
                "iccid": normalized_device_id,
                "accessToken": access_token,
            }
        )


def _gateway(
    role: GatewayRole,
    base_url: str,
    signing_profile: SigningProfile,
    tls_mode: TlsMode,
) -> GatewayConfig:
    return GatewayConfig(role, base_url, signing_profile, tls_mode)


_EU_HEADERS: Final = {
    "rs": "2",
    "terminal": "GW_APP_GWM",
    "brand": "6",
    "language": "en",
    "systemType": "1",
    "cVer": "1.3.0",
    "secVersion": "2.0",
    "appId": "6",
    "channel": "APP",
    "enterpriseId": "CC01",
}

_ANZ_HEADERS: Final = {
    "rs": "2",
    "terminal": "GW_APP_Haval",
    "brand": "1",
    "enterpriseId": "CC01",
    "appId": "1",
    "channel": "APP",
    "cVer": "1.0.0",
    "systemType": "1",
    "language": "en_US",
}

_RUSSIA_HEADERS: Final = {
    "rs": "2",
    "terminal": "GW_APP_Haval",
    "brand": "1",
    "enterpriseId": "CC01",
    "brandId": "CCZ001",
    "appId": "1",
    "channel": "APP",
    "systemType": "1",
    "cVer": "1.0.0",
    "communityBrand": "1",
    "language": "ru",
    "secVersion": "2.0",
}

_PROTOCOLS: Final[Mapping[Region, RegionProtocol]] = MappingProxyType(
    {
        Region.EU: RegionProtocol(
            region=Region.EU,
            gateways={
                GatewayRole.H5_V1: _gateway(
                    GatewayRole.H5_V1,
                    "https://eu-h5-gateway.gwmcloud.com/app-api/api/v1.0/",
                    EU_BT_AUTH,
                    TlsMode.DEFAULT,
                ),
                GatewayRole.AUTH_V2: _gateway(
                    GatewayRole.AUTH_V2,
                    "https://eu-h5-gateway.gwmcloud.com/app-api/api/v2.0/",
                    EU_GWM_AUTH,
                    TlsMode.DEFAULT,
                ),
                GatewayRole.APP_V1: _gateway(
                    GatewayRole.APP_V1,
                    "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/",
                    EU_BT_AUTH,
                    TlsMode.EU_ISSUED_MTLS,
                ),
                GatewayRole.CERTIFICATE_V1: _gateway(
                    GatewayRole.CERTIFICATE_V1,
                    "https://eu-app-gateway-common.gwmcloud.com/app-api/api/v1.0/",
                    EU_BT_AUTH,
                    TlsMode.EU_BOOTSTRAP_MTLS,
                ),
            },
            base_headers=_EU_HEADERS,
            device_id_length=16,
            allowed_countries=None,
        ),
        Region.ANZ: RegionProtocol(
            region=Region.ANZ,
            gateways={
                GatewayRole.H5_V1: _gateway(
                    GatewayRole.H5_V1,
                    "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/",
                    ANZ_BT_AUTH,
                    TlsMode.DEFAULT,
                ),
                GatewayRole.AUTH_V2: _gateway(
                    GatewayRole.AUTH_V2,
                    "https://aus-h5-gateway.gwmcloud.com/app-api/api/v2.0/",
                    ANZ_BT_AUTH,
                    TlsMode.DEFAULT,
                ),
                GatewayRole.APP_V1: _gateway(
                    GatewayRole.APP_V1,
                    "https://aus-h5-gateway.gwmcloud.com/app-api/api/v1.0/",
                    ANZ_BT_AUTH,
                    TlsMode.DEFAULT,
                ),
            },
            base_headers=_ANZ_HEADERS,
            device_id_length=16,
            allowed_countries=frozenset({"AU", "NZ"}),
        ),
        Region.RUSSIA: RegionProtocol(
            region=Region.RUSSIA,
            gateways={
                GatewayRole.H5_V1: _gateway(
                    GatewayRole.H5_V1,
                    "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/",
                    RUSSIA_GWM_AUTH,
                    TlsMode.DEFAULT,
                ),
                GatewayRole.APP_V1: _gateway(
                    GatewayRole.APP_V1,
                    "https://rus-app-gateway.gwmcloud.com/app-api/api/v1.0/",
                    RUSSIA_GWM_AUTH,
                    TlsMode.RUSSIA_BOOTSTRAP_MTLS,
                ),
            },
            base_headers=_RUSSIA_HEADERS,
            device_id_length=None,
            allowed_countries=frozenset({"RU"}),
        ),
    }
)


def get_region_protocol(region: Region | str) -> RegionProtocol:
    """Return the immutable protocol for an enum or normalized string region."""

    try:
        normalized = region if isinstance(region, Region) else Region(region.strip().lower())
    except (AttributeError, TypeError, ValueError):
        raise ValueError("unsupported region") from None
    return _PROTOCOLS[normalized]
