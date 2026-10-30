"""Allowlisted Pakistan authentication and vehicle-read request contracts.

No transport or Home Assistant integration is connected yet. Command and
charging operations are intentionally absent from this policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from .regions import GatewayRole


@dataclass(frozen=True, slots=True)
class PakistanEndpoint:
    """A fixed operation, method, gateway and relative path."""

    method: str
    gateway: GatewayRole
    path: str
    authenticated: bool


_ENDPOINTS = MappingProxyType(
    {
        "login": PakistanEndpoint("POST", GatewayRole.AUTH_V2, "userAuth/loginWithPassword", False),
        "request_verification": PakistanEndpoint("POST", GatewayRole.AUTH_V2, "userAuth/getVerifyCode", False),
        "verify_code": PakistanEndpoint("POST", GatewayRole.AUTH_V2, "userAuth/checkVerifyCode", False),
        "refresh_token": PakistanEndpoint("POST", GatewayRole.H5_V1, "userAuth/refreshToken", False),
        "get_user_info": PakistanEndpoint("GET", GatewayRole.H5_V1, "user/getUserBaseInfo", True),
        "enroll_certificate": PakistanEndpoint("POST", GatewayRole.CERTIFICATE_V1, "appAuth/applyCertificate", True),
        "acquire_vehicles": PakistanEndpoint("GET", GatewayRole.APP_V1, "globalapp/vehicle/acquireVehicles", True),
        "get_last_status": PakistanEndpoint("GET", GatewayRole.APP_V1, "vehicle/getLastStatus", True),
        "get_vehicle_basics": PakistanEndpoint("GET", GatewayRole.APP_V1, "vehicle/vehicleBasicsInfo", True),
    }
)


def pakistan_endpoint(operation: str) -> PakistanEndpoint:
    """Return a known read-only/authentication contract, or fail closed."""
    try:
        return _ENDPOINTS[operation]
    except (KeyError, TypeError):
        raise ValueError("pakistan_operation_not_supported") from None
