"""Allowlisted Brazil (BR) hosts, paths and header sets, read-only.

Nothing here can express a command: only the password login, the two vehicle
reads and the token refresh exist. Any other operation fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

BR_AUTH_HOST: Final = "br-front-service.gwmcloud.com"
BR_APP_HOST: Final = "br-app-gateway.gwmcloud.com"
BR_H5_HOST: Final = "br-h5-gateway.gwmcloud.com"
BR_AUTH_BASE_URL: Final = f"https://{BR_AUTH_HOST}/br-official-commerce/br-official-gateway/pc-api/api/v1.0/"
BR_APP_BASE_URL: Final = f"https://{BR_APP_HOST}/app-api/api/v1.0/"
BR_H5_BASE_URL: Final = f"https://{BR_H5_HOST}/app-api/api/v1.0/"
BR_SUCCESS_CODE: Final = "000000"
BR_CREDENTIAL_REJECTED_CODE: Final = "308001"

# Login web-portal headers confirmed against the live backend.
_AUTH_HEADERS: Final = MappingProxyType(
    {
        "appid": "6",
        "brand": "6",
        "brandid": "CCZ001",
        "country": "BR",
        "devicetype": "0",
        "enterpriseid": "CC01",
        "gwid": "",
        "language": "pt_BR",
        "rs": "5",
        "terminal": "GW_PC_GWM",
    }
)
# Vehicle gateway (app) headers confirmed against the live backend.
_APP_HEADERS: Final = MappingProxyType(
    {
        "rs": "2",
        "terminal": "GW_APP_GWM",
        "brand": "6",
        "language": "pt_BR",
        "systemtype": "2",
        "regioncode": "BR",
        "country": "BR",
    }
)


@dataclass(frozen=True, slots=True)
class BrEndpoint:
    """A fixed operation: method, base URL and relative path."""

    method: str
    base_url: str
    path: str
    authenticated: bool


_ENDPOINTS: Final = MappingProxyType(
    {
        "login": BrEndpoint("POST", BR_AUTH_BASE_URL, "userAuth/loginAccount", False),
        "acquire_vehicles": BrEndpoint("GET", BR_APP_BASE_URL, "globalapp/vehicle/acquireVehicles", True),
        "get_last_status": BrEndpoint("GET", BR_APP_BASE_URL, "vehicle/getLastStatus", True),
        "refresh_token": BrEndpoint("POST", BR_H5_BASE_URL, "userAuth/refreshToken", True),
    }
)


def br_endpoint(operation: str) -> BrEndpoint:
    """Return a known read-only contract, or fail closed."""
    try:
        return _ENDPOINTS[operation]
    except (KeyError, TypeError):
        raise ValueError("br_operation_not_supported") from None


def br_auth_headers() -> dict[str, str]:
    """Headers for the login host (no token)."""
    return dict(_AUTH_HEADERS)


def br_app_headers(access_token: str, refresh_token: str) -> dict[str, str]:
    """Headers for the vehicle gateway and the h5 refresh host (both tokens are carried)."""
    return {**_APP_HEADERS, "accessToken": access_token, "refreshToken": refresh_token}
