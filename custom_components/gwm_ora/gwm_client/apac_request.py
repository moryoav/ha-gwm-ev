"""Prepare allowlisted APAC requests without sending network traffic."""

from __future__ import annotations

import re
import ssl
from urllib.parse import quote

from ._dotnet_json import encode_dotnet_json
from ._protocol import _TransportRequest
from .apac_climate import validate_climate_payload
from .apac_endpoints import apac_endpoint
from .apac_identity import _is_validated_context
from .apac_material import ApacMaterial
from .apac_policy import apac_gateways, validate_apac_country
from .models import VehicleIdentifier
from .regions import TlsMode
from .signing import sign_request

_HEX_DEVICE = re.compile(r"[0-9A-Fa-f]{32}\Z")
_BASE_HEADERS = {
    "rs": "2",
    "terminal": "GW_APP_Haval",
    "brand": "1",
    "enterpriseId": "CC01",
    "appId": "1",
    "channel": "APP",
    "cVer": "3.0.9",
    "systemType": "1",
    "language": "en",
    "secVersion": "2.0",
}


def prepare_apac_request(
    *,
    operation: str,
    material: ApacMaterial,
    ssl_context: ssl.SSLContext,
    device_id: str,
    country: str,
    access_token: str | None = None,
    body: dict[str, object] | None = None,
    vehicle_id: str | None = None,
    enrollment_device_id: str | None = None,
    command_id: str | None = None,
) -> _TransportRequest:
    """Build a signed request for the allowlisted regional operations.

    Mutual TLS contexts must come from the matching APAC bootstrap or issued
    identity validator. Default contexts use verified standard server TLS.
    The caller owns these contexts and must not mutate them after validation.
    """
    try:
        validate_apac_country(country)
        endpoint = apac_endpoint(operation)
        gateway = apac_gateways(material)[endpoint.gateway]
        if (
            not isinstance(ssl_context, ssl.SSLContext)
            or not ssl_context.check_hostname
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
            or ssl_context.minimum_version < ssl.TLSVersion.TLSv1_2
            or (
                ssl_context.maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
                and ssl_context.maximum_version < ssl_context.minimum_version
            )
        ):
            raise ValueError("invalid")
        if gateway.tls_mode is TlsMode.DEFAULT:
            if ssl_context.security_level <= 0:
                raise ValueError("invalid")
        elif gateway.tls_mode in {TlsMode.APAC_BOOTSTRAP_MTLS, TlsMode.APAC_ISSUED_MTLS}:
            if ssl_context.security_level != 0 or not _is_validated_context(ssl_context, gateway.tls_mode):
                raise ValueError("invalid")
        else:
            raise ValueError("invalid")
        if not isinstance(device_id, str) or _HEX_DEVICE.fullmatch(device_id) is None:
            raise ValueError("invalid")
        if endpoint.authenticated != (access_token is not None):
            raise ValueError("invalid")
        if access_token is not None and (
            not isinstance(access_token, str)
            or not access_token
            or len(access_token) > 16384
            or any(not 0x21 <= ord(c) <= 0x7E for c in access_token)
        ):
            raise ValueError("invalid")
        if (operation == "enroll_certificate") != (enrollment_device_id is not None):
            raise ValueError("invalid")
        header_device = enrollment_device_id or device_id
        if not re.fullmatch(r"[0-9a-fA-F]{32}[0-9]{1,17}|[0-9a-fA-F]{32}", header_device):
            raise ValueError("invalid")
        if endpoint.method == "GET":
            if body is not None:
                raise ValueError("invalid")
            body_text = None
        else:
            if type(body) is not dict:
                raise ValueError("invalid")
            body_text = encode_dotnet_json(body)
        if operation in {"get_last_status", "get_vehicle_basics"}:
            if not isinstance(vehicle_id, str) or not vehicle_id or len(vehicle_id) > 512:
                raise ValueError("invalid")
            query = (
                "?vin=" + quote(vehicle_id, safe="") + ("&seqNo=" if operation == "get_last_status" else "&flag=true")
            )
        elif operation in {"send_climate_command", "get_remote_command_result"}:
            if not isinstance(vehicle_id, str) or not vehicle_id or len(vehicle_id) > 512:
                raise ValueError("invalid")
            VehicleIdentifier(vehicle_id)
            if operation == "get_remote_command_result":
                if not isinstance(command_id, str) or not re.fullmatch(r"[0-9a-f]{32}1234", command_id):
                    raise ValueError("invalid")
                query = "?seqNo=" + command_id
            else:
                if command_id is not None:
                    raise ValueError("invalid")
                validate_climate_payload(body, vehicle_id)
                query = ""
        elif vehicle_id is None and command_id is None:
            query = ""
        else:
            raise ValueError("invalid")
        signed = sign_request(
            gateway.signing_profile, endpoint.method, gateway.base_url + endpoint.path + query, body_text
        )
        headers = {
            **_BASE_HEADERS,
            "country": country,
            "regionCode": country,
            "deviceId": header_device,
            "iccid": header_device,
            "Accept": "application/json",
            **signed.headers,
        }
        if access_token is not None:
            headers["accessToken"] = access_token
        if operation in {"send_climate_command", "get_remote_command_result"}:
            assert vehicle_id is not None
            headers["vin"] = vehicle_id
        if body_text is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        return _TransportRequest(
            operation=operation,
            method=endpoint.method,
            url=signed.url,
            headers=headers,
            ssl_context=ssl_context,
            body=None if body_text is None else body_text.encode("utf-8"),
        )
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("apac_request_invalid") from None
