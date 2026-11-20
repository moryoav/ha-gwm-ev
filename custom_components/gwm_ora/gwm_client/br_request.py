"""Prepare and decode allowlisted BR requests; the transport is injected.

No network traffic happens here. Sending goes through the shared bounded
``AiohttpTransport`` (no redirects, cookies, proxies or retries).
"""

from __future__ import annotations

import json
import re
import ssl
import uuid
from collections.abc import Mapping
from urllib.parse import quote

from ._protocol import _TransportRequest, _TransportResponse
from .br_endpoints import (
    BR_BUSY_CODES,
    BR_CREDENTIAL_REJECTED_CODE,
    BR_SUCCESS_CODE,
    br_app_headers,
    br_auth_headers,
    br_endpoint,
)
from .br_identity import BrCredentials
from .charging import ChargingPlanCommand
from .client import _reject_json_constant, _unique_object, _validate_json_depth
from .errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmHttpError,
    GwmRateLimitError,
    GwmSchemaError,
    GwmTlsError,
    is_overseas_session_expired,
)
from .models import VehicleIdentifier
from .signing import BRAZIL_GWM_AUTH, sign_request

_TOKEN_CHARS = re.compile(r"[\x21-\x7e]{1,16384}\Z")
# Both fixed phrases come from the vehicle gateway's HTML 400 when mTLS fails.
_TLS_MARKERS = (b"No required SSL certificate", b"The SSL certificate error")
_USER_AGENT = "okhttp/4.9.3"


class GwmBrCredentialError(GwmAuthenticationError):
    """The BR login refused the account or password (code 308001)."""

    _category = "credential_rejected"
    _message = "GWM BR credentials were rejected"


class GwmBrSessionRejectedError(GwmAuthenticationError):
    """The account session was replaced by another app login."""

    _message = "GWM BR session was replaced by another login"


class GwmBrBusyError(GwmApiError):
    """The vehicle or GWM is busy with another remote operation (do not retry in a loop)."""

    _message = "GWM BR vehicle is busy with another operation"


def charging_plan_body(command: ChargingPlanCommand) -> bytes:
    """Wire body of ``setChargingPlan`` from the shared, already validated command.

    Only the BR field names and constants live here; the window rules are those of
    ``ChargingPlanCommand``. There is no PIN. Clearing sends empty strings for both
    times. The sequence number is a hex UUID plus a fixed suffix, as the vendor app does.
    """
    if type(command) is not ChargingPlanCommand:
        raise ValueError("invalid")
    body = {
        "enable": command.enable,
        "startTime": command.start_time_ms if command.enable else "",
        "endTime": command.end_time_ms if command.enable else "",
        "seqNo": uuid.uuid4().hex + "1234",
        "planType": "1",
        "vin": command.identifier.value,
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _refresh_body(access_token: str, refresh_token: str, device_id: str) -> bytes:
    """Keep the full installation identity used by the app's v2 login."""
    return json.dumps(
        {"accessToken": access_token, "refreshToken": refresh_token, "deviceId": device_id},
        separators=(",", ":"),
    ).encode("utf-8")


def prepare_br_request(
    *,
    operation: str,
    ssl_context: ssl.SSLContext,
    credentials: BrCredentials | None = None,
    access_token: str | None = None,
    refresh_token: str = "",
    vehicle_id: str | None = None,
    plan: ChargingPlanCommand | None = None,
    device_id: str | None = None,
    gw_id: str | None = None,
    verification_code: str | None = None,
) -> _TransportRequest:
    """Build one allowlisted request (login, token refresh, two reads, or the opt-in charging write)."""
    try:
        endpoint = br_endpoint(operation)
        auth_operation = operation in {"login", "request_verification", "verify_code"}
        if verification_code is not None and operation not in {"login", "verify_code"}:
            raise ValueError("invalid")
        if (
            not isinstance(ssl_context, ssl.SSLContext)
            or not ssl_context.check_hostname
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
            # Vehicle gateway: mTLS context at SECLEVEL=0. Login host: a standard, non-downgraded one.
            or (ssl_context.security_level != 0) == (not auth_operation)
        ):
            raise ValueError("invalid")
        body: bytes | None = None
        query = ""
        if auth_operation:
            if (
                type(credentials) is not BrCredentials
                or access_token is not None
                or vehicle_id is not None
                or device_id is not None
                or gw_id is not None
            ):
                raise ValueError("invalid")
            headers = {**br_auth_headers(), "content-type": "application/json", "accept": "application/json"}
            headers.update({"deviceId": credentials.device_id, "iccid": credentials.device_id})
            if operation == "verify_code" and verification_code is None:
                raise ValueError("invalid")
            payload = (
                credentials.login_body(verification_code) if operation == "login"
                else credentials.verification_body(verification_code)
            )
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        else:
            if (
                credentials is not None
                or not isinstance(access_token, str)
                or _TOKEN_CHARS.fullmatch(access_token) is None
                or not isinstance(refresh_token, str)
                or (refresh_token and _TOKEN_CHARS.fullmatch(refresh_token) is None)
                or (gw_id is not None and (not isinstance(gw_id, str) or _TOKEN_CHARS.fullmatch(gw_id) is None))
                or (device_id is not None and (not isinstance(device_id, str) or re.fullmatch(r"[0-9a-f]{32}", device_id) is None))
            ):
                raise ValueError("invalid")
            headers = {**br_app_headers(access_token, refresh_token), "accept": "application/json"}
            if gw_id is not None:
                headers["gwId"] = gw_id
            if device_id is not None:
                headers.update({"deviceId": device_id, "iccid": device_id})
            if plan is not None and operation != "set_charging_plan":
                raise ValueError("invalid")
            if operation == "refresh_token":
                if (
                    not refresh_token
                    or vehicle_id is not None
                    or not isinstance(device_id, str)
                    or re.fullmatch(r"[0-9a-f]{32}", device_id) is None
                ):
                    raise ValueError("invalid")
                headers["content-type"] = "application/json"
                body = _refresh_body(access_token, refresh_token, device_id)
            elif operation == "set_charging_plan":
                if vehicle_id is not None or type(plan) is not ChargingPlanCommand:
                    raise ValueError("invalid")
                query = "?vin=" + quote(plan.identifier.value, safe="")
                body = charging_plan_body(plan)
                headers["content-type"] = "application/json"
            elif operation == "get_last_status":
                if not isinstance(vehicle_id, str):
                    raise ValueError("invalid")
                VehicleIdentifier(vehicle_id)
                query = "?vin=" + quote(vehicle_id, safe="") + "&flag=true"
            elif vehicle_id is not None:
                raise ValueError("invalid")
        headers["user-agent"] = _USER_AGENT
        url = endpoint.base_url + endpoint.path + query
        signed = sign_request(
            BRAZIL_GWM_AUTH,
            endpoint.method,
            url,
            body.decode("utf-8") if body is not None else None,
            uri_component_safe="-._~!*'()",
            whitespace_policy="preserve",
        )
        headers.update(signed.headers)
        return _TransportRequest(
            operation=operation,
            method=endpoint.method,
            url=url,
            headers=headers,
            ssl_context=ssl_context,
            body=body,
        )
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("br_request_invalid") from None


def decode_br_envelope(response: _TransportResponse, *, operation: str) -> object:
    """Return ``data`` of a successful envelope, or raise a redacted client error."""
    envelope: object = None
    try:
        envelope = json.loads(
            response.body.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        _validate_json_depth(envelope)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        envelope = None
    mapping = envelope if isinstance(envelope, Mapping) else None
    code = mapping.get("code") if mapping is not None else None

    data = mapping.get("data") if mapping is not None else None
    if code == "607501":
        raise GwmBrSessionRejectedError(operation=operation, api_code=code)
    if operation == "set_charging_plan" and mapping is not None and (
        (isinstance(code, str) and code in BR_BUSY_CODES)
        or mapping.get("running") is True
        or (isinstance(data, Mapping) and data.get("running") is True)
        or (isinstance(mapping.get("description"), str) and "REMOTE250502" in mapping["description"])
    ):
        raise GwmBrBusyError(operation=operation, api_code=code)
    if code == BR_CREDENTIAL_REJECTED_CODE:
        raise GwmBrCredentialError(operation=operation, api_code=code)
    if response.status in {401, 403}:
        raise GwmAuthenticationError(operation=operation, api_code=code)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry = int(retry_after) if retry_after and len(retry_after) <= 10 and retry_after.isdecimal() else None
        raise GwmRateLimitError(operation=operation, api_code=code, retry_after_seconds=retry)
    if not 200 <= response.status <= 299:
        # An HTML 400 from the gateway means the client certificate chain was not accepted.
        if mapping is None and response.status == 400 and any(marker in response.body for marker in _TLS_MARKERS):
            raise GwmTlsError(operation=operation)
        raise GwmHttpError(operation=operation, status=response.status)
    if mapping is None:
        raise GwmSchemaError(operation=operation)
    if operation == "refresh_token" and (not isinstance(code, str) or not code):
        # No code is not a refusal: keep the saved tokens and let the next poll retry.
        raise GwmSchemaError(operation=operation)
    if code != BR_SUCCESS_CODE:
        if (
            operation in {"login", "verify_code"} and code in {"308103", "308011", "308012"}
        ) or (operation == "verify_code" and code == "550002"):
            raise GwmApiError(operation=operation, api_code=code)
        if operation in ("login", "refresh_token"):
            raise GwmAuthenticationError(operation=operation, api_code=code)
        error = GwmApiError(operation=operation, api_code=code)
        # BR 570062 is the vehicle gateway's "refresh token expired" reply.
        if code == "570062" or is_overseas_session_expired(error):
            # Same expired-session codes as the other overseas gateways: renew once and repeat.
            raise GwmAuthenticationError(operation=operation, api_code=code)
        raise error
    return mapping.get("data")
