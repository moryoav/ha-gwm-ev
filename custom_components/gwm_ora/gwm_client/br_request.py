"""Prepare and decode allowlisted BR requests; the transport is injected.

No network traffic happens here. Sending goes through the shared bounded
``AiohttpTransport`` (no redirects, cookies, proxies or retries).
"""

from __future__ import annotations

import json
import re
import ssl
from collections.abc import Mapping
from urllib.parse import quote

from ._protocol import _TransportRequest, _TransportResponse
from .br_endpoints import (
    BR_CREDENTIAL_REJECTED_CODE,
    BR_SUCCESS_CODE,
    br_app_headers,
    br_auth_headers,
    br_endpoint,
)
from .br_identity import BrCredentials
from .client import _reject_json_constant, _unique_object, _validate_json_depth
from .errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmHttpError,
    GwmRateLimitError,
    GwmSchemaError,
    GwmTlsError,
)
from .models import VehicleIdentifier

_TOKEN_CHARS = re.compile(r"[\x21-\x7e]{1,16384}\Z")
# Both fixed phrases come from the vehicle gateway's HTML 400 when mTLS fails.
_TLS_MARKERS = (b"No required SSL certificate", b"The SSL certificate error")
_USER_AGENT = "okhttp/4.9.3"


class GwmBrCredentialError(GwmAuthenticationError):
    """The BR login refused the account or password (code 308001)."""

    _category = "credential_rejected"
    _message = "GWM BR credentials were rejected"


def prepare_br_request(
    *,
    operation: str,
    ssl_context: ssl.SSLContext,
    credentials: BrCredentials | None = None,
    access_token: str | None = None,
    refresh_token: str = "",
    vehicle_id: str | None = None,
) -> _TransportRequest:
    """Build one allowlisted request (login or one of two reads)."""
    try:
        endpoint = br_endpoint(operation)
        if (
            not isinstance(ssl_context, ssl.SSLContext)
            or not ssl_context.check_hostname
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
            or ssl_context.security_level != 0
        ):
            raise ValueError("invalid")
        body: bytes | None = None
        query = ""
        if operation == "login":
            if type(credentials) is not BrCredentials or access_token is not None or vehicle_id is not None:
                raise ValueError("invalid")
            headers = {**br_auth_headers(), "content-type": "application/json", "accept": "application/json"}
            body = json.dumps(credentials.login_body(), separators=(",", ":")).encode("utf-8")
        else:
            if (
                credentials is not None
                or not isinstance(access_token, str)
                or _TOKEN_CHARS.fullmatch(access_token) is None
                or not isinstance(refresh_token, str)
                or (refresh_token and _TOKEN_CHARS.fullmatch(refresh_token) is None)
            ):
                raise ValueError("invalid")
            headers = {**br_app_headers(access_token, refresh_token), "accept": "application/json"}
            if operation == "get_last_status":
                if not isinstance(vehicle_id, str):
                    raise ValueError("invalid")
                VehicleIdentifier(vehicle_id)
                query = "?vin=" + quote(vehicle_id, safe="") + "&flag=true"
            elif vehicle_id is not None:
                raise ValueError("invalid")
        headers["user-agent"] = _USER_AGENT
        return _TransportRequest(
            operation=operation,
            method=endpoint.method,
            url=endpoint.base_url + endpoint.path + query,
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
    if code != BR_SUCCESS_CODE:
        if operation == "login":
            raise GwmAuthenticationError(operation=operation, api_code=code)
        raise GwmApiError(operation=operation, api_code=code)
    return mapping.get("data")
