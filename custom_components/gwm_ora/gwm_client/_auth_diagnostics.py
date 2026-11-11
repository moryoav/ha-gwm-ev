"""Bounded, value-free authentication diagnostics.

Only fixed labels, booleans, counters, durations, HTTP metadata, numeric API
codes and JSON types leave this module. Never log request/response text, URLs,
header values, unknown JSON keys, identifiers, cookies or exception messages.
Classification is observational and must not affect protocol decisions.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import re
import ssl
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp

from ._diagnostics import (
    _MAX_HEADER_CHARS,
    _check_depth,
    _header_shape,
    _json_type,
    _milliseconds,
    _reject_constant,
    _ShapeError,
    _unique_object,
)
from ._protocol import _TransportRequest
from .errors import GwmClientError, _safe_http_status, _safe_operation, _safe_retry_after

_LOGGER = logging.getLogger(__name__)
_MAX_BODY_BYTES = 256 * 1024
_API_CODE = re.compile(r"-?[0-9]{1,6}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[abrc]+[0-9]+)?\Z")
_OPERATIONS = frozenset({"login", "refresh_token", "request_verification", "verify_code", "get_user_info", "enroll_certificate"})
_PATHS = {
    "userAuth/loginWithPassword": ("login", "password_login", "POST"),
    "userAuth/loginAccount": ("login", "legacy_login", "POST"),
    "userAuth/refreshToken": ("refresh_token", "token_refresh", "POST"),
    "userAuth/getVerifyCode": ("request_verification", "request_verification", "POST"),
    "userAuth/getSMSCode": ("request_verification", "request_sms", "POST"),
    "userAuth/checkVerifyCode": ("verify_code", "verify_code", "POST"),
    "userAuth/checkSMSCode": ("verify_code", "verify_sms", "POST"),
    "userAuth/loginWithSMS": ("verify_code", "sms_login", "POST"),
    "user/getUserBaseInfo": ("get_user_info", "user_profile", "GET"),
    "appAuth/applyCertificate": ("enroll_certificate", "certificate_enrollment", "POST"),
}
_HOSTS = {
    "eu-h5-gateway.gwmcloud.com": "eu",
    "eu-app-gateway-common.gwmcloud.com": "eu",
    "aus-h5-gateway.gwmcloud.com": "aus",
    "rus-h5-gateway.gwmcloud.com": "rus",
    "br-front-service.gwmcloud.com": "br",
}
# The BR password login runs on the web-portal gateway with its own prefix and no request signing.
_BR_LOGIN_PREFIX = "/br-official-commerce/br-official-gateway/pc-api/api/v1.0/"
_CATEGORIES = frozenset({
    "client_error", "configuration_error", "route_policy_error", "client_closed",
    "transport_error", "network_error", "tls_error", "deadline_exceeded",
    "redirect_rejected", "response_too_large", "http_error", "protocol_error",
    "schema_error", "api_error", "authentication_error", "signature_error",
    "rate_limit_error", "optional_endpoint_unavailable",
})
_CAUSE_TYPES = frozenset({
    "TimeoutError", "OSError", "ConnectionError", "ConnectionResetError", "BrokenPipeError",
    "SSLError", "SSLCertVerificationError", "ClientConnectorError", "ClientConnectorDNSError",
    "ClientConnectionError", "ClientOSError", "ServerDisconnectedError", "ClientPayloadError",
    "ClientConnectorCertificateError", "ClientConnectorSSLError", "ClientSSLError", "ServerFingerprintMismatch",
})
_AUTH_FIELDS = (
    "accessToken", "refreshToken", "token", "gwId", "beanId", "userId",
    "deviceId", "certificate", "clientCertificate", "cert", "certContent",
    "privateKey", "clientKey", "key", "ca", "encoded", "expiresIn", "expireTime",
)
_ENVELOPE_FIELDS = ("code", "data", "message", "msg", "description", "desc", "error", "error_description", "success", "status")
_TEXT_FIELDS = ("message", "msg", "description", "desc", "error", "error_description")
_ATTEMPT_IDS = itertools.count(1)
_REQUEST_IDS_LOCAL = itertools.count(1)
_CURRENT_ATTEMPT: ContextVar[AuthAttempt | None] = ContextVar("gwm_auth_diagnostic_attempt", default=None)
_IDENTITY_REASONS = frozenset({
    "bootstrap_certificate_encoding_invalid", "bootstrap_identity_invalid", "bootstrap_private_key_encoding_invalid",
    "ca_bundle_invalid", "ca_intermediate_invalid", "identity_basic_constraints_invalid", "identity_chain_invalid",
    "identity_extended_key_usage_invalid", "identity_expired", "identity_extensions_invalid", "identity_invalid",
    "identity_issuer_invalid", "identity_key_mismatch", "identity_key_usage_invalid", "identity_not_yet_valid",
    "identity_renewal_required", "identity_rsa_contract_invalid", "issued_certificate_encoding_invalid",
    "issued_identity_invalid", "issued_identity_key_invalid", "issued_private_key_encoding_invalid",
})


def _emit(level: int, event: str, fields: Mapping[str, object]) -> None:
    """All callers supply fixed field names and already classified values."""
    with suppress(Exception):
        if _LOGGER.isEnabledFor(level):
            template = "GWM authentication diagnostic: event=%s " + " ".join(f"{key}=%s" for key in fields)
            _LOGGER.log(level, template, event, *fields.values())


def _api_code(value: object) -> str | None:
    if type(value) is int and -99_999 <= value <= 999_999:
        return str(value)
    return value if type(value) is str and len(value) <= 7 and _API_CODE.fullmatch(value) else None


def _failure_fields(error: BaseException) -> dict[str, object]:
    if isinstance(error, asyncio.CancelledError):
        return {"category": "cancelled", "operation": "unknown", "http_status": None, "api_code": None}
    if isinstance(error, GwmClientError):
        return {
            "category": error.category if type(error.category) is str and error.category in _CATEGORIES else "unknown",
            "operation": _safe_operation(error.operation),
            "http_status": _safe_http_status(getattr(error, "status", None)),
            "api_code": _api_code(getattr(error, "api_code", None)),
            "retry_after_seconds": _safe_retry_after(getattr(error, "retry_after_seconds", None)),
        }
    return {"category": "unexpected_error", "operation": "unknown", "http_status": None, "api_code": None}


@dataclass(slots=True)
class AuthAttempt:
    """Process-local correlation; never derived from an account or a token."""

    identifier: int
    started: float
    fields: dict[str, object]
    outcome: str = "returned"
    last_response: dict[str, object] = field(default_factory=dict)

    def complete(self, outcome: str, *, access_rejected: bool = False, identity_rejected: bool = False) -> None:
        self.outcome = outcome if outcome in {"authenticated", "verification_required"} else "returned"
        self.fields.update(access_rejected=access_rejected is True, identity_rejected=identity_rejected is True)


@contextmanager
def authentication_scope(
    *, flow: str, saved_state: bool, access_present: bool, refresh_present: bool,
    identity_present: bool, password_login_allowed: bool, verification_supplied: bool,
) -> Iterator[AuthAttempt]:
    """Trace one EU authentication/renewal without retaining private state."""
    attempt = AuthAttempt(next(_ATTEMPT_IDS), time.monotonic(), {
        "region": "eu", "flow": flow if flow in {"interactive", "startup_resume", "session_renewal"} else "unknown",
        "saved_state": saved_state is True, "access_present": access_present is True,
        "refresh_present": refresh_present is True, "identity_present": identity_present is True,
        "password_login_allowed": password_login_allowed is True, "verification_supplied": verification_supplied is True,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "aiohttp": aiohttp.__version__ if _VERSION.fullmatch(aiohttp.__version__) else "unknown",
        "openssl": ".".join(str(part) for part in ssl.OPENSSL_VERSION_INFO[:3]),
    })
    token = _CURRENT_ATTEMPT.set(attempt)
    _emit(logging.DEBUG, "attempt_start", {"attempt": attempt.identifier, **attempt.fields})
    try:
        yield attempt
    except BaseException as error:
        level = logging.DEBUG if isinstance(error, asyncio.CancelledError) else logging.WARNING
        if attempt.last_response:
            _emit(level, "attempt_last_response", attempt.last_response)
        _emit(level, "attempt_failure", {
            "attempt": attempt.identifier, **attempt.fields,
            "elapsed_ms": _milliseconds(time.monotonic() - attempt.started), **_failure_fields(error),
        })
        raise
    else:
        _emit(logging.DEBUG, "attempt_complete", {
            "attempt": attempt.identifier, **attempt.fields, "outcome": attempt.outcome,
            "elapsed_ms": _milliseconds(time.monotonic() - attempt.started),
        })
    finally:
        _CURRENT_ATTEMPT.reset(token)


def identity_check(stage: str, outcome: str, *, reason: object = None) -> None:
    """Report local TLS/identity validation without certificate or error text."""
    with suppress(Exception):
        attempt = _CURRENT_ATTEMPT.get()
        _emit(logging.WARNING if outcome in {"rejected", "renewal_needed"} else logging.DEBUG, "identity_check", {
            "attempt": attempt.identifier if attempt is not None else 0,
            "region": "eu",
            "stage": stage if stage in {"bootstrap_context", "server_context", "issued_context", "certificate_request", "enrolled_identity"} else "unknown",
            "outcome": outcome if outcome in {"started", "completed", "rejected", "renewal_needed"} else "unknown",
            "reason": reason if type(reason) is str and reason in _IDENTITY_REASONS else "unspecified",
        })


@dataclass(slots=True)
class AuthExchange:
    """Contains only safe metadata; no request or response object is retained."""

    fields: dict[str, object]
    started: float
    phase: str = "connect"
    status: int | None = None
    headers: dict[str, object] = field(default_factory=dict)


def _remember_response(exchange: AuthExchange, fields: dict[str, object]) -> None:
    attempt = _CURRENT_ATTEMPT.get()
    if attempt is not None and exchange.fields["attempt"] == attempt.identifier:
        attempt.last_response = fields


def begin_request(request: _TransportRequest, *, connect_timeout: float, read_timeout: float, remaining: float) -> AuthExchange | None:
    """Recognize exact public routes without logging a URL or request values."""
    with suppress(Exception):
        if request.operation not in _OPERATIONS:
            return None
        url = urlsplit(request.url)
        region = _HOSTS.get(url.hostname or "")
        if region is None or url.port not in {None, 443}:
            return None
        prefix = (
            _BR_LOGIN_PREFIX
            if region == "br" and url.path.startswith(_BR_LOGIN_PREFIX)
            else next((value for value in ("/app-api/api/v1.0/", "/app-api/api/v2.0/") if url.path.startswith(value)), None)
            if region != "br"
            else None
        )
        if prefix is None:
            return None
        route = _PATHS.get(url.path[len(prefix):])
        if route is None or request.operation != route[0]:
            return None
        certificate = request.operation == "enroll_certificate"
        if certificate != (url.hostname == "eu-app-gateway-common.gwmcloud.com"):
            return None
        version_two = prefix == "/app-api/api/v2.0/"
        gateway = "br_login" if region == "br" else "certificate_v1" if certificate else "auth_v2" if version_two else "h5_v1"
        signing = (
            "none" if region == "br"
            else "gwm_auth" if region == "rus" or (region == "eu" and version_two) else "bt_auth"
        )
        names = {name.lower() for name in request.headers}
        attempt = _CURRENT_ATTEMPT.get()
        fields: dict[str, object] = {
            "attempt": attempt.identifier if attempt is not None else 0, "request": next(_REQUEST_IDS_LOCAL),
            "region": region, "gateway": gateway, "operation": route[0], "stage": route[1],
            "method": request.method if request.method in {"GET", "POST"} else "unknown",
            "expected_method": route[2], "signing": signing,
            "tls": "bootstrap_mtls" if certificate else "server_tls",
            "tls_verify_required": request.ssl_context.verify_mode == ssl.CERT_REQUIRED,
            "tls_hostname_check": request.ssl_context.check_hostname is True,
            "body_present": request.body is not None, "access_header_present": "accesstoken" in names,
            "device_header_present": "deviceid" in names,
            "base_headers_complete": {"terminal", "brand", "cver", "appid", "channel"}.issubset(names),
            "signature_present": f"{signing.replace('_', '-')}-sign" in names,
            "timestamp_present": f"{signing.replace('_', '-')}-timestamp" in names,
            "nonce_present": f"{signing.replace('_', '-')}-nonce" in names,
            "connect_timeout_ms": _milliseconds(connect_timeout), "read_timeout_ms": _milliseconds(read_timeout),
            "deadline_remaining_ms": _milliseconds(remaining),
        }
        exchange = AuthExchange(fields, time.monotonic())
        _emit(logging.DEBUG, "request_start", fields)
        return exchange
    return None


def response_headers(exchange: AuthExchange | None, *, status: int, headers: Mapping[str, str], version: object = None) -> None:
    """Log before redirect/encoding/size policy can reject the response."""
    if exchange is None:
        return
    with suppress(Exception):
        exchange.status = _safe_http_status(status)
        exchange.phase = "response_read"
        exchange.headers = _header_shape(headers)
        major, minor = getattr(version, "major", None), getattr(version, "minor", None)
        exchange.headers["http_version"] = f"{major}.{minor}" if type(major) is int and type(minor) is int and 0 <= major <= 3 and 0 <= minor <= 9 else "unknown"
        level = logging.DEBUG if exchange.status is not None and 200 <= exchange.status <= 299 else logging.WARNING
        fields = {
            **exchange.fields, "elapsed_ms": _milliseconds(time.monotonic() - exchange.started),
            "http_status": exchange.status, **exchange.headers,
        }
        _remember_response(exchange, fields)
        _emit(level, "response_headers", fields)


def _field_types(value: object, names: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        return "not_object"
    return ",".join(f"{name}:{_json_type(value[name])}" for name in names if name in value) or "none"


def _text_hints(text: str) -> dict[str, object]:
    lower = text.lower()
    return {
        "waf_hint": any(marker in lower for marker in ("web application firewall", "aliyun", "alibaba", "acw_sc__", "waf block", "waf_block")),
        "captcha_hint": any(marker in lower for marker in ("captcha", "cf-chl-", "challenge-platform", "javascript challenge", "slider verification")),
        "denied_hint": any(marker in lower for marker in ("access denied", "forbidden", "request blocked", "request rejected", "请求被拦截", "访问被拒绝")),
        "method_hint": any(marker in lower for marker in ("method not allowed", "request method", "不支持的请求方法")),
        "expired_hint": any(marker in lower for marker in ("expired", "expiration", "token失效", "登录失效", "登录过期")),
        "signature_hint": any(marker in lower for marker in ("signature", "签名")),
        "rate_limit_hint": any(marker in lower for marker in ("too many requests", "rate limit", "请求频繁", "操作频繁")),
        "credential_hint": any(marker in lower for marker in ("password", "credential", "密码")),
        "permission_hint": any(marker in lower for marker in ("permission", "unauthorized", "权限")),
    }


def _body_shape(body: bytes) -> dict[str, object]:
    fields: dict[str, object] = {"body_bytes": len(body), "body_kind": "empty" if not body else "other", "envelope_reason": "empty_body"}
    if not body:
        return fields
    prefix = body[:_MAX_BODY_BYTES]
    text = prefix.decode("utf-8", errors="replace")
    stripped = text.lstrip("\ufeff \t\r\n").lower()
    html = stripped.startswith(("<!doctype html", "<html", "<head", "<body"))
    fields.update(body_kind="html" if html else "other", html_hint=html,
                  javascript_hint="<script" in stripped, diagnostic_truncated=len(body) > _MAX_BODY_BYTES)
    if len(body) > _MAX_BODY_BYTES:
        fields.update(envelope_reason="diagnostic_size_limit", **_text_hints(text))
        return fields
    try:
        value = json.loads(body.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        _check_depth(value)
    except UnicodeDecodeError:
        fields.update(body_kind="binary", envelope_reason="invalid_utf8")
        return fields
    except _ShapeError as error:
        reason = error.args[0] if error.args and type(error.args[0]) is str and error.args[0] in {"duplicate_json_key", "non_finite_number", "json_too_deep"} else "invalid_json"
        fields.update(body_kind="json", envelope_reason=reason)
        return fields
    except RecursionError:
        fields.update(body_kind="json", envelope_reason="json_too_deep")
        return fields
    except ValueError:
        fields.update(envelope_reason="invalid_json", **_text_hints(text))
        return fields
    fields.update(body_kind="json", root_type=_json_type(value))
    if not isinstance(value, dict):
        fields["envelope_reason"] = "unexpected_root_type"
        return fields
    code = value.get("code")
    reason = "missing_code" if "code" not in value else "unexpected_code_type" if type(code) is not str else "envelope_ok" if code == "000000" else "api_code_not_success"
    data = value.get("data")
    # Only known message fields are classified. Values and unknown field names
    # are never copied into a LogRecord, even for a successful token response.
    message_text = " ".join(value[name][:_MAX_HEADER_CHARS] for name in _TEXT_FIELDS if type(value.get(name)) is str)
    fields.update(
        envelope_reason=reason, api_code=_api_code(code), api_code_type=_json_type(code) if "code" in value else "missing",
        data_present="data" in value, data_type=_json_type(data) if "data" in value else "missing",
        envelope_fields=_field_types(value, _ENVELOPE_FIELDS), auth_fields=_field_types(data, _AUTH_FIELDS),
        unknown_envelope_fields=bool(value.keys() - set(_ENVELOPE_FIELDS)),
        unknown_auth_fields=isinstance(data, dict) and bool(data.keys() - set(_AUTH_FIELDS)),
        **_text_hints(message_text),
    )
    return fields


def response_body(exchange: AuthExchange | None, body: bytes) -> None:
    """Report response shape only, with failure summaries visible by default."""
    if exchange is None:
        return
    with suppress(Exception):
        exchange.phase = "response_complete"
        shape = _body_shape(body)
        expected = shape.get("envelope_reason") == "envelope_ok" or shape.get("api_code") in {"308103", "110641"}
        success_status = exchange.status is not None and 200 <= exchange.status <= 299
        fields = {
            **exchange.fields, "elapsed_ms": _milliseconds(time.monotonic() - exchange.started),
            "http_status": exchange.status, **exchange.headers, **shape,
        }
        _remember_response(exchange, fields)
        _emit(logging.DEBUG if expected and success_status else logging.WARNING, "response_body", fields)


def transport_failure(exchange: AuthExchange | None, error: BaseException, *, cause: BaseException | None = None) -> None:
    """No exception text, repr, traceback, request or response is logged."""
    if exchange is None:
        return
    with suppress(Exception):
        _emit(logging.DEBUG if isinstance(error, asyncio.CancelledError) else logging.WARNING, "transport_failure", {
            **exchange.fields, "phase": exchange.phase,
            "elapsed_ms": _milliseconds(time.monotonic() - exchange.started),
            "response_status": exchange.status, **exchange.headers, **_failure_fields(error),
            "cause_type": type(cause).__name__ if type(cause).__name__ in _CAUSE_TYPES else "other" if cause is not None else "none",
        })
