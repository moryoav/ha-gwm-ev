"""Bounded overseas request diagnostics; never a protocol decision.

Log only fixed labels, flags, numeric metadata and JSON types. Discovery
HTTP failures are visible without debug logging. Authentication uses the
same safe header classifications and a separate body summary. The issue 54
test build also captures the first bounded Russian discovery 400 HTML page.
"""

from __future__ import annotations

import json
import logging
import math
import re
import ssl
import sys
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from ._protocol import _TransportRequest, _TransportResponse
from .errors import GwmClientError, _safe_api_code, _safe_http_status, _safe_operation, _safe_retry_after
from .regions import GatewayRole, Region, get_region_protocol

_LOGGER = logging.getLogger(__name__)
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 64
_MAX_HEADER_CHARS = 4096
_MAX_CLOCK_SKEW_SECONDS = 7 * 24 * 60 * 60
_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
_REQUEST_IDS = frozenset({"x-request-id", "x-trace-id", "x-aliyun-request-id", "x-acs-request-id", "traceid", "request-id"})
_DISCOVERY_GATEWAYS = {
    urlsplit(gateway.base_url).hostname: (region.value, gateway.tls_mode.value)
    for region in Region
    for gateway in (get_region_protocol(region).gateway(GatewayRole.APP_V1),)
}
_RUSSIA_DISCOVERY_HOST = urlsplit(get_region_protocol(Region.RUSSIA).gateway(GatewayRole.APP_V1).base_url).hostname
_RUSSIA_SIGNING_HEADERS = {"gwm-auth-appkey", "gwm-auth-sign", "gwm-auth-timestamp", "gwm-auth-nonce"}
_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
_ISSUE54_HTML_LOGGED = False
_OPERATIONS = frozenset({
    "acquire_vehicles", "get_vehicle_basics", "get_last_status", "get_charging_plan",
    "update_climate_defaults", "send_climate_command", "send_lock_command",
    "send_close_windows_command", "send_front_defroster_command",
    "send_cabin_clean_command", "get_remote_command_result", "set_charging_plan",
})
_STAGES = (
    ("/vehicle/modifyVehicleRemoteCtlInfo", "save_climate_defaults"),
    ("/userAuth/checkSecurityPassword", "security_check"),
    ("/vehicle/T5/sendCmd", "command_send"),
    ("/vehicle/getRemoteCtrlResultT5", "command_result"),
    ("/vehicle/vehicleBasicsInfo", "vehicle_basics"),
    ("/vehicle/getLastStatus", "vehicle_status"),
    ("/vehicleCharge/getChargingInfos", "charging_plan_read"),
    ("/vehicleCharge/setChargingPlan", "charging_plan_write"),
)
_FAILURE_CATEGORIES = frozenset({
    "client_error", "configuration_error", "route_policy_error", "client_closed",
    "transport_error", "network_error", "tls_error", "deadline_exceeded",
    "redirect_rejected", "response_too_large", "http_error", "protocol_error",
    "schema_error", "api_error", "authentication_error", "signature_error",
    "rate_limit_error", "optional_endpoint_unavailable",
})


@dataclass(frozen=True, slots=True)
class _EnvelopeShape:
    reason: str
    root_type: str = "unknown"
    api_code: str | None = None
    api_code_type: str = "unknown"
    data_present: bool | None = None
    data_type: str = "unknown"


class _ShapeError(ValueError):
    """Contains only a fixed diagnostic reason, never source content."""


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    return {
        bool: "boolean", int: "integer", float: "number", str: "string",
        dict: "object", list: "array",
    }.get(type(value), "unknown")


def _numeric_code(value: object) -> str | None:
    # This conversion is diagnostic-only. Do not change GwmApiError.api_code:
    # doing so could change token renewal / retry decisions for numeric codes.
    if type(value) is int and -99_999_999_999 <= value <= 999_999_999_999:
        return _safe_api_code(str(value))
    return _safe_api_code(value) if type(value) is str else None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ShapeError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise _ShapeError("non_finite_number")


def _check_depth(value: object, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise _ShapeError("json_too_deep")
    if isinstance(value, float) and not math.isfinite(value):
        raise _ShapeError("non_finite_number")
    if isinstance(value, dict):
        for child in value.values():
            _check_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_depth(child, depth + 1)


def _envelope_shape(body: bytes) -> _EnvelopeShape:
    if len(body) > _MAX_DIAGNOSTIC_BYTES:
        return _EnvelopeShape("diagnostic_size_limit")
    if not body:
        return _EnvelopeShape("empty_body")
    try:
        envelope = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _check_depth(envelope)
    except UnicodeDecodeError:
        return _EnvelopeShape("invalid_utf8")
    except _ShapeError as error:
        # Only our own fixed reasons can reach this exception class.
        return _EnvelopeShape(str(error))
    except RecursionError:
        return _EnvelopeShape("json_too_deep")
    except ValueError:
        return _EnvelopeShape("invalid_json")
    root_type = _json_type(envelope)
    if not isinstance(envelope, dict):
        return _EnvelopeShape("unexpected_root_type", root_type=root_type)
    code = envelope.get("code")
    if "code" not in envelope:
        reason = "missing_code"
    elif type(code) is not str:
        reason = "unexpected_code_type"
    elif code != "000000":
        reason = "api_code_not_success"
    else:
        reason = "envelope_ok"
    return _EnvelopeShape(
        reason=reason,
        root_type=root_type,
        api_code=_numeric_code(code),
        api_code_type=_json_type(code) if "code" in envelope else "missing",
        data_present="data" in envelope,
        data_type=_json_type(envelope["data"]) if "data" in envelope else "missing",
    )


def _milliseconds(seconds: float) -> int | None:
    """Convert a plausible duration to rounded milliseconds."""
    return round(seconds * 1000) if math.isfinite(seconds) and 0 <= seconds <= 24 * 60 * 60 else None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Find a case-insensitive header within the diagnostic size limit."""
    for key, value in headers.items():
        if key.lower() == name and type(value) is str:
            return value if len(value) <= _MAX_HEADER_CHARS else None
    return None


def _content_type(value: str | None) -> str:
    """Classify a media type without retaining its parameters."""
    if value is None:
        return "missing_or_oversized"
    mime = value.partition(";")[0].strip().lower()
    if mime == "application/json" or mime.endswith("+json"):
        return "json"
    return {"text/html": "html", "text/plain": "text", "application/xml": "xml", "text/xml": "xml",
            "application/octet-stream": "binary", "": "empty"}.get(mime, "other")


def _server_family(value: str | None) -> str:
    """Recognize known server families without logging banner text."""
    if value is None:
        return "missing_or_oversized"
    lower = value.lower()
    for marker, label in (("aliyun", "alibaba"), ("tengine", "tengine"), ("cloudflare", "cloudflare"),
                          ("nginx", "nginx"), ("envoy", "envoy"), ("apache", "apache"), ("microsoft-iis", "iis")):
        if marker in lower:
            return label
    return "other"


def _date_shape(value: str | None) -> tuple[str, int | None]:
    """Classify a server date and estimate clock skew within a bounded window."""
    if value is None:
        return "missing_or_oversized", None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            return "timezone_missing", None
        skew = round((parsed - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return "invalid", None
    return ("valid", skew) if abs(skew) <= _MAX_CLOCK_SKEW_SECONDS else ("outside_clock_window", None)


def _header_shape(headers: Mapping[str, str]) -> dict[str, object]:
    """Summarize response headers as fixed labels, flags, and bounded numbers."""
    names = {name.lower() for name in headers}
    allow = _header(headers, "allow")
    methods = {part.strip().upper() for part in allow.split(",")} if allow is not None else set()
    encoding = _header(headers, "content-encoding")
    normalized_encoding = encoding.strip().lower() if encoding is not None else "missing"
    content_length = _header(headers, "content-length")
    length = int(content_length) if content_length and re.fullmatch(r"[0-9]{1,9}", content_length) else None
    retry_after = _header(headers, "retry-after")
    retry_seconds = int(retry_after) if retry_after and re.fullmatch(r"[0-9]{1,5}", retry_after) else None
    server_date, skew = _date_shape(_header(headers, "date"))
    cookies = [value[:_MAX_HEADER_CHARS].lower() for name, value in headers.items() if name.lower() == "set-cookie" and type(value) is str]
    return {
        "content_type": _content_type(_header(headers, "content-type")),
        "content_encoding": normalized_encoding if normalized_encoding in {"missing", "identity", "gzip", "br", "deflate"} else "other",
        "declared_body_bytes": length, "content_length_present": "content-length" in names,
        "allow_present": "allow" in names, "allow_methods": ",".join(sorted(methods & _METHODS)) or "none",
        "allow_unknown_methods": bool(methods - _METHODS), "server_family": _server_family(_header(headers, "server")),
        "server_date": server_date, "clock_skew_seconds": skew,
        "retry_after_present": "retry-after" in names, "retry_after_seconds": _safe_retry_after(retry_seconds),
        "location_present": "location" in names, "via_present": "via" in names,
        "request_id_present": bool(names & _REQUEST_IDS), "set_cookie_present": "set-cookie" in names,
        "waf_cookie_hint": any(re.search(r"(?:^|[,;]\s*)(?:acw_tc|acw_sc__v[23]|ssxmod_itna[123]?|__cf_bm|cf_clearance)=", value) for value in cookies),
        "waf_header_hint": bool(names & {"cf-ray", "x-sucuri-id", "x-waf-action", "x-aliyun-waf", "x-aliyun-waf-action"}),
    }


def _context(request: _TransportRequest, *, level: int = logging.DEBUG) -> tuple[str, str] | None:
    """Match a logged operation to a known path without retaining the URL."""
    if not _LOGGER.isEnabledFor(level) or request.operation not in _OPERATIONS:
        return None
    path = urlsplit(request.url).path
    if request.operation == "acquire_vehicles":
        return ("acquire_vehicles", "vehicle_discovery") if path.endswith("/globalapp/vehicle/acquireVehicles") else None
    for suffix, stage in _STAGES:
        if path.endswith(suffix):
            return _safe_operation(request.operation), stage
    return None


def log_request(request: _TransportRequest) -> None:
    """Record a fixed stage label; diagnostic failures must never affect IO."""
    with suppress(Exception):
        context = _context(request)
        if context is not None:
            _LOGGER.debug("GWM request diagnostic: operation=%s stage=%s", *context)


def _issue54_html_capture(body: bytes) -> dict[str, str]:
    """Expose one complete bounded page as an escaped byte string on the test branch."""
    global _ISSUE54_HTML_LOGGED
    if len(body) > _MAX_DIAGNOSTIC_BYTES:
        return {"html_capture": "size_limit"}
    if _ISSUE54_HTML_LOGGED:
        return {"html_capture": "already_logged"}
    _ISSUE54_HTML_LOGGED = True
    return {"html_capture": "full", "html_body": repr(body)}


def _russia_request_fields(request: _TransportRequest) -> dict[str, object]:
    """Describe the prepared request without logging its URL or header values."""
    names = {name.lower() for name in request.headers}
    sizes = [len(name) + len(value) + 4 for name, value in request.headers.items()]
    return {
        "diagnostic_profile": "issue54",
        "prepared_header_count": len(sizes),
        "prepared_header_bytes": sum(sizes),
        "largest_prepared_header_bytes": max(sizes, default=0),
        "access_header_present": "accesstoken" in names,
        "device_header_present": "deviceid" in names,
        "country_headers_complete": {"country", "regioncode"}.issubset(names),
        "accept_header_present": "accept" in names,
        "user_agent_present": "user-agent" in names,
        "signing_headers_complete": _RUSSIA_SIGNING_HEADERS.issubset(names),
        "base_headers_complete": {"terminal", "brand", "cver", "appid", "channel"}.issubset(names),
        "query_present": bool(urlsplit(request.url).query),
        "request_body_present": request.body is not None,
        "tls_server_verify_required": request.ssl_context.verify_mode == ssl.CERT_REQUIRED,
        "tls_hostname_check": request.ssl_context.check_hostname is True,
        "tls_config_min": request.ssl_context.minimum_version.name,
        "tls_config_max": request.ssl_context.maximum_version.name,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "openssl": ".".join(str(part) for part in ssl.OPENSSL_VERSION_INFO[:3]),
    }


def discovery_connection_fields(
    request: _TransportRequest, response: object, *, elapsed_seconds: float,
) -> dict[str, object]:
    """Observe public HTTP/TLS metadata while the response connection is available."""
    fields: dict[str, object] = {}
    with suppress(Exception):
        if (
            urlsplit(request.url).hostname != _RUSSIA_DISCOVERY_HOST
            or _context(request, level=logging.WARNING) != ("acquire_vehicles", "vehicle_discovery")
        ):
            return fields
        fields["response_headers_ms"] = _milliseconds(elapsed_seconds)
        version = getattr(response, "version", None)
        major, minor = getattr(version, "major", None), getattr(version, "minor", None)
        fields["http_version"] = f"{major}.{minor}" if type(major) is int and type(minor) is int and 0 <= major <= 3 and 0 <= minor <= 9 else "unknown"
        fields.update(negotiated_tls="unknown", negotiated_alpn="unknown", negotiated_cipher_bits=None)
        transport = getattr(getattr(response, "connection", None), "transport", None)
        if transport is None:
            return fields
        tls = transport.get_extra_info("ssl_object")
        if isinstance(tls, (ssl.SSLObject, ssl.SSLSocket)):
            protocol = tls.version()
            alpn = tls.selected_alpn_protocol()
            cipher = tls.cipher()
            fields["negotiated_tls"] = protocol if protocol in _TLS_VERSIONS else "unknown"
            fields["negotiated_alpn"] = alpn if alpn in {"h2", "http/1.1"} else "none" if alpn is None else "unknown"
            if cipher and type(cipher[2]) is int and 0 < cipher[2] <= 512:
                fields["negotiated_cipher_bits"] = cipher[2]
    return fields


def _discovery_fields(
    request: _TransportRequest,
    headers: Mapping[str, str],
    elapsed_seconds: float | None,
) -> dict[str, object]:
    """Classify the known route and headers without copying their values."""
    region, tls_mode = _DISCOVERY_GATEWAYS.get(urlsplit(request.url).hostname, ("unknown", "unknown"))
    fields = {
        "region": region, "gateway": "app_v1" if region != "unknown" else "unknown",
        "method": request.method, "tls_mode": tls_mode,
        "elapsed_ms": _milliseconds(elapsed_seconds) if elapsed_seconds is not None else None,
        **_header_shape(headers),
    }
    if region == "rus":
        fields.update(_russia_request_fields(request))
    return fields


def log_response(
    request: _TransportRequest,
    response: _TransportResponse,
    *,
    headers: Mapping[str, str] | None = None,
    elapsed_seconds: float | None = None,
    connection_fields: Mapping[str, object] | None = None,
) -> None:
    """Summarize a bounded response without accepting it or exposing its data."""
    with suppress(Exception):
        discovery = request.operation == "acquire_vehicles"
        level = logging.WARNING if discovery and not 200 <= response.status <= 299 else logging.DEBUG
        context = _context(request, level=level)
        if context is None:
            return
        shape = _envelope_shape(response.body)
        message = (
            "GWM response diagnostic: operation=%s stage=%s http_status=%s "
            "body_bytes=%s root_type=%s api_code=%s api_code_type=%s "
            "data_present=%s data_type=%s envelope_reason=%s"
        )
        values: tuple[object, ...] = (
            *context, response.status, len(response.body), shape.root_type,
            shape.api_code, shape.api_code_type, shape.data_present,
            shape.data_type, shape.reason,
        )
        if discovery:
            fields = _discovery_fields(request, response.headers if headers is None else headers, elapsed_seconds)
            fields["html_hint"] = response.body[:256].lstrip().lower().startswith(
                (b"<!doctype html", b"<html", b"<head", b"<body")
            )
            if connection_fields is not None:
                fields.update(connection_fields)
            if fields["region"] == "rus" and response.status == 400 and fields["html_hint"]:
                fields.update(_issue54_html_capture(response.body))
            message += " " + " ".join(f"{name}=%s" for name in fields)
            values += tuple(fields.values())
        _LOGGER.log(level, message, *values)


def log_discovery_rejection(
    request: _TransportRequest,
    error: GwmClientError,
    *,
    status: int,
    headers: Mapping[str, str],
    elapsed_seconds: float,
    connection_fields: Mapping[str, object] | None = None,
) -> None:
    """Report headers already received when transport rejects the response."""
    with suppress(Exception):
        context = _context(request, level=logging.WARNING)
        if context != ("acquire_vehicles", "vehicle_discovery"):
            return
        category = error.category if error.category in _FAILURE_CATEGORIES else "unknown"
        fields = _discovery_fields(request, headers, elapsed_seconds)
        if connection_fields is not None:
            fields.update(connection_fields)
        message = (
            "GWM response diagnostic: operation=%s stage=%s http_status=%s "
            "response_rejected=True category=%s "
        ) + " ".join(f"{name}=%s" for name in fields)
        _LOGGER.warning(message, *context, _safe_http_status(status), category, *fields.values())


def log_failure(request: _TransportRequest, error: GwmClientError) -> None:
    """Record a transport failure with a fixed category, never exception text."""
    with suppress(Exception):
        context = _context(request)
        if context is not None:
            category = error.category if error.category in _FAILURE_CATEGORIES else "unknown"
            _LOGGER.debug(
                "GWM transport diagnostic: operation=%s stage=%s category=%s",
                *context, category,
            )
