"""Opt-in, bounded overseas request diagnostics; never a protocol decision.

Only fixed labels, numeric status/code metadata and JSON *types* are logged.
The original response is neither changed nor accepted here. Authentication
payloads are outside this scope.
"""

from __future__ import annotations

import json
import logging
import math
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._protocol import _TransportRequest, _TransportResponse
from .errors import GwmClientError, _safe_api_code, _safe_operation

_LOGGER = logging.getLogger(__name__)
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 64
_OPERATIONS = frozenset({
    "get_vehicle_basics", "get_last_status", "get_charging_plan",
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


def _context(request: _TransportRequest) -> tuple[str, str] | None:
    if not _LOGGER.isEnabledFor(logging.DEBUG) or request.operation not in _OPERATIONS:
        return None
    path = urlsplit(request.url).path
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


def log_response(request: _TransportRequest, response: _TransportResponse) -> None:
    """Summarize a bounded response without accepting it or exposing its data."""
    with suppress(Exception):
        context = _context(request)
        if context is None:
            return
        shape = _envelope_shape(response.body)
        _LOGGER.debug(
            "GWM response diagnostic: operation=%s stage=%s http_status=%s "
            "body_bytes=%s root_type=%s api_code=%s api_code_type=%s "
            "data_present=%s data_type=%s envelope_reason=%s",
            *context, response.status, len(response.body), shape.root_type,
            shape.api_code, shape.api_code_type, shape.data_present,
            shape.data_type, shape.reason,
        )


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
