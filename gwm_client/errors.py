"""Secret-safe exception taxonomy for the standalone GWM client.

The exceptions in this module intentionally accept only narrowly validated
metadata.  Request URLs, headers, bodies, cloud descriptions, response bytes,
and underlying HTTP-library exceptions must be discarded by the layer that
maps them into this hierarchy.
"""

from __future__ import annotations

from typing import Final

_UNKNOWN_OPERATION: Final = "unknown"
_SAFE_OPERATION_ALIASES: Final = frozenset(
    {
        _UNKNOWN_OPERATION,
        "acquire_vehicles",
        "charging_info",
        "check_security_pin",
        "enroll_certificate",
        "get_charging_info",
        "get_command_result",
        "get_last_status",
        "get_user_info",
        "get_vehicle_basics",
        "initialize_auto_ai",
        "initialize_bean_tech",
        "last_status",
        "login",
        "modify_remote_control",
        "refresh_token",
        "request",
        "request_verification",
        "send_command",
        "set_charging_plan",
        "vehicle_basics",
        "verify_code",
    }
)
_MAX_API_CODE_LENGTH: Final = 12
_MAX_RETRY_AFTER_SECONDS: Final = 24 * 60 * 60


def _safe_operation(value: object) -> str:
    return value if isinstance(value, str) and value in _SAFE_OPERATION_ALIASES else _UNKNOWN_OPERATION


def _safe_api_code(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > _MAX_API_CODE_LENGTH or not normalized.isascii():
        return None
    digits = normalized[1:] if normalized.startswith("-") else normalized
    return normalized if digits.isdecimal() and digits else None


def _safe_http_status(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 100 <= value <= 599 else None


def _safe_retry_after(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= _MAX_RETRY_AFTER_SECONDS else None


class GwmClientError(Exception):
    """Base for errors safe to surface in logs and Home Assistant."""

    _category = "client_error"
    _message = "GWM client operation failed"

    __slots__ = ("category", "operation")

    def __init__(self, *, operation: object = _UNKNOWN_OPERATION) -> None:
        self.category = type(self)._category
        self.operation = _safe_operation(operation)
        super().__init__(type(self)._message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(category={self.category!r}, operation={self.operation!r})"


class GwmConfigurationError(GwmClientError):
    """Local client configuration is invalid."""

    _category = "configuration_error"
    _message = "GWM client configuration is invalid"


class GwmRoutePolicyError(GwmClientError):
    """A request was rejected before reaching the HTTP adapter."""

    _category = "route_policy_error"
    _message = "GWM request is not permitted"


class GwmClosedError(GwmClientError):
    """The client or its transport is already closed."""

    _category = "client_closed"
    _message = "GWM client is closed"


class GwmTransportError(GwmClientError):
    """Base for failures while exchanging an allowed request."""

    _category = "transport_error"
    _message = "GWM transport failed"


class GwmNetworkError(GwmTransportError):
    """The remote service could not be reached."""

    _category = "network_error"
    _message = "GWM network request failed"


class GwmTlsError(GwmTransportError):
    """TLS negotiation or certificate validation failed."""

    _category = "tls_error"
    _message = "GWM TLS request failed"


class GwmDeadlineExceededError(GwmTransportError):
    """The operation's single monotonic deadline expired."""

    _category = "deadline_exceeded"
    _message = "GWM request deadline exceeded"


class GwmRedirectError(GwmTransportError):
    """The remote service attempted a disallowed redirect."""

    _category = "redirect_rejected"
    _message = "GWM redirect was rejected"


class GwmResponseTooLargeError(GwmTransportError):
    """The bounded response limit was exceeded."""

    _category = "response_too_large"
    _message = "GWM response exceeded its size limit"


class GwmHttpError(GwmTransportError):
    """The server returned an unsuccessful HTTP status."""

    _category = "http_error"
    _message = "GWM HTTP request failed"

    __slots__ = ("status",)

    def __init__(
        self,
        *,
        operation: object = _UNKNOWN_OPERATION,
        status: object = None,
    ) -> None:
        self.status = _safe_http_status(status)
        super().__init__(operation=operation)


class GwmProtocolError(GwmClientError):
    """The response did not satisfy the GWM protocol contract."""

    _category = "protocol_error"
    _message = "GWM protocol response is invalid"


class GwmSchemaError(GwmProtocolError):
    """A response envelope or typed payload has an invalid shape."""

    _category = "schema_error"
    _message = "GWM response schema is invalid"


class GwmApiError(GwmProtocolError):
    """GWM returned a non-success application code."""

    _category = "api_error"
    _message = "GWM API rejected the operation"

    __slots__ = ("api_code",)

    def __init__(
        self,
        *,
        operation: object = _UNKNOWN_OPERATION,
        api_code: object = None,
    ) -> None:
        self.api_code = _safe_api_code(api_code)
        super().__init__(operation=operation)


class GwmAuthenticationError(GwmApiError):
    """The stored GWM authentication state was rejected."""

    _category = "authentication_error"
    _message = "GWM authentication was rejected"


class GwmSignatureError(GwmApiError):
    """GWM rejected the request signature before processing the operation."""

    _category = "signature_error"
    _message = "GWM request signature was rejected"


class GwmRateLimitError(GwmApiError):
    """GWM throttled the request, with an optional bounded retry delay."""

    _category = "rate_limit_error"
    _message = "GWM request was rate limited"

    __slots__ = ("retry_after_seconds",)

    def __init__(
        self,
        *,
        operation: object = _UNKNOWN_OPERATION,
        api_code: object = None,
        retry_after_seconds: object = None,
    ) -> None:
        self.retry_after_seconds = _safe_retry_after(retry_after_seconds)
        super().__init__(operation=operation, api_code=api_code)


class GwmOptionalEndpointError(GwmApiError):
    """An optional regional endpoint is unavailable or unsupported."""

    _category = "optional_endpoint_unavailable"
    _message = "Optional GWM endpoint is unavailable"


__all__ = [
    "GwmApiError",
    "GwmAuthenticationError",
    "GwmClientError",
    "GwmClosedError",
    "GwmConfigurationError",
    "GwmDeadlineExceededError",
    "GwmHttpError",
    "GwmNetworkError",
    "GwmOptionalEndpointError",
    "GwmProtocolError",
    "GwmRateLimitError",
    "GwmRedirectError",
    "GwmResponseTooLargeError",
    "GwmRoutePolicyError",
    "GwmSchemaError",
    "GwmSignatureError",
    "GwmTlsError",
    "GwmTransportError",
]
