"""Secret-safety and hierarchy tests for standalone client errors."""

from __future__ import annotations

import inspect
from collections.abc import Callable

import pytest

from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmOptionalEndpointError,
    GwmProtocolError,
    GwmRateLimitError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmSignatureError,
    GwmTlsError,
    GwmTransportError,
)

SECRET = "SENSITIVE-do-not-retain-8e47749f"


def _surface(error: BaseException) -> str:
    public_attributes = {
        name: getattr(error, name)
        for name in ("category", "operation", "status", "api_code", "retry_after_seconds")
        if hasattr(error, name)
    }
    return "\n".join(
        (
            str(error),
            repr(error),
            repr(error.args),
            repr(vars(error)),
            repr(public_attributes),
        )
    )


@pytest.mark.parametrize(
    ("factory", "category"),
    [
        (GwmClientError, "client_error"),
        (GwmConfigurationError, "configuration_error"),
        (GwmRoutePolicyError, "route_policy_error"),
        (GwmClosedError, "client_closed"),
        (GwmTransportError, "transport_error"),
        (GwmNetworkError, "network_error"),
        (GwmTlsError, "tls_error"),
        (GwmDeadlineExceededError, "deadline_exceeded"),
        (GwmRedirectError, "redirect_rejected"),
        (GwmResponseTooLargeError, "response_too_large"),
        (GwmProtocolError, "protocol_error"),
        (GwmSchemaError, "schema_error"),
    ],
)
def test_simple_errors_expose_only_fixed_safe_metadata(
    factory: Callable[..., GwmClientError],
    category: str,
) -> None:
    error = factory(operation="acquire_vehicles")

    assert error.category == category
    assert error.operation == "acquire_vehicles"
    assert error.args == (str(error),)
    assert SECRET not in _surface(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_hierarchy_supports_coarse_grained_error_handling() -> None:
    assert issubclass(GwmNetworkError, GwmTransportError)
    assert issubclass(GwmTlsError, GwmTransportError)
    assert issubclass(GwmDeadlineExceededError, GwmTransportError)
    assert issubclass(GwmRedirectError, GwmTransportError)
    assert issubclass(GwmResponseTooLargeError, GwmTransportError)
    assert issubclass(GwmHttpError, GwmTransportError)
    assert issubclass(GwmSchemaError, GwmProtocolError)
    assert issubclass(GwmApiError, GwmProtocolError)
    assert issubclass(GwmAuthenticationError, GwmApiError)
    assert issubclass(GwmSignatureError, GwmApiError)
    assert issubclass(GwmRateLimitError, GwmApiError)
    assert issubclass(GwmOptionalEndpointError, GwmApiError)


@pytest.mark.parametrize(
    "unsafe_operation",
    [
        SECRET,
        "secret_token_value",
        "https://example.test/vehicle?vin=secret",
        '{"password":"secret"}',
        "last_status\nInjected: value",
        None,
        object(),
    ],
)
def test_unknown_or_unsafe_operation_aliases_are_not_retained(
    unsafe_operation: object,
) -> None:
    error = GwmNetworkError(operation=unsafe_operation)

    assert error.operation == "unknown"
    assert SECRET not in _surface(error)


@pytest.mark.parametrize(
    "api_code",
    ["-101", "000000", "607501", "123456789012"],
)
def test_short_numeric_api_codes_may_be_retained(api_code: str) -> None:
    error = GwmApiError(operation="last_status", api_code=api_code)

    assert error.api_code == api_code
    assert error.operation == "last_status"
    assert api_code not in str(error)
    assert api_code not in repr(error)


@pytest.mark.parametrize(
    "unsafe_code",
    [
        SECRET,
        "607501\n" + SECRET,
        "ABC123",
        "1234567890123",
        "",
        "   ",
        607501,
        True,
        None,
        object(),
    ],
)
def test_unsafe_api_codes_normalize_without_leakage(unsafe_code: object) -> None:
    error = GwmAuthenticationError(
        operation="login",
        api_code=unsafe_code,
    )

    assert error.api_code is None
    assert SECRET not in _surface(error)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (100, 100),
        (401, 401),
        (599, 599),
        (99, None),
        (600, None),
        ("401", None),
        (True, None),
        (None, None),
        (SECRET, None),
    ],
)
def test_http_status_is_bounded_and_safe(status: object, expected: int | None) -> None:
    error = GwmHttpError(operation="request", status=status)

    assert error.status == expected
    assert SECRET not in _surface(error)


@pytest.mark.parametrize(
    ("retry_after_seconds", "expected"),
    [
        (0, 0),
        (60, 60),
        (86_400, 86_400),
        (-1, None),
        (86_401, None),
        (1.5, None),
        ("60", None),
        (True, None),
        (SECRET, None),
    ],
)
def test_rate_limit_retry_delay_is_bounded(
    retry_after_seconds: object,
    expected: int | None,
) -> None:
    error = GwmRateLimitError(
        operation="acquire_vehicles",
        api_code="607099",
        retry_after_seconds=retry_after_seconds,
    )

    assert error.api_code == "607099"
    assert error.retry_after_seconds == expected
    assert SECRET not in _surface(error)


@pytest.mark.parametrize(
    "factory",
    [
        GwmApiError,
        GwmAuthenticationError,
        GwmSignatureError,
        GwmOptionalEndpointError,
        GwmRateLimitError,
    ],
)
def test_api_error_variants_keep_safe_codes_out_of_messages(
    factory: Callable[..., GwmApiError],
) -> None:
    error = factory(operation="vehicle_basics", api_code="607099")

    assert error.api_code == "607099"
    assert "607099" not in str(error)
    assert "607099" not in repr(error)
    assert error.category in _surface(error)


@pytest.mark.parametrize(
    ("factory", "forbidden_parameter"),
    [
        (GwmNetworkError, "url"),
        (GwmNetworkError, "cause"),
        (GwmHttpError, "body"),
        (GwmHttpError, "headers"),
        (GwmApiError, "description"),
        (GwmApiError, "response"),
    ],
)
def test_raw_transport_and_cloud_material_cannot_be_attached(
    factory: Callable[..., GwmClientError],
    forbidden_parameter: str,
) -> None:
    assert forbidden_parameter not in inspect.signature(factory).parameters

    with pytest.raises(TypeError) as raised:
        factory(operation="request", **{forbidden_parameter: SECRET})

    assert SECRET not in str(raised.value)


def test_repr_never_expands_even_safe_optional_metadata() -> None:
    error = GwmRateLimitError(
        operation="get_vehicle_basics",
        api_code="607099",
        retry_after_seconds=60,
    )

    assert repr(error) == ("GwmRateLimitError(category='rate_limit_error', operation='get_vehicle_basics')")
    assert error.args == ("GWM request was rate limited",)
