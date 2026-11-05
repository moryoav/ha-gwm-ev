"""Offline mainland-China auth behavior and protocol contracts."""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any

import pytest
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    CLOCK,
    CODE,
    FIXTURE,
    PHONE,
    SENSITIVE,
    VIN,
    _assert_request,
    _client,
    _complete_state,
    _credentials,
    _empty_state,
    _FakeTransport,
    _partial_state,
    _response,
    _success_plans,
    _Wait,
)

from custom_components.gwm_ora.gwm_client._protocol import _Deadline
from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaClient,
    ChinaClientConfig,
    ChinaInitializationRequired,
    ChinaRiskControlRequired,
    ChinaVerificationRequired,
)
from custom_components.gwm_ora.gwm_client.china_transport import (
    _ChinaTransportRequest,
    _ChinaTransportResponse,
)
from custom_components.gwm_ora.gwm_client.config import RequestTimeouts
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmSchemaError,
    GwmTlsError,
)
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier


def test_credentials_state_and_result_models_are_bound_immutable_and_repr_safe() -> None:
    credentials = _credentials(device_id="01234567-89ab-cdef")
    assert credentials.device_id == "0123456789abcdef0000000000000000"
    assert len(credentials.account_binding) == 64
    assert PHONE not in repr(credentials)
    state = _partial_state(credentials)
    assert state.matches(credentials)
    assert state.has_g_app
    assert not state.complete
    assert FIXTURE["g_app_state"]["g_token"] not in repr(state)
    result = ChinaInitializationRequired(state=state, failures=("auto_ai:network_error",))
    assert FIXTURE["g_app_state"]["g_token"] not in repr(result)

    with pytest.raises((AttributeError, TypeError)):
        state.g_token = SENSITIVE  # type: ignore[misc]
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        ChinaAuthState(
            account_binding=credentials.account_binding,
            device_id=credentials.device_id,
            bean_tech_access_token="SYNTHETIC-ORPHAN",
        )
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        _partial_state(credentials, auto_ai_token_id="SYNTHETIC-ONLY-TOKEN")
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        _partial_state(credentials, bean_tech_access_token="SYNTHETIC-ONLY-BEAN")
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        _partial_state(
            credentials,
            auto_ai_token_id="SYNTHETIC-AUTO-TOKEN",
            auto_ai_user_id="SYNTHETIC-AUTO-USER",
        )


@pytest.mark.parametrize(
    "phone",
    ["", "contains space", "contains\N{NO-BREAK SPACE}space", "bad\nphone", "X" * 65],
)
def test_phone_preflight_matches_transport_printable_no_space_boundary(phone: str) -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        _credentials(phone=phone)


def test_phone_preflight_accepts_bounded_printable_utf8() -> None:
    assert _credentials(phone="合成号码").phone == "合成号码"


@pytest.mark.asyncio
async def test_sms_request_is_throttled_and_publishes_no_secret_code() -> None:
    transport = _FakeTransport(request_verification=[{"code": "000000", "data": {}}])
    client = _client(transport)
    first = await client.authenticate(_credentials())
    assert isinstance(first, ChinaVerificationRequired)
    assert first.code_requested
    assert first.state.verification_requested_at == CLOCK
    assert CODE not in repr(first)

    second = await client.authenticate(_credentials(), state=first.state)
    assert isinstance(second, ChinaVerificationRequired)
    assert not second.code_requested
    assert [request.operation for request in transport.calls] == ["request_verification"]
    _assert_request(transport.calls[0], "request_verification")


@pytest.mark.asyncio
async def test_sms_login_initializes_both_services_then_forces_discovery_before_install() -> None:
    transport = _FakeTransport(**_success_plans())
    client = _client(transport)
    result = await client.authenticate(_credentials(), verification_code=CODE)
    assert isinstance(result, ChinaAuthenticated)
    assert result.state.complete
    assert result.state.bean_tech_access_token == "SYNTHETIC-BEAN-ACCESS"
    assert result.state.auto_ai_token_id == "SYNTHETIC-AUTO-TOKEN"
    assert client.authenticated
    operations = [request.operation for request in transport.calls]
    assert operations[0] == "login"
    assert set(operations[1:3]) == {"initialize_bean_tech", "initialize_auto_ai"}
    assert operations[-1] == "acquire_vehicles"
    assert result.state.verification_requested_at is None
    for request in transport.calls:
        _assert_request(request, request.operation)


@pytest.mark.asyncio
async def test_partial_state_retries_initialization_directly_without_refresh_or_sms() -> None:
    transport = _FakeTransport(**_success_plans(login=False))
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaAuthenticated)
    operations = [request.operation for request in transport.calls]
    assert set(operations[:2]) == {"initialize_bean_tech", "initialize_auto_ai"}
    assert operations[-1] == "acquire_vehicles"
    assert "refresh_token" not in operations
    assert "request_verification" not in operations
    assert "login" not in operations


@pytest.mark.asyncio
async def test_matching_complete_state_is_never_accepted_from_cache() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(result, ChinaAuthenticated)
    assert [request.operation for request in transport.calls] == ["acquire_vehicles"]


@pytest.mark.asyncio
@pytest.mark.parametrize("rejection", [_response({}, status=401), {"code": "550004"}, {"code": 550004}])
async def test_definitive_complete_session_rejection_refreshes_then_reinitializes(rejection: object) -> None:
    refresh = {
        "code": "000000",
        "data": {
            "token": "SYNTHETIC-G-TOKEN-ROTATED",
            "refreshToken": "SYNTHETIC-G-REFRESH-ROTATED",
            "ssoToken": "SYNTHETIC-SSO-TOKEN-ROTATED",
        },
    }
    plans = _success_plans(login=False)
    plans["acquire_vehicles"] = [
        rejection,
        FIXTURE["responses"]["discovery"],
    ]
    plans["refresh_token"] = [refresh]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(result, ChinaAuthenticated)
    assert result.state.g_token == "SYNTHETIC-G-TOKEN-ROTATED"
    assert result.state.g_refresh_token == "SYNTHETIC-G-REFRESH-ROTATED"
    assert result.state.bean_tech_access_token == "SYNTHETIC-BEAN-ACCESS"
    operations = [request.operation for request in transport.calls]
    assert operations[0:2] == ["acquire_vehicles", "refresh_token"]
    assert operations[-1] == "acquire_vehicles"
    _assert_request(transport.calls[1], "refresh_request")


@pytest.mark.asyncio
async def test_explicit_session_refresh_renews_platforms_without_sms_or_old_discovery() -> None:
    plans = _success_plans(login=False)
    plans["refresh_token"] = [{
        "code": "000000",
        "data": {"token": "ROTATED-G-TOKEN", "refreshToken": "ROTATED-G-REFRESH"},
    }]
    plans["initialize_bean_tech"] = [{
        "code": "000000",
        "data": {**FIXTURE["responses"]["bean_tech"]["data"], "accessToken": "ROTATED-BEAN-TOKEN"},
    }]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    result = await client.refresh_session(_credentials(), _complete_state())

    assert result.state.g_token == "ROTATED-G-TOKEN"
    assert result.state.g_refresh_token == "ROTATED-G-REFRESH"
    assert result.state.bean_tech_access_token == "ROTATED-BEAN-TOKEN"
    assert result.state.auto_ai_token_id == "SYNTHETIC-AUTO-TOKEN"
    assert client.authenticated
    assert [request.operation for request in transport.calls] == [
        "refresh_token", "initialize_bean_tech", "initialize_auto_ai", "acquire_vehicles",
    ]
    _assert_request(transport.calls[0], "refresh_request")
    assert transport.calls[-1].headers["Authorization"] == "ROTATED-BEAN-TOKEN"


@pytest.mark.asyncio
async def test_renewal_platform_logins_start_together_with_one_deadline() -> None:
    bean_started = asyncio.Event()
    auto_started = asyncio.Event()
    deadlines: list[_Deadline] = []

    class Transport(_FakeTransport):
        async def execute(self, request: _ChinaTransportRequest, **kwargs: Any) -> _ChinaTransportResponse:
            if request.operation in {"initialize_bean_tech", "initialize_auto_ai"}:
                deadlines.append(kwargs["deadline"])
                started, other = (bean_started, auto_started) if request.operation == "initialize_bean_tech" else (auto_started, bean_started)
                started.set()
                await other.wait()
            return await super().execute(request, **kwargs)

    plans = _success_plans(login=False)
    plans["refresh_token"] = [FIXTURE["responses"]["login"]]
    client = _client(Transport(**plans))

    result = await asyncio.wait_for(client.refresh_session(_credentials(), _complete_state()), 5)

    assert result.state.complete and client.authenticated
    assert len(deadlines) == 2 and deadlines[0] is deadlines[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("bean_code,auto_code,expected,code", [
    ("7654321", "550004", GwmAuthenticationError, "550004"),
    ("550004", "1013", GwmApiError, "1013"),
])
async def test_concurrent_renewal_preserves_authentication_and_risk_failures(
    bean_code: str, auto_code: str, expected: type[GwmClientError], code: str,
) -> None:
    transport = _FakeTransport(
        refresh_token=[FIXTURE["responses"]["login"]],
        initialize_bean_tech=[{"code": bean_code}],
        initialize_auto_ai=[{"header": {"c": auto_code}}],
    )
    client = _client(transport)
    with pytest.raises(expected) as raised:
        await client.refresh_session(_credentials(), _complete_state())
    assert raised.value.api_code == code
    assert not client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["550004", 550004])
async def test_beantech_status_expiry_revokes_session_without_leaking_response(code: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_last_status=[{"code": code, "message": SENSITIVE}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmAuthenticationError) as raised:
        await client.get_last_status(VehicleIdentifier(BEAN_VIN))

    assert raised.value.api_code == "550004"
    assert raised.value.operation == "get_last_status"
    assert not client.authenticated
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_operation", ["initialize_bean_tech", "initialize_auto_ai", "acquire_vehicles"])
async def test_explicit_refresh_publishes_rotated_partial_before_later_failure(failed_operation: str) -> None:
    plans = {operation: values * 2 for operation, values in _success_plans(login=False).items()}
    plans[failed_operation].insert(0, GwmSchemaError(operation=failed_operation))
    plans["refresh_token"] = [{
        "code": "000000",
        "data": {"token": "ROTATED-G-TOKEN", "refreshToken": "ROTATED-G-REFRESH"},
    }]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    published: list[ChinaAuthState] = []

    async def publish(state: ChinaAuthState) -> None:
        assert not client.authenticated
        published.append(state)

    with pytest.raises(GwmSchemaError):
        await client.refresh_session(_credentials(), _complete_state(), on_state=publish)

    partial = published[-1]
    assert partial.g_token == "ROTATED-G-TOKEN"
    assert partial.g_refresh_token == "ROTATED-G-REFRESH"
    assert partial.has_g_app and not partial.complete
    assert partial.bean_tech_access_token is None
    assert partial.auto_ai_token_id is None
    assert not client.authenticated

    result = await client.refresh_session(_credentials(), partial, on_state=publish)

    assert result.state.g_refresh_token == "ROTATED-G-REFRESH"
    assert result.state.complete
    assert client.authenticated
    assert sum(request.operation == "refresh_token" for request in transport.calls) == 1
    assert not any(request.operation in {"login", "request_verification"} for request in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"code": "550004"}, GwmAuthenticationError),
        ({"code": "7654321"}, GwmApiError),
        (_response({}, status=429), GwmRateLimitError),
        (GwmNetworkError(operation="refresh_token"), GwmNetworkError),
    ],
)
async def test_explicit_session_refresh_failure_does_not_send_sms(
    response: object, expected: type[GwmClientError],
) -> None:
    transport = _FakeTransport(refresh_token=[response])
    client = _client(transport)
    with pytest.raises(expected):
        await client.refresh_session(_credentials(), _complete_state())
    assert [request.operation for request in transport.calls] == ["refresh_token"]
    assert not client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["550004", 550004])
async def test_auto_ai_rejection_during_explicit_refresh_is_authentication_failure(code: object) -> None:
    plans = _success_plans(login=False)
    plans["refresh_token"] = [FIXTURE["responses"]["login"]]
    plans["initialize_auto_ai"] = [{"header": {"c": code, "m": SENSITIVE}}]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    with pytest.raises(GwmAuthenticationError) as raised:
        await client.refresh_session(_credentials(), _complete_state())

    assert raised.value.operation == "initialize_auto_ai"
    assert raised.value.api_code == "550004"
    assert not client.authenticated
    assert [request.operation for request in transport.calls] == [
        "refresh_token", "initialize_bean_tech", "initialize_auto_ai",
    ]
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [[], {"code": "550004"}])
async def test_explicit_refresh_rejects_malformed_auto_ai_error_code(code: object) -> None:
    plans = _success_plans(login=False)
    plans["refresh_token"] = [FIXTURE["responses"]["login"]]
    plans["initialize_auto_ai"] = [{"header": {"c": code}}]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    with pytest.raises(GwmSchemaError) as raised:
        await client.refresh_session(_credentials(), _complete_state())

    assert raised.value.operation == "initialize_auto_ai"
    assert not client.authenticated
    assert not any(request.operation in {"login", "request_verification"} for request in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["1013", 1013])
@pytest.mark.parametrize("operation", [
    "refresh_token", "initialize_bean_tech", "initialize_auto_ai", "acquire_vehicles",
])
async def test_explicit_refresh_risk_control_stops_without_sms(operation: str, code: object) -> None:
    plans = _success_plans(login=False)
    plans["refresh_token"] = [FIXTURE["responses"]["login"]]
    plans[operation] = [{"header": {"c": code}} if operation == "initialize_auto_ai" else {"code": code}]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    with pytest.raises(GwmApiError) as raised:
        await client.refresh_session(_credentials(), _complete_state())

    assert raised.value.api_code == "1013"
    assert raised.value.operation == operation
    assert not client.authenticated
    assert Counter(request.operation for request in transport.calls)[operation] == 1
    assert Counter(request.operation for request in transport.calls)["refresh_token"] == 1
    assert not any(request.operation in {"login", "request_verification"} for request in transport.calls)


@pytest.mark.asyncio
async def test_restart_policy_refreshes_complete_state_without_sms_fallback() -> None:
    refresh = {
        "code": "000000",
        "data": {
            "token": "SYNTHETIC-G-TOKEN-ROTATED",
            "refreshToken": "SYNTHETIC-G-REFRESH-ROTATED",
            "ssoToken": "SYNTHETIC-SSO-TOKEN-ROTATED",
        },
    }
    plans = _success_plans(login=False)
    plans["acquire_vehicles"] = [
        _response({}, status=401),
        FIXTURE["responses"]["discovery"],
    ]
    plans["refresh_token"] = [refresh]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    result = await client.authenticate(
        _credentials(),
        state=_complete_state(),
        allow_sms_login=False,
    )

    assert isinstance(result, ChinaAuthenticated)
    assert result.state.g_token == "SYNTHETIC-G-TOKEN-ROTATED"
    operations = [request.operation for request in transport.calls]
    assert operations[0:2] == ["acquire_vehicles", "refresh_token"]
    assert operations[-1] == "acquire_vehicles"
    assert "request_verification" not in operations
    assert "login" not in operations


@pytest.mark.asyncio
async def test_restart_policy_never_requests_sms_when_refresh_is_rejected() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[_response({}, status=401)],
        refresh_token=[_response({}, status=401)],
    )
    client = _client(transport)

    with pytest.raises(GwmAuthenticationError):
        await client.authenticate(
            _credentials(),
            state=_complete_state(),
            allow_sms_login=False,
        )

    assert [request.operation for request in transport.calls] == [
        "acquire_vehicles",
        "refresh_token",
    ]


@pytest.mark.asyncio
async def test_restart_policy_rejects_empty_state_without_http() -> None:
    transport = _FakeTransport()
    client = _client(transport)

    with pytest.raises(GwmAuthenticationError):
        await client.authenticate(
            _credentials(),
            state=_empty_state(),
            allow_sms_login=False,
        )

    assert transport.calls == []


@pytest.mark.asyncio
async def test_refresh_rotation_failure_publishes_only_new_g_app_state() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[_response({}, status=401)],
        refresh_token=[
            {
                "code": "000000",
                "data": {
                    "token": "SYNTHETIC-G-TOKEN-ROTATED",
                    "refreshToken": "SYNTHETIC-G-REFRESH-ROTATED",
                    "ssoToken": "SYNTHETIC-SSO-TOKEN-ROTATED",
                },
            }
        ],
        initialize_bean_tech=[GwmSchemaError(operation="initialize_bean_tech")],
        initialize_auto_ai=[FIXTURE["responses"]["auto_ai"]],
    )
    client = _client(transport)

    result = await client.authenticate(_credentials(), state=_complete_state())

    assert isinstance(result, ChinaInitializationRequired)
    assert result.state.g_token == "SYNTHETIC-G-TOKEN-ROTATED"
    assert result.state.g_refresh_token == "SYNTHETIC-G-REFRESH-ROTATED"
    assert result.state.bean_tech_access_token is None
    assert result.state.auto_ai_token_id is None
    _assert_request(transport.calls[1], "refresh_request")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("refresh_response", "error_type"),
    [
        ({"code": "7654321"}, GwmApiError),
        (_response({}, status=429), GwmRateLimitError),
    ],
)
async def test_refresh_unknown_or_rate_limit_failure_never_cascades(
    refresh_response: object,
    error_type: type[GwmClientError],
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[_response({}, status=401)],
        refresh_token=[refresh_response],
    )
    client = _client(transport)

    with pytest.raises(error_type):
        await client.authenticate(_credentials(), state=_complete_state())

    assert [request.operation for request in transport.calls] == [
        "acquire_vehicles",
        "refresh_token",
    ]
    _assert_request(transport.calls[1], "refresh_request")


@pytest.mark.asyncio
async def test_unknown_complete_session_api_error_does_not_refresh_or_discard_installed_state() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[
            FIXTURE["responses"]["discovery"],
            {"code": "7654321", "description": SENSITIVE},
        ]
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    with pytest.raises(GwmApiError) as raised:
        await client.authenticate(_credentials(), state=authenticated.state)
    assert raised.value.api_code == "7654321"
    assert client.authenticated
    assert [request.operation for request in transport.calls] == [
        "acquire_vehicles",
        "acquire_vehicles",
    ]
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_unknown_sms_login_error_propagates_and_code_is_one_shot_per_account() -> None:
    transport = _FakeTransport(login=[{"code": "7000000", "description": SENSITIVE}])
    client = _client(transport)
    with pytest.raises(GwmApiError) as raised:
        await client.authenticate(_credentials(), verification_code=CODE)
    assert raised.value.api_code == "7000000"

    repeated = await client.authenticate(_credentials(), verification_code=CODE)
    assert isinstance(repeated, ChinaVerificationRequired)
    assert not repeated.code_requested
    assert not repeated.code_rejected
    assert Counter(request.operation for request in transport.calls) == Counter({"login": 1})


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_sms_login_auth_rejection_is_an_explicit_finite_continuation(status: int) -> None:
    transport = _FakeTransport(
        request_verification=[{"code": "000000", "data": {}}],
        login=[_response({}, status=status)],
    )
    client = _client(transport)
    requested = await client.authenticate(_credentials())
    assert isinstance(requested, ChinaVerificationRequired)

    rejected = await client.authenticate(
        _credentials(),
        state=requested.state,
        verification_code=CODE,
    )

    assert isinstance(rejected, ChinaVerificationRequired)
    assert not rejected.code_requested
    assert rejected.code_rejected
    assert rejected.state.verification_requested_at is None
    assert [request.operation for request in transport.calls] == ["request_verification", "login"]


@pytest.mark.asyncio
async def test_new_sms_delivery_rearms_one_shot_code_submission_without_retaining_code() -> None:
    transport = _FakeTransport(
        login=[{"code": "7000000"}, {"code": "7000001"}],
        request_verification=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    with pytest.raises(GwmApiError):
        await client.authenticate(_credentials(), verification_code=CODE)
    requested = await client.authenticate(_credentials())
    assert isinstance(requested, ChinaVerificationRequired)
    assert requested.code_requested
    with pytest.raises(GwmApiError):
        await client.authenticate(
            _credentials(),
            state=requested.state,
            verification_code=CODE,
        )
    assert Counter(request.operation for request in transport.calls) == Counter(
        {"login": 2, "request_verification": 1}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["request_verification", "login"])
async def test_risk_control_1013_is_a_typed_stop_with_no_cascade(operation: str) -> None:
    transport = _FakeTransport(**{operation: [{"code": "1013", "description": SENSITIVE}]})
    client = _client(transport)
    result = await client.authenticate(
        _credentials(),
        verification_code=CODE if operation == "login" else None,
    )
    assert isinstance(result, ChinaRiskControlRequired)
    assert result.api_code == "1013"
    assert [request.operation for request in transport.calls] == [operation]
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_outer_g_app_auto_ai_risk_control_is_not_misclassified_as_schema() -> None:
    transport = _FakeTransport(
        initialize_bean_tech=[FIXTURE["responses"]["bean_tech"]],
        initialize_auto_ai=[{"code": "1013", "description": SENSITIVE}],
    )
    client = _client(transport)

    result = await client.authenticate(_credentials(), state=_partial_state())

    assert isinstance(result, ChinaRiskControlRequired)
    assert result.state == _partial_state()
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("auto_ai_response", "failure"),
    [
        ({"code": "7654321", "description": SENSITIVE}, "auto_ai:api_error:7654321"),
        ({"code": []}, "auto_ai:schema_error"),
    ],
)
async def test_outer_g_app_auto_ai_errors_keep_exact_classification(
    auto_ai_response: object,
    failure: str,
) -> None:
    transport = _FakeTransport(
        initialize_bean_tech=[FIXTURE["responses"]["bean_tech"]],
        initialize_auto_ai=[auto_ai_response],
    )
    client = _client(transport)

    result = await client.authenticate(_credentials(), state=_partial_state())

    assert isinstance(result, ChinaInitializationRequired)
    assert result.failures == (failure,)
    assert result.state == _partial_state()
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [[], {}, True])
async def test_malformed_application_code_is_schema_not_network(code: object) -> None:
    transport = _FakeTransport(request_verification=[{"code": code}])
    client = _client(transport)

    with pytest.raises(GwmSchemaError):
        await client.authenticate(_credentials())


@pytest.mark.asyncio
async def test_malformed_login_token_is_schema_not_network() -> None:
    transport = _FakeTransport(
        login=[
            {
                "code": "000000",
                "data": {
                    "gToken": [],
                    "gRefreshToken": "SYNTHETIC-G-REFRESH",
                    "ssoToken": "SYNTHETIC-SSO-TOKEN",
                    "userId": "SYNTHETIC-USER",
                    "beanId": "SYNTHETIC-BEAN",
                },
            }
        ]
    )
    client = _client(transport)

    with pytest.raises(GwmSchemaError):
        await client.authenticate(_credentials(), verification_code=CODE)


@pytest.mark.asyncio
async def test_initialization_retries_only_network_and_selected_gateway_failures() -> None:
    sleeps: list[float] = []

    async def sleeper(delay: float) -> None:
        sleeps.append(delay)

    transport = _FakeTransport(
        initialize_bean_tech=[
            GwmNetworkError(operation="initialize_bean_tech"),
            GwmHttpError(operation="initialize_bean_tech", status=503),
            FIXTURE["responses"]["bean_tech"],
        ],
        initialize_auto_ai=[FIXTURE["responses"]["auto_ai"]],
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
    )
    client = _client(transport, sleeper=sleeper)
    result = await client.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaAuthenticated)
    assert sleeps == [1.0, 1.0]
    assert Counter(request.operation for request in transport.calls)["initialize_bean_tech"] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "category"),
    [
        (GwmTlsError(operation="initialize_bean_tech"), "tls_error"),
        (GwmRateLimitError(operation="initialize_bean_tech"), "rate_limit_error"),
        (GwmSchemaError(operation="initialize_bean_tech"), "schema_error"),
    ],
)
async def test_terminal_initialization_failures_are_not_retried_or_cascaded(
    failure: GwmClientError,
    category: str,
) -> None:
    transport = _FakeTransport(
        initialize_bean_tech=[failure],
        initialize_auto_ai=[FIXTURE["responses"]["auto_ai"]],
    )
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaInitializationRequired)
    assert not result.state.complete
    assert result.state.bean_tech_access_token is None
    assert result.state.auto_ai_token_id is None
    assert any(category in label for label in result.failures)
    assert Counter(request.operation for request in transport.calls)["initialize_bean_tech"] == 1
    assert all(request.operation not in {"refresh_token", "login", "request_verification"} for request in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["550004", 550004])
@pytest.mark.parametrize("operation", ["initialize_bean_tech", "initialize_auto_ai", "acquire_vehicles"])
async def test_saved_partial_state_rejection_propagates_authentication_failure(operation: str, code: object) -> None:
    plans = _success_plans(login=False)
    plans[operation] = [{"header": {"c": code}} if operation == "initialize_auto_ai" else {"code": code}]
    transport = _FakeTransport(**plans)
    client = _client(transport)

    with pytest.raises(GwmAuthenticationError) as raised:
        await client.authenticate(_credentials(), state=_partial_state(), allow_sms_login=False)

    assert raised.value.api_code == "550004"
    assert raised.value.operation == operation
    assert not client.authenticated
    assert not any(request.operation in {"refresh_token", "login", "request_verification"} for request in transport.calls)


@pytest.mark.asyncio
async def test_unknown_initialization_api_error_publishes_g_app_only_partial_metadata() -> None:
    transport = _FakeTransport(
        initialize_bean_tech=[{"code": "7654321", "description": SENSITIVE}],
        initialize_auto_ai=[FIXTURE["responses"]["auto_ai"]],
    )
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaInitializationRequired)
    assert result.failures == ("bean_tech:api_error:7654321",)
    assert result.state.g_token == "SYNTHETIC-G-TOKEN"
    assert result.state.bean_tech_access_token is None
    assert result.state.auto_ai_token_id is None
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("service", "response", "failure"),
    [
        (
            "initialize_bean_tech",
            {"code": "000000", "data": {"accessToken": []}},
            "bean_tech:schema_error",
        ),
        (
            "initialize_auto_ai",
            {"header": {"c": 0}, "body": {"tokenId": [], "userId": "SYNTHETIC-USER"}},
            "auto_ai:schema_error",
        ),
    ],
)
async def test_malformed_platform_tokens_publish_schema_partial(
    service: str,
    response: object,
    failure: str,
) -> None:
    plans: dict[str, list[object]] = {
        "initialize_bean_tech": [FIXTURE["responses"]["bean_tech"]],
        "initialize_auto_ai": [FIXTURE["responses"]["auto_ai"]],
    }
    plans[service] = [response]
    client = _client(_FakeTransport(**plans))

    result = await client.authenticate(_credentials(), state=_partial_state())

    assert isinstance(result, ChinaInitializationRequired)
    assert result.failures == (failure,)
    assert not result.state.complete
    assert result.state.bean_tech_access_token is None
    assert result.state.auto_ai_token_id is None


@pytest.mark.asyncio
async def test_platform_success_followed_by_discovery_failure_discards_downstream_pair() -> None:
    plans = _success_plans(login=False)
    plans["acquire_vehicles"] = [_response({}, status=502)]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaInitializationRequired)
    assert result.failures == ("discovery:http_error:502",)
    assert not result.state.complete
    assert result.state.bean_tech_access_token is None
    assert result.state.auto_ai_token_id is None
    assert not client.authenticated


@pytest.mark.asyncio
async def test_missing_platform_prerequisite_fails_locally_without_one_sided_initialization() -> None:
    partial = _partial_state(sso_token=None, pt_token=None)
    transport = _FakeTransport()
    client = _client(transport)
    result = await client.authenticate(_credentials(), state=partial)
    assert isinstance(result, ChinaInitializationRequired)
    assert set(result.failures) == {
        "bean_tech:configuration_error",
        "auto_ai:configuration_error",
    }
    assert transport.calls == []


@pytest.mark.asyncio
async def test_cancellation_and_deadline_propagate_without_installing_state() -> None:
    transport = _FakeTransport(request_verification=[_Wait(), _Wait()])
    config = ChinaClientConfig(timeouts=RequestTimeouts(total=0.05, connect=0.05, read=0.05))
    client = _client(transport, config=config)
    with pytest.raises(GwmDeadlineExceededError):
        await client.authenticate(_credentials())
    assert not client.authenticated

    task = asyncio.create_task(client.authenticate(_credentials()))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not client.authenticated


@pytest.mark.asyncio
async def test_cancelled_matching_state_revalidation_preserves_installed_session() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"], _Wait()],
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)

    task = asyncio.create_task(client.authenticate(_credentials(), state=authenticated.state))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert client.authenticated
    assert [request.operation for request in transport.calls] == [
        "acquire_vehicles",
        "acquire_vehicles",
    ]


@pytest.mark.asyncio
async def test_external_transport_lifecycle_and_invalid_injected_entropy_are_fail_closed() -> None:
    external = _FakeTransport()
    client = _client(external)
    await client.aclose()
    await client.aclose()
    assert external.close_calls == 0
    assert client.closed

    bad_salt_transport = _FakeTransport(request_verification=[{"code": "000000"}])
    bad_salt = ChinaClient(
        ChinaClientConfig(),
        transport=bad_salt_transport,
        clock=lambda: CLOCK,
        salt_source=lambda: b"short",
    )
    with pytest.raises(GwmConfigurationError):
        await bad_salt.authenticate(_credentials())
    assert bad_salt_transport.calls == []

    bad_nonce_transport = _FakeTransport()
    bad_nonce = ChinaClient(
        ChinaClientConfig(),
        transport=bad_nonce_transport,
        clock=lambda: CLOCK,
        salt_source=lambda: bytes.fromhex(FIXTURE["salt_hex"]),
        nonce_source=lambda: SENSITIVE,
    )
    result = await bad_nonce.authenticate(_credentials(), state=_partial_state())
    assert isinstance(result, ChinaInitializationRequired)
    assert all(SENSITIVE not in failure for failure in result.failures)


def test_invalid_config_timeout_code_and_state_inputs_fail_before_transport() -> None:
    with pytest.raises(ValueError, match="^response_limit_invalid$"):
        ChinaClientConfig(max_response_bytes=0)
    with pytest.raises(GwmConfigurationError):
        ChinaClient(ChinaClientConfig(), transport=_FakeTransport(), clock=object())  # type: ignore[arg-type]
    with pytest.raises(GwmConfigurationError):
        ChinaClient(
            ChinaClientConfig(),
            authenticated_state=_partial_state(),
            transport=_FakeTransport(),
        )


@pytest.mark.asyncio
async def test_prevalidated_state_handoff_starts_authenticated_without_login() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
    )
    client = ChinaClient(
        ChinaClientConfig(),
        authenticated_state=_complete_state(),
        transport=transport,
        clock=lambda: CLOCK,
        salt_source=lambda: bytes.fromhex(FIXTURE["salt_hex"]),
        nonce_source=lambda: FIXTURE["nonce"],
        sequence_source=lambda: BEAN_COMMAND_ID,
    )

    assert client.authenticated
    vehicles = await client.acquire_vehicles()

    assert [vehicle.identifier.value for vehicle in vehicles][0] == VIN
    assert [request.operation for request in transport.calls] == ["acquire_vehicles"]


@pytest.mark.asyncio
async def test_invalid_auth_timeout_and_code_fail_without_http() -> None:
    transport = _FakeTransport()
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await client.authenticate(_credentials(), timeout=31)
    with pytest.raises(GwmConfigurationError):
        await client.authenticate(_credentials(), verification_code="bad\ncode")
    with pytest.raises(GwmConfigurationError):
        await client.authenticate(_credentials(), verification_code="X" * 65)
    with pytest.raises(GwmConfigurationError):
        await client.authenticate(
            _credentials(),
            verification_code=CODE,
            allow_sms_login=False,
        )
    with pytest.raises(GwmConfigurationError):
        await client.authenticate(
            _credentials(),
            allow_sms_login="yes",  # type: ignore[arg-type]
        )
    assert transport.calls == []
