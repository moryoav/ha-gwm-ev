"""Offline production-contract tests for the isolated mainland-China client."""

from __future__ import annotations

import asyncio
import json
from collections import Counter, deque
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest

from gwm_client._protocol import _Deadline
from gwm_client.charging import ChargingPlanCommand
from gwm_client.china_client import (
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaClient,
    ChinaClientConfig,
    ChinaCredentials,
    ChinaInitializationRequired,
    ChinaRiskControlRequired,
    ChinaVehicle,
    ChinaVehicleStatus,
    ChinaVerificationRequired,
)
from gwm_client.china_crypto import bean_tech_sign
from gwm_client.china_transport import (
    _ChinaTransportRequest,
    _ChinaTransportResponse,
)
from gwm_client.commands import (
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    RemoteCommandResultItem,
    select_remote_command_result,
)
from gwm_client.config import RequestTimeouts
from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from gwm_client.models import CloudVehicle, CloudVehicleStatus, VehicleIdentifier

FIXTURE = json.loads(
    (Path(__file__).with_name("fixtures") / "china_auth_contracts_v1.json").read_text(
        encoding="utf-8"
    )
)
BEAN_FIXTURE = json.loads(
    (Path(__file__).with_name("fixtures") / "china_beantech_status_v1.json").read_text(
        encoding="utf-8"
    )
)
CLOCK = datetime.fromisoformat(FIXTURE["clock"])
DEVICE_ID = FIXTURE["credentials"]["device_id"]
PHONE = FIXTURE["credentials"]["phone"]
CODE = FIXTURE["credentials"]["verification_code"]
VIN = "LGWTEST0000000001"
UNSUPPORTED_VIN = "LGWTEST0000000002"
BEAN_VIN = BEAN_FIXTURE["vin"]
BEAN_COMMAND_ID = "0123456789abcdef0123456789abcdef1234"
SENSITIVE = "SENSITIVE-PRIVATE-VALUE-MUST-NOT-LEAK"


class _Wait:
    pass


class _FakeTransport:
    def __init__(self, **plans: list[object]) -> None:
        self.plans = {operation: deque(items) for operation, items in plans.items()}
        self.calls: list[_ChinaTransportRequest] = []
        self.close_calls = 0

    async def execute(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _ChinaTransportResponse:
        del deadline, connect_timeout, read_timeout
        self.calls.append(request)
        queue = self.plans.get(request.operation)
        if queue is None or not queue:
            raise AssertionError(f"unexpected operation {request.operation}")
        item = queue.popleft()
        if isinstance(item, _Wait):
            await asyncio.Event().wait()
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, _ChinaTransportResponse):
            return item
        return _response(item)

    async def aclose(self) -> None:
        self.close_calls += 1


def _response(value: object, *, status: int = 200, headers: Mapping[str, str] | None = None) -> _ChinaTransportResponse:
    return _ChinaTransportResponse(
        status=status,
        headers={} if headers is None else headers,
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


def _credentials(*, phone: str = PHONE, device_id: str = DEVICE_ID) -> ChinaCredentials:
    return ChinaCredentials(phone=phone, device_id=device_id)


def _empty_state(credentials: ChinaCredentials | None = None) -> ChinaAuthState:
    return ChinaAuthState.for_credentials(credentials or _credentials())


def _partial_state(credentials: ChinaCredentials | None = None, **changes: object) -> ChinaAuthState:
    credentials = credentials or _credentials()
    values: dict[str, object] = {
        "account_binding": credentials.account_binding,
        "device_id": credentials.device_id,
        **FIXTURE["g_app_state"],
    }
    values.update(changes)
    return ChinaAuthState(**values)  # type: ignore[arg-type]


def _complete_state(credentials: ChinaCredentials | None = None, **changes: object) -> ChinaAuthState:
    values: dict[str, object] = {
        **{
            name: getattr(_partial_state(credentials), name)
            for name in ChinaAuthState.__dataclass_fields__
        },
        **FIXTURE["complete_state"],
    }
    values.update(changes)
    return ChinaAuthState(**values)  # type: ignore[arg-type]


def _success_plans(*, login: bool = True) -> dict[str, list[object]]:
    plans: dict[str, list[object]] = {
        "initialize_bean_tech": [FIXTURE["responses"]["bean_tech"]],
        "initialize_auto_ai": [FIXTURE["responses"]["auto_ai"]],
        "acquire_vehicles": [FIXTURE["responses"]["discovery"]],
    }
    if login:
        plans["login"] = [FIXTURE["responses"]["login"]]
    return plans


def _client(
    transport: _FakeTransport,
    *,
    clock: Any = lambda: CLOCK,
    sleeper: Any = None,
    config: ChinaClientConfig | None = None,
) -> ChinaClient:
    return ChinaClient(
        config or ChinaClientConfig(),
        transport=transport,
        clock=clock,
        salt_source=lambda: bytes.fromhex(FIXTURE["salt_hex"]),
        nonce_source=lambda: FIXTURE["nonce"],
        sequence_source=lambda: BEAN_COMMAND_ID,
        sleeper=sleeper,
    )


def _assert_request(request: _ChinaTransportRequest, expected_name: str) -> None:
    expected = FIXTURE["requests"][expected_name]
    assert request.method == expected["method"]
    assert request.service == expected["service"]
    assert request.url == expected["url"]
    assert dict(request.headers) == expected["headers"]
    assert (None if request.body is None else request.body.decode()) == expected["body"]


def test_exact_fixed_contracts_cover_every_task16_route() -> None:
    credentials = _credentials()
    empty = _empty_state(credentials)
    partial = _partial_state(credentials)
    complete = _complete_state(credentials)
    client = _client(_FakeTransport())

    requests = {
        "request_verification": client._build_g_app_request(
            operation="request_verification",
            url=FIXTURE["requests"]["request_verification"]["url"],
            logical_body={"phone": credentials.phone, "flag": "LOGIN"},
            state=empty,
            encrypt_body=True,
        ),
        "login": client._build_g_app_request(
            operation="login",
            url=FIXTURE["requests"]["login"]["url"],
            logical_body={"code": CODE, "phone": credentials.phone, "deviceToken": ""},
            state=empty,
            encrypt_body=True,
        ),
        "refresh_request": client._build_g_app_request(
            operation="refresh_token",
            url=FIXTURE["requests"]["refresh_request"]["url"],
            logical_body={"token": complete.g_token, "refreshToken": complete.g_refresh_token},
            state=complete,
            encrypt_body=True,
        ),
        "initialize_bean_tech": client._build_bean_tech_login_request(credentials, partial),
        "initialize_auto_ai": client._build_auto_ai_login_request(credentials, partial),
        "acquire_vehicles": client._build_g_app_request(
            operation="acquire_vehicles",
            url=FIXTURE["requests"]["acquire_vehicles"]["url"],
            logical_body={"vehicleVersion": 13},
            state=complete,
            encrypt_body=False,
        ),
        "get_last_status": client._build_auto_ai_request(
            operation="get_last_status",
            state=complete,
            function="GW.M.GET_VEHICLE_STATE",
            body={"vin": VIN},
            url="https://ti.gwm.com.cn:8443/tsp/ead",
            include_token=True,
        ),
    }
    for name, request in requests.items():
        _assert_request(request, name)

    bean_request = client._build_bean_tech_status_request(
        complete,
        VehicleIdentifier(BEAN_VIN),
    )
    expected = BEAN_FIXTURE["request"]
    assert bean_request.method == expected["method"]
    assert bean_request.service == expected["service"]
    assert bean_request.url == expected["url"]
    assert dict(bean_request.headers) == expected["headers"]
    assert bean_request.body is expected["body"]


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
async def test_definitive_complete_session_rejection_refreshes_then_reinitializes() -> None:
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
        (GwmAuthenticationError(operation="initialize_bean_tech"), "authentication_error"),
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
async def test_discovery_and_status_return_cloud_compatible_typed_privacy_minimized_models() -> None:
    plans = _success_plans()
    plans["get_last_status"] = [
        FIXTURE["responses"]["status"],
        BEAN_FIXTURE["response"],
    ]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), verification_code=CODE)
    assert isinstance(authenticated, ChinaAuthenticated)

    status = await client.get_last_status(VehicleIdentifier(VIN))
    assert isinstance(status, ChinaVehicleStatus)
    assert isinstance(status, CloudVehicleStatus)
    values = {item.code: item.value for item in status.items}
    assert values["2013021"] == "78"
    assert values["2011501"] == "204"
    assert values["2103010"] == "56040"
    assert values["2208001"] == "0"
    assert status.latitude == 0.0
    assert status.longitude == 0.0
    assert "vehicleSts" not in repr(status)
    assert VIN not in repr(status)
    _assert_request(transport.calls[-1], "get_last_status")

    bean_status = await client.get_last_status(VehicleIdentifier(BEAN_VIN))
    bean_values = {item.code: item.value for item in bean_status.items}
    assert bean_values["2013021"] == "71"
    assert bean_values["2011501"] == "75"
    assert bean_values["2103010"] == "22883"
    assert bean_values["9000011"] == "82.5"
    assert bean_values["9000024"] == "90"
    assert bean_values["9000025"] == "68"
    assert bean_status.latitude == 1.25
    assert bean_status.longitude == -2.5
    assert BEAN_VIN not in repr(bean_status)
    expected = BEAN_FIXTURE["request"]
    request = transport.calls[-1]
    assert request.method == expected["method"]
    assert request.service == expected["service"]
    assert request.url == expected["url"]
    assert dict(request.headers) == expected["headers"]
    assert request.body is None


@pytest.mark.asyncio
async def test_discovery_models_retain_only_safe_mapping_metadata_and_navinfo_is_enforced() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[
            FIXTURE["responses"]["discovery"],
            FIXTURE["responses"]["discovery"],
        ]
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    vehicles = await client.acquire_vehicles()
    assert all(isinstance(vehicle, ChinaVehicle | CloudVehicle) for vehicle in vehicles)
    assert vehicles[0].platform == "navinfo"
    assert vehicles[0].network_type == 2
    assert vehicles[0].tank_capacity == 56.0
    assert vehicles[2].platform == "beantech"
    assert VIN not in repr(vehicles[0])

    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(VehicleIdentifier(UNSUPPORTED_VIN))
    assert len(transport.calls) == before


def _auto_ai_payload(request: _ChinaTransportRequest) -> dict[str, Any]:
    parsed = urlsplit(request.url)
    assert parsed.query.startswith("p=")
    return json.loads(unquote(parsed.query[2:]))


@pytest.mark.asyncio
async def test_navinfo_charging_schedule_read_write_clear_and_china_weekday_contract() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_charging_plan=[
            {
                "header": {"c": "0"},
                "body": {
                    "vehicleSts": {
                        "chargeSettings": {
                            "mode": "0",
                            "phoneStrtHourMin": "23:30",
                            "phoneEndHourMin": "06:15",
                            "sundayUseTime": True,
                            "thurdayUseTime": 1,
                        }
                    }
                },
            }
        ],
        set_charging_plan=[
            {"header": {"c": "0"}, "body": {}},
            {"header": {"c": "0"}, "body": {}},
        ],
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier(VIN)

    current = await client.get_charging_plan(identifier)
    assert current.items[0].start_time_ms == int(
        datetime(2024, 8, 12, 15, 30, tzinfo=UTC).timestamp() * 1000
    )
    assert current.items[0].end_time_ms == int(
        datetime(2024, 8, 12, 22, 15, tzinfo=UTC).timestamp() * 1000
    )
    assert current.items[0].weeks == "1001000"

    start = int(datetime(2024, 8, 17, 18, 0, tzinfo=UTC).timestamp() * 1000)
    end = int(datetime(2024, 8, 17, 19, 0, tzinfo=UTC).timestamp() * 1000)
    await client.set_charging_plan(
        ChargingPlanCommand(identifier, True, start, end)
    )
    written = await client.get_charging_plan(identifier)
    assert written.items[0].start_time_ms == start
    assert written.items[0].end_time_ms == end
    assert written.items[0].weeks == "1000000"
    await client.set_charging_plan(ChargingPlanCommand(identifier, False))

    read_payload = _auto_ai_payload(
        next(call for call in transport.calls if call.operation == "get_charging_plan")
    )
    assert read_payload["header"]["fn"] == "GW.M.GET_VEHICLE_STATE"
    assert read_payload["body"] == {"vin": VIN}
    write_requests = [
        call for call in transport.calls if call.operation == "set_charging_plan"
    ]
    enabled_body = _auto_ai_payload(write_requests[0])["body"]
    assert enabled_body["chargeingMode"] == "0"
    assert enabled_body["chargingStartTime"] == "02:00"
    assert enabled_body["chargingEndTime"] == "03:00"
    assert enabled_body["repeatTimes"] == "1000000"
    clear_body = _auto_ai_payload(write_requests[1])["body"]
    assert clear_body["chargeingMode"] == "1"
    assert clear_body["chargingStartTime"] == "00:00"
    assert clear_body["chargingEndTime"] == "00:00"
    assert clear_body["repeatTimes"] == "0000000"


@pytest.mark.asyncio
async def test_beantech_charging_is_rejected_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier("LGWTEST0000000003")
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.get_charging_plan(identifier)
    with pytest.raises(GwmRoutePolicyError):
        await client.set_charging_plan(ChargingPlanCommand(identifier, False))

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_navinfo_climate_start_update_stop_and_result_contracts() -> None:
    transaction_ids = ("TX-START-1", "TX-UPDATE-2", "TX-STOP-3")
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"header": {"c": "0"}, "body": {"transactionId": value}}
            for value in transaction_ids
        ],
        save_climate_config=[
            {"code": "000000", "data": None},
            {"code": "000000", "data": None},
        ],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": json.dumps(
                                {
                                    "transactionId": transaction_ids[1],
                                    "resultCode": "3",
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier(VIN)

    started = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 21, 10, currently_on=False)
    )
    updated = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 26, 20, currently_on=True)
    )
    stopped = await client.send_climate_command(
        ClimateCommand(identifier, "off", 22, 15, currently_on=True)
    )
    results = await client.get_remote_command_results(identifier, updated.command_id)

    assert (started.command_id, updated.command_id, stopped.command_id) == transaction_ids
    command_requests = [
        request for request in transport.calls if request.operation == "send_climate_command"
    ]
    start_payload, update_payload, stop_payload = map(_auto_ai_payload, command_requests)
    assert start_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert start_payload["body"]["cmdCode"] == 6
    assert start_payload["body"]["airParams"] == {
        "engineControl": 1,
        "runTime": 10,
        "temperature": 21,
    }
    assert update_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert update_payload["body"]["cmdCode"] == 6
    assert update_payload["body"]["airParams"] == {
        "engineControl": 1,
        "runTime": 20,
        "temperature": 26,
    }
    assert stop_payload["header"]["fn"] == "GW.M.SEND_COMMON_COMMAND"
    assert stop_payload["body"]["cmdCode"] == 7
    assert "airParams" not in stop_payload["body"]
    paired_operations = [
        request.operation
        for request in transport.calls
        if request.operation in {"send_climate_command", "save_climate_config"}
    ]
    assert paired_operations == [
        "send_climate_command",
        "save_climate_config",
        "send_climate_command",
        "save_climate_config",
        "send_climate_command",
    ]
    config_requests = [
        request for request in transport.calls if request.operation == "save_climate_config"
    ]
    assert [urlsplit(request.url).path for request in config_requests] == [
        "/app-api/api/v3.0/vehicle/remote-ctrl/config",
        "/app-api/api/v3.0/vehicle/remote-ctrl/config",
    ]
    assert [json.loads(request.body or b"null") for request in config_requests] == [
        {
            "configs": {
                "cmdBody": {
                    "allowStartEng": 1,
                    "operationTime": 600,
                    "temperature": 21,
                },
                "controlType": "AIR_CONDITIONER_START",
            },
            "vin": VIN,
        },
        {
            "configs": {
                "cmdBody": {
                    "allowStartEng": 1,
                    "operationTime": 1200,
                    "temperature": 26,
                },
                "controlType": "AIR_CONDITIONER_START",
            },
            "vin": VIN,
        },
    ]

    result_request = transport.calls[-1]
    assert result_request.service == "bean_tech"
    assert urlsplit(result_request.url).path == "/app-api/api/v3.0/vehicle/remote-ctrl/result"
    assert urlsplit(result_request.url).query == (
        "seqNo=TX-UPDATE-2&vin=" + VIN + "&msgType=remote"
    )
    assert results[0].command_id == transaction_ids[1]
    assert results[0].result_code == "2000"
    assert results[0].result_message == "Command is still running"


@pytest.mark.asyncio
async def test_navinfo_climate_config_failure_preserves_accepted_command(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"header": {"c": "0"}, "body": {"transactionId": "TX-ACCEPTED"}}
        ],
        save_climate_config=[GwmNetworkError(operation="send_climate_command")],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    accepted = await client.send_climate_command(
        ClimateCommand(VehicleIdentifier(VIN), "auto", 22, 10)
    )

    assert accepted.command_id == "TX-ACCEPTED"
    assert "companion configuration request failed" in caplog.text


@pytest.mark.asyncio
async def test_navinfo_climate_rejects_temperatures_outside_captured_range() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)

    for temperature in (16, 32):
        with pytest.raises(GwmConfigurationError):
            await client.send_climate_command(
                ClimateCommand(VehicleIdentifier(VIN), "auto", temperature, 10)
            )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_unknown_platform_climate_is_rejected_before_command_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.send_climate_command(
            ClimateCommand(VehicleIdentifier("LGWTEST0000000002"), "auto", 22, 15)
        )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_navinfo_lock_unlock_close_windows_and_result_need_no_pin() -> None:
    transactions = ("TX-LOCK-1", "TX-UNLOCK-2", "TX-WINDOW-3")
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_lock_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transactions[0]}},
            {"header": {"c": "0"}, "body": {"transactionId": transactions[1]}},
        ],
        send_close_windows_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transactions[2]}}
        ],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": json.dumps(
                                {
                                    "transactionId": transactions[2],
                                    "resultCode": "0",
                                    "resultMessage": "Success",
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(VIN)

    locked = await client.send_lock_command(DoorLockCommand(identifier, True))
    unlocked = await client.send_lock_command(DoorLockCommand(identifier, False))
    closed = await client.send_close_windows_command(CloseWindowsCommand(identifier))
    results = await client.get_remote_command_results(identifier, closed.command_id)

    assert (locked.command_id, unlocked.command_id, closed.command_id) == transactions
    requests = [
        request
        for request in transport.calls
        if request.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    assert [_auto_ai_payload(request)["body"]["cmdCode"] for request in requests] == [2, 1, 3]
    assert all(
        _auto_ai_payload(request)["header"]["fn"] == "GW.M.SEND_COMMON_COMMAND"
        for request in requests
    )
    assert results[0].command_id == transactions[2]
    assert results[0].result_code == "0"


@pytest.mark.asyncio
async def test_beantech_lock_close_windows_and_legacy_result_are_isolated() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_lock_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
        send_close_windows_command=[{"code": "000000", "data": {}}],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": [
                    {
                        "remoteType": "0x08",
                        "resultCode": 6,
                        "resultMsg": "Success",
                    }
                ],
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    locked = await client.send_lock_command(DoorLockCommand(identifier, True))
    unlocked = await client.send_lock_command(DoorLockCommand(identifier, False))
    closed = await client.send_close_windows_command(CloseWindowsCommand(identifier))
    results = await client.get_remote_command_results(identifier, closed.command_id)

    assert locked.command_id == unlocked.command_id == closed.command_id == BEAN_COMMAND_ID
    sends = [
        request
        for request in transport.calls
        if request.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    command_bodies = [json.loads(request.body or b"null") for request in sends]
    assert command_bodies[0]["commands"] == [
        {"controlType": "VEHICLE_LOCK", "cmdBody": None}
    ]
    assert command_bodies[1]["commands"] == [
        {"controlType": "VEHICLE_UNLOCK", "cmdBody": None}
    ]
    assert command_bodies[2]["commands"] == [
        {
            "controlType": "WINDOW_CLOSE",
            "cmdBody": {
                "leftFront": 0,
                "leftBack": 0,
                "rightFront": 0,
                "rightBack": 0,
            },
        }
    ]
    result_request = transport.calls[-1]
    assert urlsplit(result_request.url).path == "/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
    assert urlsplit(result_request.url).query == "seqNo=" + BEAN_COMMAND_ID
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, "0x08", "6", "Success"),)


@pytest.mark.asyncio
async def test_task18_commands_reject_unknown_china_platform_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.send_lock_command(
            DoorLockCommand(VehicleIdentifier(UNSUPPORTED_VIN), True)
        )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_navinfo_extended_vehicle_controls_use_exact_app_command_shapes() -> None:
    actions = (
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "horn_and_lights",
        "tailgate_open",
        "tailgate_close",
        "sunroof_close",
        "sunroof_tilt",
        "sunroof_half",
        "sunroof_full",
        "cabin_purge",
        "force_refresh",
    )
    transaction_ids = tuple(f"TX-CONTROL-{index}" for index in range(len(actions)))
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transaction_id}}
            for transaction_id in transaction_ids
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(VIN)

    acceptances = [
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(
                identifier,
                action,  # type: ignore[arg-type]
                20 if action == "remote_start" else None,
            )
        )
        for action in actions
    ]

    assert tuple(item.command_id for item in acceptances) == transaction_ids
    requests = [
        request
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    payloads = [_auto_ai_payload(request) for request in requests]
    assert [payload["header"]["fn"] for payload in payloads] == [
        "GW.M.SET_AND_OPEN_COMMAND",
        *("GW.M.SEND_COMMON_COMMAND" for _ in range(11)),
        "GW.M.REFRESH_VEHICLE_STATE",
    ]
    assert [payload["body"].get("cmdCode") for payload in payloads] == [
        15,
        16,
        19,
        20,
        5,
        17,
        18,
        28,
        29,
        29,
        29,
        34,
        None,
    ]
    assert payloads[0]["body"]["engineParams"] == {"runTime": 20}
    assert [payloads[index]["body"]["openAngle"] for index in (8, 9, 10)] == [
        11,
        5,
        10,
    ]
    assert payloads[-1]["body"] == {"vin": VIN}


@pytest.mark.asyncio
async def test_beantech_extended_controls_are_exact_and_unsupported_actions_fail_locally() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(5)
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    for action in (
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "sunroof_close",
    ):
        accepted = await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(
                identifier,
                action,  # type: ignore[arg-type]
                10 if action == "remote_start" else None,
            )
        )
        assert accepted.command_id == BEAN_COMMAND_ID

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 600}},
        {"controlType": "ENGINE_STOP", "cmdBody": None},
        {"controlType": "WHISTLE"},
        {"controlType": "FLASH"},
        {"controlType": "SKYLIGNT_CLOSE", "cmdBody": {"skyLight": 0}},
    ]
    requests = [request for request in transport.calls if request.operation == "send_vehicle_control_command"]
    assert [urlsplit(request.url).path for request in requests] == [
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
        "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
    ]
    for index in (0, 1, 4):
        assert list(sends[index]) == ["vin", "seqNo", "sendType", "commands", "isSaveConfig"]
        assert sends[index]["isSaveConfig"] is None

    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(identifier, "tailgate_open")
        )
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("action,control_type", [
    ("horn", "WHISTLE"), ("flash_lights", "FLASH"), ("horn_and_lights", "WHISTLE_FLASH")
])
async def test_beantech_horn_lights_send_exact_pin_exempt_timely_request(
    action: str, control_type: str,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    accepted = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action)  # type: ignore[arg-type]
    )
    request = transport.calls[-1]
    expected_body = (
        '{"vin":"' + BEAN_VIN + '","seqNo":"' + BEAN_COMMAND_ID
        + '","sendType":0,"commands":[{"controlType":"' + control_type + '"}]}'
    )
    assert accepted.command_id == BEAN_COMMAND_ID
    assert request.service == "bean_tech"
    assert request.method == "POST"
    assert request.url == "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/timely"
    assert request.body == expected_body.encode()
    assert request.headers["vin"] == BEAN_VIN
    assert "securityToken" not in request.headers
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        FIXTURE["nonce"], request.headers["bt-auth-timestamp"], "json=" + expected_body,
    )
    assert len(transport.calls) == 2


def _horn_request() -> _ChinaTransportRequest:
    return _client(_FakeTransport())._build_bean_tech_command_request(
        _complete_state(), VehicleIdentifier(BEAN_VIN), sequence_number=BEAN_COMMAND_ID,
        operation="send_vehicle_control_command", control_type="WHISTLE", command_body=None,
    )


@pytest.mark.parametrize("mutation", [
    "service", "method", "host", "path", "operation", "token", "signature", "header",
    "missing_body", "invalid_json", "list_body", "vin", "sequence", "sequence_type",
    "send_type", "boolean_send_type", "float_send_type", "extra_key", "missing_key",
    "command_body", "security_command", "climate_command", "multiple_commands", "format",
    "content_type", "auth_header",
])
def test_beantech_horn_transport_rejects_unapproved_routes_and_payloads(mutation: str) -> None:
    request = _horn_request()
    headers = dict(request.headers)
    body = json.loads(request.body or b"null")
    changes: dict[str, Any] = {}
    if mutation == "service":
        changes["service"] = "auto_ai"
    elif mutation == "method":
        changes["method"] = "GET"
    elif mutation == "host":
        changes["url"] = request.url.replace("gw-app-gateway.gwmapp-h.com", "example.invalid")
    elif mutation == "path":
        changes["url"] = request.url + "/unexpected"
    elif mutation == "operation":
        changes["operation"] = "send_lock_command"
    elif mutation == "token":
        headers["securityToken"] = SENSITIVE
    elif mutation == "signature":
        headers["bt-auth-sign"] = "0" * 32
    elif mutation == "header":
        headers["Unexpected"] = "value"
    elif mutation == "content_type":
        headers["Content-Type"] = "text/plain"
    elif mutation == "auth_header":
        headers["rs"] = "9"
    elif mutation == "missing_body":
        changes["body"] = None
    elif mutation == "invalid_json":
        changes["body"] = b"{"
    elif mutation == "list_body":
        changes["body"] = b"[]"
    elif mutation == "format":
        changes["body"] = json.dumps(body, indent=2).encode()
    else:
        if mutation == "vin":
            body["vin"] = VIN
        elif mutation == "sequence":
            body["seqNo"] = "invalid"
        elif mutation == "sequence_type":
            body["seqNo"] = 123
        elif mutation == "send_type":
            body["sendType"] = 1
        elif mutation == "boolean_send_type":
            body["sendType"] = False
        elif mutation == "float_send_type":
            body["sendType"] = 0.0
        elif mutation == "extra_key":
            body["isSaveConfig"] = None
        elif mutation == "missing_key":
            del body["sendType"]
        elif mutation == "command_body":
            body["commands"][0]["cmdBody"] = None
        elif mutation == "security_command":
            body["commands"] = [{"controlType": "VEHICLE_UNLOCK"}]
        elif mutation == "climate_command":
            body["commands"] = [{"controlType": "AIR_CONDITIONER_START"}]
        elif mutation == "multiple_commands":
            body["commands"].append({"controlType": "FLASH"})
        changes["body"] = json.dumps(body, separators=(",", ":")).encode()
    # Re-sign mutated bodies so schema checks cannot pass merely because the
    # original signature no longer matches.
    if changes.get("body") is not None:
        headers["bt-auth-sign"] = bean_tech_sign(
            "POST", "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
            headers["bt-auth-nonce"], headers["bt-auth-timestamp"],
            "json=" + changes["body"].decode(),
        )
    with pytest.raises(ValueError):
        replace(request, headers=headers, **changes)


@pytest.mark.asyncio
@pytest.mark.parametrize("code,expected", [(2, "pending"), ("2", "pending"), (3.0, "pending"),
    ("3", "pending"), (0, "completed"), ("0", "completed"), (6, "completed"), (7, "failed")])
@pytest.mark.parametrize("shape", ["object", "json", "inline"])
async def test_beantech_horn_results_map_pending_success_and_failure(
    code: object, expected: str, shape: str,
) -> None:
    data = {"resultCode": code, "resultMessage": "Synthetic result", "transactionId": "server-generated-id"}
    message = data if shape == "inline" else {
        "messageType": "remote", "messageData": json.dumps(data) if shape == "json" else data,
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [message]}}],
    )
    # A fresh client has no in-memory knowledge of the original submission.
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(
        VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="horn",
    )
    assert results == (RemoteCommandResultItem(
        BEAN_COMMAND_ID, None if shape == "inline" else "remote",
        "2000" if expected == "pending" else str(code), "Synthetic result",
    ),)
    result = select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None, expected_remote_type="china")
    assert result is not None and result.state == expected
    request = transport.calls[-1]
    assert request.url == (
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/result"
        + "?seqNo=" + BEAN_COMMAND_ID + "&vin=" + BEAN_VIN + "&msgType=remote"
    )
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET", "/app-api/api/v3.0/vehicle/remote-ctrl/result", FIXTURE["nonce"],
        request.headers["bt-auth-timestamp"], "msgtype=remote" + "seqno=" + BEAN_COMMAND_ID + "vin=" + BEAN_VIN,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    {}, {"messageList": None}, {"messageList": []},
    {"messageList": [None, {}, {"messageData": " "}, {"messageData": []}, {"messageData": "null"},
        {"messageData": {"resultCode": ""}}, {"messageData": {"resultCode": None}}]},
], ids=["absent", "null", "empty", "incomplete_messages"])
async def test_beantech_horn_incomplete_results_keep_polling(data: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": data}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_remote_command_results(
        VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="flash_lights",
    ) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    [], "invalid", {"messageList": {}}, {"messageList": "invalid"},
    {"messageList": [{"messageData": "{"}]},
    *({"messageList": [{"messageData": {"resultCode": code}}]} for code in (True, [], {})),
], ids=["list_root", "string_root", "object_messages", "string_messages", "broken_json", "bool_code", "list_code", "object_code"])
async def test_beantech_horn_malformed_results_raise_typed_errors(data: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": data}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_remote_command_results(
            VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="horn_and_lights",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["unknown", "", True, [], 123])
async def test_invalid_result_action_is_rejected_before_transport(action: Any) -> None:
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(transport).get_remote_command_results(
            VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action,
        )
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    {"code": "551210"}, {"code": "607777"}, GwmNetworkError(operation="send_vehicle_control_command"),
], ids=["busy", "rejected", "network"])
async def test_beantech_horn_send_is_not_retried_or_rerouted(error: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_vehicle_control_command=[error],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn"))
    assert len(transport.calls) == 2
    assert transport.calls[-1].url.endswith("/remote-ctrl/timely")


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [{}, {"code": None}, {"code": True}, {"code": []}, {"code": {}}])
async def test_beantech_horn_requires_an_explicit_acceptance_code(response: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_vehicle_control_command=[response],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn"))
    assert len(transport.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("vin", [UNSUPPORTED_VIN, "LGWTEST0000000099"])
@pytest.mark.parametrize("action", ["horn", "flash_lights", "horn_and_lights"])
async def test_horn_lights_reject_unknown_vehicle_or_platform_locally(vin: str, action: Any) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmRoutePolicyError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(vin), action))
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_results(VehicleIdentifier(vin), BEAN_COMMAND_ID, control_action=action)
    assert len(transport.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["horn", "flash_lights", "horn_and_lights"])
async def test_navinfo_horn_result_correlation_is_unchanged(action: Any) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [
            {"messageData": {"transactionId": "other-command", "resultCode": "0"}},
            {"messageData": {"transactionId": "TX-HORN", "resultCode": "2"}},
        ]}}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(VehicleIdentifier(VIN), "TX-HORN", control_action=action)
    assert len(results) == 1
    assert results[0].command_id == "TX-HORN"
    assert results[0].result_code == "2000"


@pytest.mark.asyncio
@pytest.mark.parametrize("tank_capacity", ["not-a-number", -1, True, [], "NaN", 10**400])
async def test_optional_tank_capacity_quirks_do_not_reject_discovery(tank_capacity: object) -> None:
    discovery = {
        "code": "000000",
        "data": {
            "acquireVehiclesList": [
                {
                    "vin": VIN,
                    "vehicleId": "synthetic-vehicle-1",
                    "belongPlatform": "navinfo",
                    "vehicleNetworkType": 2,
                    "tankCapacity": tank_capacity,
                }
            ]
        },
    }
    transport = _FakeTransport(acquire_vehicles=[discovery, discovery])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)

    vehicles = await client.acquire_vehicles()

    assert vehicles[0].tank_capacity is None


@pytest.mark.asyncio
async def test_status_auth_rejection_revokes_read_eligibility_and_session() -> None:
    plans = _success_plans()
    plans["get_last_status"] = [_response({}, status=401)]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    await client.authenticate(_credentials(), verification_code=CODE)
    with pytest.raises(GwmAuthenticationError):
        await client.get_last_status(VehicleIdentifier(VIN))
    assert not client.authenticated
    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()


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


@pytest.mark.asyncio
async def test_beantech_climate_start_and_stop_use_timely_without_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
        set_bean_tech_ac_temperature=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    started = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 22, 15)
    )
    stopped = await client.send_climate_command(
        ClimateCommand(identifier, "off", 22, 15)
    )

    assert started.command_id == stopped.command_id == BEAN_COMMAND_ID
    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_climate_command"
    ]
    assert sends[0]["commands"] == [
        {
            "controlType": "AIR_CONDITIONER_START",
            "cmdBody": {
                "allowStartEng": 1,
                "operationTime": 900,
                "temperature": 22,
            },
        }
    ]
    assert sends[1]["commands"] == [{"controlType": "AIR_CONDITIONER_STOP"}]
    for request in transport.calls:
        if request.operation == "send_climate_command":
            assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in request.headers
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_comfort_off_multicommand_shape() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "comfort_off")
    )

    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert "securityToken" not in sent.headers
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )
    body = json.loads(sent.body or b"null")
    assert body["sendType"] == 1
    assert body["commands"] == [
        {"controlType": "AIR_CONDITIONER_STOP"},
        {
            "controlType": "SEAT_HEATING_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 1, "rightFront": 0},
        },
        {
            "controlType": "SEAT_VENTILATION_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 2, "rightFront": 0},
        },
        {"controlType": "STEERING_WHEEL_HEATLESS"},
    ]


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_request_shape() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    await client.set_bean_tech_cabin_clean_appointment(
        VehicleIdentifier(BEAN_VIN), time_ms=1735689600000
    )

    request = next(
        call
        for call in transport.calls
        if call.operation == "set_bean_tech_cabin_clean_appointment"
    )
    assert json.loads(request.body or b"null") == {
        "commands": [
            {
                "controlType": "CABIN_CLEANING_START",
                "cmdBody": {"operationTime": 60},
            }
        ],
        "subscribeType": 0,
        "time": 1735689600000,
        "vin": BEAN_VIN,
    }


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_read_parses_time() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_cabin_clean_appointment=[
            {
                "code": "000000",
                "data": [
                    {
                        "subscribeType": 0,
                        "controlType": "CABIN_CLEANING_START",
                        "cmd": "CABIN_CLEANING_START",
                        "cmdContent": {"operationTime": 60},
                        "time": 1788375600000,
                        "takeEffect": 2,
                    }
                ],
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    time_ms = await client.get_bean_tech_cabin_clean_appointment(
        VehicleIdentifier(BEAN_VIN)
    )

    assert time_ms == 1788375600000
    request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_cabin_clean_appointment"
    )
    assert request.method == "GET"
    assert request.url.endswith(
        "/app-api/api/v3.0/vehicle/remote-ctrl/subscribe/"
        + BEAN_VIN
        + "?cmds=CABIN_CLEANING_START&type=0"
    )
    assert request.body is None


@pytest.mark.asyncio
async def test_beantech_comfort_modes_reject_non_mapping_entries() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[
            {"code": "000000", "data": ["not-a-mapping"]},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_comfort_modes(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
async def test_beantech_comfort_mode_rejects_missing_mode_id() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[
            {"code": "000000", "data": [{"type": "1"}]},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(
            VehicleIdentifier(BEAN_VIN), mode_type="warm"
        )


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_read_returns_none_when_unset() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": []}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    assert (
        await client.get_bean_tech_cabin_clean_appointment(
            VehicleIdentifier(BEAN_VIN)
        )
        is None
    )


_COMFORT_CONTRACTS = (
    ("seat_heating_start", "SEAT_HEATING_START", {"leftFront": 3, "operationTime": 600}),
    ("seat_heating_stop", "SEAT_HEATING_STOP", {"leftFront": 0, "operationMode": 1}),
    ("seat_heating_start_passenger", "SEAT_HEATING_START", {"rightFront": 3, "operationTime": 600}),
    ("seat_heating_stop_passenger", "SEAT_HEATING_STOP", {"rightFront": 0, "operationMode": 1}),
    ("seat_ventilation_start", "SEAT_VENTILATION_START", {"leftFront": 3, "operationTime": 600}),
    ("seat_ventilation_stop", "SEAT_VENTILATION_STOP", {"leftFront": 0, "operationMode": 2}),
    ("seat_ventilation_start_passenger", "SEAT_VENTILATION_START", {"rightFront": 3, "operationTime": 600}),
    ("seat_ventilation_stop_passenger", "SEAT_VENTILATION_STOP", {"rightFront": 0, "operationMode": 2}),
    ("steering_wheel_heating", "STEERING_WHEEL_HEATING", {"operationTime": 600}),
    ("steering_wheel_heatless", "STEERING_WHEEL_HEATLESS", None),
    ("defrost_front_start", "DEFROST_FRONT_START", {"operationTime": 900}),
    ("defrost_front_stop", "DEFROST_FRONT_STOP", None),
    ("defrost_back_start", "DEFROST_BACK_START", {"operationTime": 900}),
    ("defrost_back_stop", "DEFROST_BACK_STOP", None),
    ("cabin_clean", "CABIN_CLEANING_START", {"operationTime": 60}),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("action,control_type,command_body", _COMFORT_CONTRACTS)
async def test_beantech_comfort_captured_payloads_and_navinfo_isolation(
    action: str, control_type: str, command_body: object,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    acceptance = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action)  # type: ignore[arg-type]
    )
    assert acceptance.command_id == BEAN_COMMAND_ID
    request = transport.calls[-1]
    command = {"controlType": control_type}
    if command_body is not None:
        command["cmdBody"] = command_body
    assert json.loads(request.body) == {
        "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID, "sendType": 0, "commands": [command],
    }
    assert request.url == "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/timely"
    assert "securityToken" not in request.headers
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", urlsplit(request.url).path, FIXTURE["nonce"], request.headers["bt-auth-timestamp"],
        "json=" + request.body.decode(),
    )
    before = len(transport.calls)
    for vin in (VIN, UNSUPPORTED_VIN):
        with pytest.raises(GwmRoutePolicyError):
            await client.send_vehicle_control_command(
                ChinaVehicleControlCommand(VehicleIdentifier(vin), action)  # type: ignore[arg-type]
            )
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("minutes,temperature", [(5, 17), (6, 22), (30, 31)])
async def test_beantech_climate_companion_config_preserves_units(minutes: int, temperature: int) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000"}],
        set_bean_tech_ac_temperature=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    accepted = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", temperature, minutes))
    assert accepted.command_id == BEAN_COMMAND_ID
    control = {"controlType": "AIR_CONDITIONER_START", "cmdBody": {
        "allowStartEng": 1, "operationTime": minutes * 60, "temperature": temperature,
    }}
    send, config = transport.calls[-2:]
    assert json.loads(send.body)["commands"] == [control]
    assert json.loads(config.body) == {"configs": [control], "vin": BEAN_VIN}
    assert config.url.endswith("/remote-ctrl/config")
    assert config.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", urlsplit(config.url).path, FIXTURE["nonce"], config.headers["bt-auth-timestamp"],
        "json=" + config.body.decode(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [GwmNetworkError(), GwmAuthenticationError(), {"code": "551210"}, {}])
async def test_beantech_climate_companion_failure_retains_accepted_command(failure: object, caplog) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000"}], set_bean_tech_ac_temperature=[failure],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15))
    assert result.command_id == BEAN_COMMAND_ID
    assert Counter(call.operation for call in transport.calls)["send_climate_command"] == 1
    assert "was accepted" in caplog.text
    assert BEAN_VIN not in caplog.text
    assert BEAN_COMMAND_ID not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("mode_type,expected_id,expected_type", [("warm", "123", "1"), ("cool", "456", "2"), ("common", "456", "2")])
async def test_beantech_comfort_modes_normalize_and_send_dynamic_selection(mode_type, expected_id, expected_type) -> None:
    modes = [{"modeId": 123, "type": 1, "commonUseMode": "0"}, {"modeId": "456", "type": "2", "commonUseMode": 1}]
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[{"code": "000000", "data": modes}] * 2,
        set_bean_tech_comfort_mode=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    assert await client.get_bean_tech_comfort_modes(identifier) == (
        {"modeId": "123", "type": "1", "commonUseMode": 0},
        {"modeId": "456", "type": "2", "commonUseMode": 1},
    )
    command_id = await client.set_bean_tech_comfort_mode(identifier, mode_type=mode_type)
    assert command_id == BEAN_COMMAND_ID
    request = transport.calls[-1]
    assert json.loads(request.body) == {
        "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID, "sendType": 0,
        "commands": [{"controlType": "COMFORT_MODE_CTRL", "cmdBody": {
            "action": 1, "modeId": expected_id, "type": expected_type,
        }}],
    }
    assert "securityToken" not in request.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("modeId", None), ("modeId", ""), ("modeId", " "), ("modeId", True), ("modeId", 0),
    ("modeId", 1.0), ("modeId", []), ("modeId", "private\nvalue"),
    pytest.param("modeId", "x" * 129, id="oversized-mode-id"),
    ("type", None), ("type", 0), ("type", 3), ("type", True), ("type", 1.0), ("type", []),
    ("commonUseMode", None), ("commonUseMode", 2), ("commonUseMode", True), ("commonUseMode", 1.0), ("commonUseMode", []),
])
async def test_beantech_comfort_mode_schema_rejects_before_command(field, value) -> None:
    mode = {"modeId": "123", "type": "1", "commonUseMode": 1, field: value}
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [mode]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type="common")
    assert not any(call.operation == "set_bean_tech_comfort_mode" for call in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, {}, "bad", [None], [{"time": True}], [{"time": 0}], [{"time": -1}], [{"time": 1.5}], [{"time": "1735689600000"}], [{"time": 253402214399001}]])
async def test_beantech_appointment_read_rejects_malformed_data(data: object) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, True, 0, -1, "1735689600000", 1.5, [], 253402214399001])
async def test_beantech_appointment_rejects_invalid_timestamp_before_io(value: object) -> None:
    transport = _FakeTransport()
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN), time_ms=value)  # type: ignore[arg-type]
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, True, "", "invalid", []])
async def test_beantech_comfort_rejects_invalid_mode_before_io(value: object) -> None:
    transport = _FakeTransport()
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type=value)  # type: ignore[arg-type]
    assert transport.calls == []


async def _submit_beantech_feature(client: ChinaClient, feature: str, vin: str = BEAN_VIN):
    identifier = VehicleIdentifier(vin)
    if feature == "climate":
        return await client.send_climate_command(ClimateCommand(identifier, "off", 22, 15))
    if feature == "comfort_mode":
        return await client.set_bean_tech_comfort_mode(identifier, mode_type="warm")
    if feature == "appointment":
        return await client.set_bean_tech_cabin_clean_appointment(identifier, time_ms=1735689600000)
    return await client.send_vehicle_control_command(ChinaVehicleControlCommand(identifier, "comfort_off"))


@pytest.mark.asyncio
@pytest.mark.parametrize("feature,operation", [("climate", "send_climate_command"), ("comfort_mode", "set_bean_tech_comfort_mode"), ("appointment", "set_bean_tech_cabin_clean_appointment"), ("comfort_off", "send_vehicle_control_command")])
@pytest.mark.parametrize("failure", [{}, {"data": {}}, {"code": None}, {"code": "551210"}, GwmNetworkError(), GwmRateLimitError()])
async def test_beantech_new_submissions_require_acceptance_and_never_retry(feature, operation, failure) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [{"modeId": "123", "type": "1"}]}], **{operation: [failure]})
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await _submit_beantech_feature(client, feature)
    assert Counter(call.operation for call in transport.calls)[operation] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("feature", ["comfort_mode", "appointment", "comfort_off"])
@pytest.mark.parametrize("vin", [VIN, UNSUPPORTED_VIN])
async def test_beantech_new_writes_reject_other_platforms_before_transport(feature: str, vin: str) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await _submit_beantech_feature(client, feature, vin)
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["climate", "comfort_mode", "comfort_off"] + [row[0] for row in _COMFORT_CONTRACTS])
@pytest.mark.parametrize("code,state", [(2, "pending"), (3, "pending"), (0, "completed"), (7, "failed")])
async def test_beantech_new_actions_use_timely_result_semantics(action, code, state) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_remote_command_result=[{"code": "000000", "data": {"messageList": [{"messageType": "remote", "messageData": {"transactionId": "provider-internal", "resultCode": code}}]}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action)
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, "remote", "2000" if code in {2, 3} else str(code), None),)
    assert select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None).state == state
    assert urlsplit(transport.calls[-1].url).path == "/app-api/api/v3.0/vehicle/remote-ctrl/result"


def _beantech_feature_request(kind):
    client = _client(_FakeTransport())
    state, identifier = _complete_state(), VehicleIdentifier(BEAN_VIN)
    if kind == "config":
        return client._build_bean_tech_config_request(state, identifier, temperature=22, operation_time_minutes=15)
    if kind == "subscribe":
        return client._build_bean_tech_subscribe_request(state, identifier, time_ms=1735689600000)
    if kind == "subscribe_get":
        return client._build_bean_tech_subscribe_get_request(state, identifier)
    if kind == "comfort_get":
        return client._build_bean_tech_simple_get_request(state, identifier, operation="get_bean_tech_comfort_modes", path="/app-api/api/v3.0/vehicle/one-touch/mode", url="https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/one-touch/mode")
    commands = {
        "climate": [("AIR_CONDITIONER_START", {"allowStartEng": 1, "operationTime": 900, "temperature": 22})],
        "climate_stop": [("AIR_CONDITIONER_STOP", None)],
        "seat": [("SEAT_HEATING_STOP", {"leftFront": 0, "operationMode": 1})],
        "comfort_mode": [("COMFORT_MODE_CTRL", {"action": 1, "modeId": "123", "type": "1"})],
        "comfort_off": [
            ("AIR_CONDITIONER_STOP", None),
            ("SEAT_HEATING_STOP", {"leftFront": 0, "operationMode": 1, "rightFront": 0}),
            ("SEAT_VENTILATION_STOP", {"leftFront": 0, "operationMode": 2, "rightFront": 0}),
            ("STEERING_WHEEL_HEATLESS", None),
        ],
    }[kind]
    return client._build_bean_tech_timely_request_for_commands(
        state, identifier, sequence_number=BEAN_COMMAND_ID,
        operation="send_climate_command" if kind.startswith("climate") else "set_bean_tech_comfort_mode" if kind == "comfort_mode" else "send_vehicle_control_command",
        commands=commands, send_type=1 if kind == "comfort_off" else 0,
    )


@pytest.mark.parametrize("kind", ["climate", "climate_stop", "seat", "comfort_mode", "comfort_off", "config", "subscribe", "subscribe_get", "comfort_get"])
@pytest.mark.parametrize("mutation", ["host", "path", "method", "service", "operation", "token", "signature", "content_type", "vin_header"])
def test_beantech_new_routes_reject_wrong_destinations_and_headers(kind, mutation):
    request = _beantech_feature_request(kind)
    headers, changes = dict(request.headers), {}
    if mutation == "host":
        changes["url"] = request.url.replace("gw-app-gateway.gwmapp-h.com", "example.invalid")
    elif mutation == "path":
        changes["url"] = request.url + "/unexpected"
    elif mutation == "method":
        changes["method"] = "POST" if request.method == "GET" else "GET"
    elif mutation == "service":
        changes["service"] = "auto_ai"
    elif mutation == "operation":
        changes["operation"] = "send_lock_command"
    elif mutation == "token":
        headers["securityToken"] = SENSITIVE
    elif mutation == "signature":
        headers["bt-auth-sign"] = "0" * 32
    elif mutation == "content_type":
        headers["Content-Type"] = "text/plain"
    else:
        headers["vin"] = VIN
    with pytest.raises(ValueError, match="route_invalid"):
        replace(request, headers=headers, **changes)


@pytest.mark.parametrize("kind", ["climate", "climate_stop", "seat", "comfort_mode", "comfort_off", "config", "subscribe"])
@pytest.mark.parametrize("mutation", ["list", "null", "malformed", "missing", "extra", "wrong_vin", "boolean", "command", "command_body"])
def test_beantech_new_post_schemas_reject_resigned_malformed_payloads(kind, mutation):
    request = _beantech_feature_request(kind)
    headers = dict(request.headers)
    body = json.loads(request.body)
    if mutation == "list":
        raw = b"[]"
    elif mutation == "null":
        raw = b"null"
    elif mutation == "malformed":
        raw = b"{"
    else:
        if mutation == "missing":
            body.pop(next(iter(body)))
        elif mutation == "extra":
            body["isSaveConfig"] = None
        elif mutation == "wrong_vin":
            body["vin"] = VIN
        elif mutation == "boolean":
            if "sendType" in body:
                body["sendType"] = bool(body["sendType"])
            elif "subscribeType" in body:
                body["subscribeType"] = False
            else:
                body["configs"][0]["cmdBody"]["allowStartEng"] = True
        elif mutation == "command":
            key = "configs" if kind == "config" else "commands"
            body[key] = [{"controlType": "VEHICLE_UNLOCK"}]
        else:
            key = "configs" if kind == "config" else "commands"
            body[key][0]["cmdBody"] = {"unexpected": 1}
        raw = json.dumps(body, separators=(",", ":")).encode()
    headers["bt-auth-sign"] = bean_tech_sign("POST", urlsplit(request.url).path, headers["bt-auth-nonce"], headers["bt-auth-timestamp"], "json=" + raw.decode())
    with pytest.raises(ValueError, match="route_invalid"):
        replace(request, body=raw, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [16, 32])
async def test_beantech_climate_rejects_out_of_range_temperature_before_send(temperature):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmConfigurationError):
        await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", temperature, 15))
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get_bean_tech_comfort_modes", "get_bean_tech_cabin_clean_appointment"])
async def test_beantech_new_reads_reject_bad_identifiers_and_other_platforms(method):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await getattr(client, method)(BEAN_VIN)
    assert transport.calls == []
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    for vin in (VIN, UNSUPPORTED_VIN):
        with pytest.raises(GwmRoutePolicyError):
            await getattr(client, method)(VehicleIdentifier(vin))
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [[], [{"modeId": "123", "type": "2", "commonUseMode": 0}]])
@pytest.mark.parametrize("mode", ["warm", "common"])
async def test_beantech_missing_requested_comfort_mode_is_a_schema_error(data, mode):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type=mode)
    assert not any(call.operation == "set_bean_tech_comfort_mode" for call in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [[{}], [{"time": None}]])
async def test_beantech_missing_appointment_time_is_unset(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sequence", [None, "invalid", 1, "raise"])
@pytest.mark.parametrize("feature", ["climate", "comfort_off", "comfort_mode"])
async def test_beantech_sequence_failure_prevents_physical_command(sequence, feature):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [{"modeId": "123", "type": "1"}]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    def source():
        if sequence == "raise":
            raise ValueError(SENSITIVE)
        return sequence
    client._sequence_source = source
    with pytest.raises(GwmConfigurationError) as error:
        await _submit_beantech_feature(client, feature)
    assert SENSITIVE not in str(error.value)
    assert all(not call.operation.startswith(("send_", "set_")) for call in transport.calls)


@pytest.mark.parametrize("kind,changes", [
    ("config", {"configs": [{"controlType": "AIR_CONDITIONER_START", "cmdBody": None}]}),
    ("comfort_mode", {"commands": [{"controlType": "COMFORT_MODE_CTRL", "cmdBody": None}]}),
    ("comfort_mode", {"commands": []}),
    ("comfort_mode", {"commands": [None]}),
])
def test_beantech_new_schemas_reject_incomplete_commands(kind, changes):
    request = _beantech_feature_request(kind)
    body = json.loads(request.body)
    body.update(changes)
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = dict(request.headers)
    headers["bt-auth-sign"] = bean_tech_sign("POST", urlsplit(request.url).path, headers["bt-auth-nonce"], headers["bt-auth-timestamp"], "json=" + raw.decode())
    with pytest.raises(ValueError):
        replace(request, body=raw, headers=headers)


@pytest.mark.asyncio
async def test_beantech_climate_companion_timeout_keeps_the_accepted_id():
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_climate_command=[{"code": "000000"}], set_bean_tech_ac_temperature=[_Wait()])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15), timeout=0.4)
    assert result.command_id == BEAN_COMMAND_ID
    assert Counter(call.operation for call in transport.calls)["send_climate_command"] == 1


@pytest.mark.asyncio
async def test_beantech_climate_skips_optional_save_when_deadline_is_almost_used():
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_climate_command=[{"code": "000000"}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15), timeout=0.08)
    assert result.command_id == BEAN_COMMAND_ID
    assert not any(call.operation == "set_bean_tech_ac_temperature" for call in transport.calls)


@pytest.mark.asyncio
async def test_beantech_battery_heat_commands_have_empty_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(4)
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    for action in (
        "battery_gun_heat",
        "battery_gun_heat_stop",
        "battery_initiative_heat",
        "battery_initiative_heat_stop",
    ):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(identifier, action)  # type: ignore[arg-type]
        )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {"controlType": "BATTERY_GUN_HEAT_START"},
        {"controlType": "BATTERY_GUN_HEAT_STOP"},
        {"controlType": "BATTERY_INITIATIVE_HEAT_START"},
        {"controlType": "BATTERY_INITIATIVE_HEAT_STOP"},
    ]
    for call in transport.calls:
        if call.operation == "send_vehicle_control_command":
            assert call.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in call.headers

def test_beantech_charge_setting_read_request_shape_and_signature() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_charge_setting_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
    )
    assert request.method == "GET"
    assert request.service == "bean_tech"
    assert request.url == (
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/charge/setting/"
        + BEAN_VIN
        + "?strategy=5"
    )
    assert request.body is None
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET",
        "/app-api/api/v3.0/vehicle/charge/setting/" + BEAN_VIN,
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "strategy=5",
    )

@pytest.mark.asyncio
async def test_beantech_charging_mode_write_reads_then_preserves_charge_set_param() -> None:
    charge_setting = {
        "chargingMode": 1,
        "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:00", "endTime": "07:00"},
            "drivingPlanTimes": [{"day": 1}],
        },
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": charge_setting}],
        set_bean_tech_charging_mode=[
            {"code": "000000", "data": BEAN_COMMAND_ID},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    seq_no = await client.set_bean_tech_charging_mode(identifier, enable=True)

    assert seq_no == BEAN_COMMAND_ID
    read_request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_charge_setting"
    )
    assert (
        urlsplit(read_request.url).path
        == "/app-api/api/v3.0/vehicle/charge/setting/" + BEAN_VIN
    )
    assert urlsplit(read_request.url).query == "strategy=5"

    write_request = next(
        call
        for call in transport.calls
        if call.operation == "set_bean_tech_charging_mode"
    )
    assert urlsplit(write_request.url).path == "/app-api/api/v3.0/vehicle/charge/setting"
    body = json.loads(write_request.body or b"null")
    assert body["vin"] == BEAN_VIN
    assert body["seqNo"] == BEAN_COMMAND_ID
    assert body["chargingMode"] == 0
    assert body["chargeStrategy"] == 5
    assert body["chargeSetParam"] == {
        "customTime": {"startTime": "23:00", "endTime": "07:00"},
        "drivingPlanTimes": [{"day": 1}],
    }

@pytest.mark.asyncio
async def test_beantech_charging_mode_write_aborts_when_setting_incomplete() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[
            {"code": "000000", "data": {"chargingMode": 1}},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_charging_mode(
            VehicleIdentifier(BEAN_VIN), enable=True
        )
    assert [call.operation for call in transport.calls[before:]] == [
        "get_bean_tech_charge_setting"
    ]

@pytest.mark.asyncio
async def test_beantech_charge_setting_rejects_non_beantech_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_bean_tech_charge_setting(VehicleIdentifier(VIN))
    with pytest.raises(GwmRoutePolicyError):
        await client.set_bean_tech_charging_mode(VehicleIdentifier(VIN), enable=True)
    assert len(transport.calls) == before

@pytest.mark.asyncio
async def test_beantech_battery_heating_appointment_read_parses_switch_type() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[
            {
                "code": "000000",
                "data": [
                    {
                        "type": "BATTERY_HEATING_APPOINTMENT",
                        "cmd": "BATTERY_HEATING_APPOINTMENT",
                        "cmdContent": {"switchType": 0},
                    }
                ],
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    enabled = await client.get_bean_tech_battery_heating_appointment(
        VehicleIdentifier(BEAN_VIN)
    )

    assert enabled is True
    request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_battery_heating_appointment"
    )
    assert json.loads(request.body or b"null") == {
        "sendType": 0,
        "types": ["BATTERY_HEATING_APPOINTMENT"],
        "userId": "SYNTHETIC-AUTO-USER",
        "vin": BEAN_VIN,
    }
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST",
        "/app-api/api/v3.0/vehicle/remote-ctrl/config/query",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "json=" + (request.body or b"").decode(),
    )

@pytest.mark.asyncio
async def test_beantech_battery_heating_appointment_set_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_battery_heating_appointment=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.set_bean_tech_battery_heating_appointment(
        identifier, enable=True, use_car_time_ms=1735689600000
    )
    await client.set_bean_tech_battery_heating_appointment(identifier, enable=False)

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "set_bean_tech_battery_heating_appointment"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "BATTERY_HEATING_APPOINTMENT",
            "cmdBody": {"useCarTime": 1735689600000},
        },
        {"controlType": "BATTERY_TC_STOP"},
    ]
    for request in transport.calls:
        if request.operation == "set_bean_tech_battery_heating_appointment":
            assert "securityToken" not in request.headers

@pytest.mark.asyncio
async def test_beantech_charge_soc_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_charge_soc=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    await client.set_bean_tech_charge_soc(VehicleIdentifier(BEAN_VIN), percent=80)

    request = next(
        call for call in transport.calls if call.operation == "set_bean_tech_charge_soc"
    )
    body = json.loads(request.body or b"null")
    assert body["commands"][0] == {
        "controlType": "CTRL_CHARGE_SOC",
        "cmdBody": {"chargeSoc": 80},
    }
    assert "securityToken" not in request.headers

@pytest.mark.asyncio
async def test_beantech_charge_window_write_updates_custom_time() -> None:
    charge_setting = {
        "chargingMode": 0,
        "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:00", "endTime": "07:00"},
            "drivingPlanTimes": [{"day": 1}],
        },
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": charge_setting}],
        set_bean_tech_charge_window=[{"code": "000000", "data": BEAN_COMMAND_ID}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    seq_no = await client.set_bean_tech_charge_window(
        VehicleIdentifier(BEAN_VIN), start_time="22:00", end_time="06:30"
    )

    assert seq_no == BEAN_COMMAND_ID
    write_request = next(
        call for call in transport.calls if call.operation == "set_bean_tech_charge_window"
    )
    body = json.loads(write_request.body or b"null")
    assert body["chargingMode"] == 0
    assert body["chargeStrategy"] == 5
    assert body["chargeSetParam"]["customTime"] == {
        "startTime": "22:00",
        "endTime": "06:30",
    }
    assert body["chargeSetParam"]["drivingPlanTimes"] == [{"day": 1}]

@pytest.mark.asyncio
async def test_beantech_charge_window_rejects_malformed_clock_time() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_charge_window(
            VehicleIdentifier(BEAN_VIN), start_time="25:00", end_time="07:00"
        )
    assert len(transport.calls) == before

def test_beantech_charge_result_request_uses_msg_type_charge() -> None:
    client = _client(_FakeTransport())
    command_id = "0" * 32 + "9359"
    request = client._build_bean_tech_charge_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        command_id,
    )
    assert "/app-api/api/v3.0/vehicle/remote-ctrl/result" in request.url
    assert "msgType=charge" in request.url
    assert BEAN_VIN in request.url
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET",
        "/app-api/api/v3.0/vehicle/remote-ctrl/result",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "msgtype=charge" + "seqno=" + command_id + "vin=" + BEAN_VIN,
    )

@pytest.mark.asyncio
async def test_beantech_charge_result_polling_uses_msg_type_charge() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "charge",
                            "messageData": {
                                "resultCode": "0",
                                "resultMessage": "充电设置成功",
                            },
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    results = await client.get_remote_command_results(
        identifier, BEAN_COMMAND_ID, control_action="charging_mode"
    )
    assert results == (
        RemoteCommandResultItem(BEAN_COMMAND_ID, "charge", "0", "充电设置成功"),
    )
    request = transport.calls[-1]
    assert "msgType=charge" in request.url


def _charging_setting(**updates):
    return {
        "chargingMode": 1, "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:03", "endTime": "07:07", "extension": "keep"},
            "drivingPlanTimes": [{"day": 1, "departure": "08:15"}],
            "futureField": {"nested": [1, None, True]},
        }, **updates,
    }


_CHARGING_CLIENT_CALLS = [
    ("get_bean_tech_charge_setting", {}),
    ("set_bean_tech_charging_mode", {"enable": True}),
    ("get_bean_tech_battery_heating_appointment", {}),
    ("get_bean_tech_switch_status", {}),
    ("set_bean_tech_battery_heating_appointment", {"enable": True, "use_car_time_ms": 1790000000000}),
    ("set_bean_tech_charge_soc", {"percent": 70}),
    ("set_bean_tech_charge_window", {"start_time": "22:00"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", _CHARGING_CLIENT_CALLS)
@pytest.mark.parametrize("identifier", [VIN, "LGWUNKNOWN0000001"])
async def test_charging_client_rejects_other_platforms_before_io(method, kwargs, identifier):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    count = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await getattr(client, method)(VehicleIdentifier(identifier), **kwargs)
    assert len(transport.calls) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", _CHARGING_CLIENT_CALLS)
@pytest.mark.parametrize("identifier", [None, BEAN_VIN, {}, 123])
async def test_charging_client_validates_identifier_before_authentication(method, kwargs, identifier):
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await getattr(_client(transport), method)(identifier, **kwargs)
    assert not transport.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", [
    *[("set_bean_tech_charge_soc", {"percent": value}) for value in (True, 70.0, "70", 49, 101, 55, None, [], {})],
    *[("set_bean_tech_charging_mode", {"enable": value}) for value in (0, 1, "0", None, [], {})],
    *[("set_bean_tech_battery_heating_appointment", {"enable": True, "use_car_time_ms": value})
      for value in (True, 0, -1, 1790000000000.0, "1790000000000", 253402214399001, None, [], {})],
    ("set_bean_tech_battery_heating_appointment", {"enable": 1, "use_car_time_ms": 1790000000000}),
    ("set_bean_tech_battery_heating_appointment", {"enable": False, "use_car_time_ms": 1790000000000}),
    *[("set_bean_tech_charge_window", {"start_time": value}) for value in (None, True, 800, [], {}, "8:00", "24:00", "08:60", "")],
    ("set_bean_tech_charge_window", {"end_time": "bad"}),
])
async def test_charging_client_validates_values_without_network(method, kwargs):
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await getattr(_client(transport), method)(VehicleIdentifier(BEAN_VIN), **kwargs)
    assert not transport.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    *[("chargingMode", value) for value in (None, True, False, 0.0, 1.0, 2, "2", " 0", "", [], {})],
    *[("chargeStrategy", value) for value in (None, True, False, 5.0, -1, "-1", "5.5", "", [], {})],
    *[("chargeSetParam", value) for value in (None, [], False, "invalid", {"customTime": []}, {"customTime": {}},
      {"customTime": {"startTime": "23:00"}}, {"customTime": {"startTime": "23:00", "endTime": "25:00"}})],
])
async def test_charging_settings_reject_ambiguous_values_and_abort_writes(field, value):
    data = _charging_setting(**{field: value})
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=True)
    assert [request.operation for request in transport.calls[before:]] == ["get_bean_tech_charge_setting"]


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, [], False, 0, "setting", {}])
async def test_charging_setting_missing_or_malformed_is_not_a_default_schedule(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_charge_setting(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,strategy", [(0, 5), (1, 3), ("0", "5"), ("1", "0")])
async def test_charging_setting_normalizes_mode_and_preserves_the_complete_plan(mode, strategy):
    data = _charging_setting(chargingMode=mode, chargeStrategy=strategy)
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.get_bean_tech_charge_setting(VehicleIdentifier(BEAN_VIN))
    assert result == _charging_setting(chargingMode=int(mode), chargeStrategy=int(strategy))
    assert result["chargeSetParam"] == data["chargeSetParam"]


@pytest.mark.asyncio
@pytest.mark.parametrize("enable,mode", [(True, 0), (False, 1)])
async def test_smart_charging_changes_only_mode_preserving_app_fields(enable, mode):
    data = _charging_setting(chargingMode=1 - mode)
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": data}],
        set_bean_tech_charging_mode=[{"code": "000000", "data": {}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=enable) == BEAN_COMMAND_ID
    body = json.loads(transport.calls[-1].body)
    assert body == {"vin": BEAN_VIN, "chargingMode": mode, "chargeStrategy": 5,
                    "chargeSetParam": data["chargeSetParam"], "seqNo": BEAN_COMMAND_ID}


@pytest.mark.asyncio
@pytest.mark.parametrize("updates,start,end", [({"start_time": "22:00"}, "22:00", "07:07"),
    ({"end_time": "08:00"}, "23:03", "08:00"), ({"start_time": "21:00", "end_time": "06:00"}, "21:00", "06:00")])
async def test_charging_window_edits_only_requested_bounds_from_fresh_app_settings(updates, start, end):
    data = _charging_setting(chargingMode=0, chargeStrategy="3")
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": data}],
        set_bean_tech_charge_window=[{"code": "000000", "data": {}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.set_bean_tech_charge_window(VehicleIdentifier(BEAN_VIN), **updates) == BEAN_COMMAND_ID
    expected_params = {**data["chargeSetParam"], "customTime": {"startTime": start, "endTime": end, "extension": "keep"}}
    assert json.loads(transport.calls[-1].body) == {"vin": BEAN_VIN, "chargingMode": 0, "chargeStrategy": 3,
        "chargeSetParam": expected_params, "seqNo": BEAN_COMMAND_ID}
    assert data["chargeSetParam"]["customTime"]["startTime"] == "23:03"


@pytest.mark.asyncio
@pytest.mark.parametrize("params,updates,error", [({}, {"start_time": "22:00"}, GwmSchemaError),
    ({"customTime": None}, {"end_time": "08:00"}, GwmSchemaError),
    ({"customTime": {"startTime": "22:00", "endTime": "08:00"}}, {"end_time": "22:00"}, GwmConfigurationError)])
async def test_charging_window_never_invents_a_missing_bound_or_ambiguous_full_day(params, updates, error):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting(chargeSetParam=params)}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(error):
        await client.set_bean_tech_charge_window(VehicleIdentifier(BEAN_VIN), **updates)
    assert transport.calls[-1].operation == "get_bean_tech_charge_setting"


@pytest.mark.asyncio
@pytest.mark.parametrize("value,expected", [(0, True), ("0", True), (1, False), ("1", False)])
async def test_battery_appointment_inverted_switch_values(value, expected):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": [{"cmdContent": {"switchType": value}}]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN)) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, {}, [None], [{}], [{"cmdContent": None}],
    *[[{"cmdContent": {"switchType": value}}] for value in (None, True, False, 0.0, 1.0, "2", 2, [], {})]])
async def test_battery_appointment_schema_rejects_ambiguous_state(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,expected", [({}, {"insertGunKeepWarm": None, "activeKeepWarm": None}),
    ({"insertGunKeepWarm": 1, "activeKeepWarm": "0"}, {"insertGunKeepWarm": True, "activeKeepWarm": False}),
    ({"insertGunKeepWarm": "0", "activeKeepWarm": 1}, {"insertGunKeepWarm": False, "activeKeepWarm": True})])
async def test_battery_switch_status_maps_exact_values_and_missing_fields(raw, expected):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_switch_status=[{"code": "000000", "data": {"switchStatus": raw}}],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": []}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_switch_status(VehicleIdentifier(BEAN_VIN)) == expected
    assert await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, [], {}, {"switchStatus": None}, {"switchStatus": []},
    *[{"switchStatus": {"insertGunKeepWarm": value}} for value in (True, False, 0.0, 1.0, 2, "on", [], {})]])
async def test_battery_switch_status_rejects_unrecognized_state(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_switch_status=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_switch_status(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", [case for case in _CHARGING_CLIENT_CALLS if case[0].startswith("set_")])
@pytest.mark.parametrize("failure", [{}, {"data": {}}, {"code": "551210"}, {"code": "7"}, OSError("synthetic network failure")])
async def test_charging_writes_require_explicit_acceptance_without_retry(method, kwargs, failure):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting()}], **{method: [failure]})
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await getattr(client, method)(VehicleIdentifier(BEAN_VIN), **kwargs)
    assert sum(request.operation == method for request in transport.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["battery_gun_heat", "battery_gun_heat_stop", "battery_initiative_heat", "battery_initiative_heat_stop",
    "charging_mode", "charge_window", "charge_soc", "battery_appointment"])
@pytest.mark.parametrize("code,state", [("2", "pending"), ("3", "pending"), ("0", "completed"), ("7", "failed")])
async def test_charging_results_use_typed_routes_and_pending_semantics(action, code, state):
    family = "charge" if action in {"charging_mode", "charge_window"} else "remote"
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [{"messageType": family,
            "messageData": {"resultCode": code, "transactionId": "provider-different-id"}}]}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_results(VehicleIdentifier(VIN), BEAN_COMMAND_ID, control_action=action)
    results = await client.get_remote_command_results(VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action)
    expected_code = "2000" if code in {"2", "3"} else code
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, family, expected_code, None),)
    result = select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None, expected_remote_type="charge" if family == "charge" else "china")
    assert result.state == state
    assert transport.calls[-1].url.endswith("&msgType=" + family)


@pytest.mark.asyncio
async def test_concurrent_charge_window_edits_preserve_each_other_and_app_fields():
    started, release = asyncio.Event(), asyncio.Event()
    settings = _charging_setting()
    operations = []
    class Transport(_FakeTransport):
        async def execute(self, request, **kwargs):
            if request.operation == "get_bean_tech_charge_setting":
                operations.append("read")
                if not started.is_set():
                    started.set()
                    await release.wait()
                return _response({"code": "000000", "data": settings})
            if request.operation == "set_bean_tech_charge_window":
                operations.append("write")
                settings.update(json.loads(request.body))
                return _response({"code": "000000"})
            return await super().execute(request, **kwargs)
    transport = Transport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    start = asyncio.create_task(client.set_bean_tech_charge_window(identifier, start_time="22:00"))
    await started.wait()
    end = asyncio.create_task(client.set_bean_tech_charge_window(identifier, end_time="08:00"))
    release.set()
    await asyncio.gather(start, end)
    assert operations == ["read", "write", "read", "write"]
    expected = _charging_setting()
    expected["chargeSetParam"]["customTime"].update(startTime="22:00", endTime="08:00")
    assert settings == {**expected, "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID}


@pytest.mark.asyncio
async def test_cancelled_charge_setting_read_never_submits_a_write():
    started = asyncio.Event()
    class Transport(_FakeTransport):
        async def execute(self, request, **kwargs):
            if request.operation == "get_bean_tech_charge_setting":
                started.set()
                await asyncio.Event().wait()
            return await super().execute(request, **kwargs)
    transport = Transport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    task = asyncio.create_task(client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=True))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not any(call.operation == "set_bean_tech_charging_mode" for call in transport.calls)


@pytest.mark.parametrize("failure", [None, "bad", RuntimeError("private-source-error")])
def test_charge_result_builder_rejects_invalid_nonce_without_exposing_source(failure):
    client = _client(_FakeTransport())
    def nonce():
        if isinstance(failure, Exception):
            raise failure
        return failure
    client._nonce_source = nonce
    with pytest.raises(GwmConfigurationError) as raised:
        client._build_bean_tech_charge_result_request(_complete_state(), VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID)
    assert "private-source-error" not in str(raised.value)


@pytest.mark.parametrize("state", [_empty_state(), _partial_state()])
def test_charge_result_builder_rejects_incomplete_authentication(state):
    with pytest.raises(GwmAuthenticationError):
        _client(_FakeTransport())._build_bean_tech_charge_result_request(state, VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID)


def test_battery_appointment_query_builder_requires_user_id():
    with pytest.raises(GwmAuthenticationError):
        _client(_FakeTransport())._build_bean_tech_config_query_request(
            _partial_state(), VehicleIdentifier(BEAN_VIN),
            types=["BATTERY_HEATING_APPOINTMENT"], operation="get_bean_tech_battery_heating_appointment",
        )
