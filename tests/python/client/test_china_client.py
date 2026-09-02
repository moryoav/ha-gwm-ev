"""Offline production-contract tests for the isolated mainland-China client."""

from __future__ import annotations

import asyncio
import json
from collections import Counter, deque
from collections.abc import Mapping
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
    bean_tech_security_password: str | None = None,
) -> ChinaClient:
    return ChinaClient(
        config or ChinaClientConfig(),
        transport=transport,
        clock=clock,
        salt_source=lambda: bytes.fromhex(FIXTURE["salt_hex"]),
        nonce_source=lambda: FIXTURE["nonce"],
        sequence_source=lambda: BEAN_COMMAND_ID,
        sleeper=sleeper,
        bean_tech_security_password=bean_tech_security_password,
    )


def _deadline() -> _Deadline:
    return _Deadline(asyncio.get_running_loop().time() + 10)


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
async def test_navinfo_climate_start_heat_update_stop_and_result_contracts() -> None:
    transaction_ids = ("TX-START-1", "TX-HEAT-2", "TX-STOP-3")
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
        ClimateCommand(identifier, "cool", 21, 10, currently_on=False)
    )
    heated = await client.send_climate_command(
        ClimateCommand(identifier, "heat", 26, 20, currently_on=True)
    )
    stopped = await client.send_climate_command(
        ClimateCommand(identifier, "off", 22, 15, currently_on=True)
    )
    results = await client.get_remote_command_results(identifier, heated.command_id)

    assert (started.command_id, heated.command_id, stopped.command_id) == transaction_ids
    command_requests = [
        request for request in transport.calls if request.operation == "send_climate_command"
    ]
    start_payload, heat_payload, stop_payload = map(_auto_ai_payload, command_requests)
    assert start_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert start_payload["body"]["cmdCode"] == 6
    assert start_payload["body"]["airParams"] == {
        "engineControl": 1,
        "runTime": 10,
        "temperature": 21,
    }
    assert heat_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert heat_payload["body"]["cmdCode"] == 6
    assert heat_payload["body"]["airParams"] == {
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
        "seqNo=TX-HEAT-2&vin=" + VIN + "&msgType=remote"
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
        ClimateCommand(VehicleIdentifier(VIN), "cool", 22, 10)
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
                ClimateCommand(VehicleIdentifier(VIN), "cool", temperature, 10)
            )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_climate_start_and_stop_use_timely_without_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
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
async def test_beantech_climate_uses_t5_path_when_no_security_password() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_climate_command(
        ClimateCommand(VehicleIdentifier(BEAN_VIN), "off", 22, 15)
    )
    sent = next(
        call for call in transport.calls if call.operation == "send_climate_command"
    )
    assert sent.url.endswith("/app-api/api/v1.0/vehicle/T5/sendCmd")
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_climate_rejects_temperatures_outside_captured_range() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)

    for temperature in (16, 32):
        with pytest.raises(GwmConfigurationError):
            await client.send_climate_command(
                ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", temperature, 15)
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
async def test_beantech_lock_and_windows_use_timely_with_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[
            {"code": "000000", "data": "JWT"} for _ in range(3)
        ],
        send_lock_command=[{"code": "000000", "data": {}} for _ in range(2)],
        send_close_windows_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    await client.send_lock_command(DoorLockCommand(identifier, lock=False))
    await client.send_lock_command(DoorLockCommand(identifier, lock=True))
    await client.send_close_windows_command(CloseWindowsCommand(identifier))

    bodies = [
        json.loads(call.body or b"null")
        for call in transport.calls
        if call.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    assert [body["commands"][0] for body in bodies] == [
        {"controlType": "VEHICLE_UNLOCK"},
        {"controlType": "VEHICLE_LOCK"},
        {
            "controlType": "WINDOW_CLOSE",
            "cmdBody": {
                "leftFront": 0,
                "leftBack": 0,
                "rightFront": 0,
                "rightBack": 0,
            },
        },
    ]
    assert sum(
        1 for call in transport.calls if call.operation == "generate_security_token"
    ) == 3


@pytest.mark.asyncio
async def test_beantech_result_polling_parses_v3_message_list_when_password_configured() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": "JWT"}],
        send_lock_command=[{"code": "000000", "data": {}}],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": {
                                "resultCode": "0",
                                "resultMessage": "闭锁成功",
                            },
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    locked = await client.send_lock_command(DoorLockCommand(identifier, True))
    results = await client.get_remote_command_results(identifier, locked.command_id)

    assert results == (
        RemoteCommandResultItem(BEAN_COMMAND_ID, "remote", "0", "闭锁成功"),
    )


@pytest.mark.asyncio
async def test_beantech_result_polling_normalises_pending_v3_result() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": "JWT"}],
        send_lock_command=[{"code": "000000", "data": {}}],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": {"resultCode": "2"},
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    locked = await client.send_lock_command(DoorLockCommand(identifier, True))
    results = await client.get_remote_command_results(identifier, locked.command_id)

    assert results[0].result_code == "2000"
    assert results[0].result_message == "Command is still running"


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
        {"controlType": "WHISTLE", "cmdBody": None},
        {"controlType": "FLASH", "cmdBody": None},
        {"controlType": "SKYLIGNT_CLOSE", "cmdBody": {"skyLight": 0}},
    ]

    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(identifier, "tailgate_open")
        )
    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_uses_t5_path_when_no_security_password() -> None:
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
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "remote_stop")
    )
    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v1.0/vehicle/T5/sendCmd")
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_uses_timely_path_with_token_when_password_configured() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": "JWT"}],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "remote_stop")
    )
    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert sent.headers["securityToken"] == "JWT"
    assert sum(
        1 for call in transport.calls if call.operation == "generate_security_token"
    ) == 1


@pytest.mark.asyncio
async def test_beantech_pin_exempt_commands_skip_token_generation() -> None:
    actions = (
        "horn",
        "flash_lights",
        "horn_and_lights",
        "seat_heating_start",
        "seat_heating_stop",
        "seat_heating_start_passenger",
        "seat_heating_stop_passenger",
        "seat_ventilation_start",
        "seat_ventilation_stop",
        "seat_ventilation_start_passenger",
        "seat_ventilation_stop_passenger",
        "steering_wheel_heating",
        "steering_wheel_heatless",
        "defrost_front_start",
        "defrost_front_stop",
        "defrost_back_start",
        "defrost_back_stop",
        "cabin_clean",
        "comfort_warm",
        "comfort_cool",
        "battery_gun_heat",
        "battery_gun_heat_stop",
        "battery_initiative_heat",
        "battery_initiative_heat_stop",
    )
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in actions
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    for action in actions:
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action)  # type: ignore[arg-type]
        )
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )
    for call in transport.calls:
        if call.operation == "send_vehicle_control_command":
            assert call.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in call.headers


@pytest.mark.asyncio
async def test_beantech_security_token_is_read_from_plain_data_string() -> None:
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": token}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    resolved = await client._generate_bean_tech_security_token(
        client._required_session(operation="send_lock_command"),
        VehicleIdentifier(BEAN_VIN),
        operation="send_lock_command",
        deadline=_deadline(),
    )
    assert resolved == token

    request = next(
        call for call in transport.calls if call.operation == "generate_security_token"
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/security/generate-token")
    assert json.loads(request.body or b"null") == {
        "securityPwd": "ENCRYPTED==",
        "eventType": 2,
        "version": 1,
    }


@pytest.mark.asyncio
async def test_beantech_security_token_rejects_non_string_data() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": {"securityToken": "x"}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client._generate_bean_tech_security_token(
            client._required_session(operation="send_lock_command"),
            VehicleIdentifier(BEAN_VIN),
            operation="send_lock_command",
            deadline=_deadline(),
        )


def test_beantech_timely_request_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_lock_command",
        control_type="VEHICLE_UNLOCK",
        command_body=None,
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert request.headers["securityToken"] == "JWT"
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [{"controlType": "VEHICLE_UNLOCK"}],
    }


def test_beantech_timely_request_omits_security_token_header_when_exempt() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_vehicle_control_command",
        control_type="FLASH",
        command_body=None,
        security_token=None,
    )
    assert "securityToken" not in request.headers


def test_beantech_timely_request_windows_close_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_close_windows_command",
        control_type="WINDOW_CLOSE",
        command_body={"leftFront": 0, "leftBack": 0, "rightFront": 0, "rightBack": 0},
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert request.headers["securityToken"] == "JWT"
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [
            {
                "controlType": "WINDOW_CLOSE",
                "cmdBody": {"leftFront": 0, "leftBack": 0, "rightFront": 0, "rightBack": 0},
            }
        ],
    }


def test_beantech_timely_request_engine_start_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_vehicle_control_command",
        control_type="ENGINE_START",
        command_body={"operationTime": 600},
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert request.headers["securityToken"] == "JWT"
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [{"controlType": "ENGINE_START", "cmdBody": {"operationTime": 600}}],
    }


def test_beantech_timely_request_rejects_engine_start_without_body() -> None:
    client = _client(_FakeTransport())
    with pytest.raises(ValueError):
        client._build_bean_tech_timely_request(
            _complete_state(),
            VehicleIdentifier(BEAN_VIN),
            sequence_number="0" * 32 + "9359",
            operation="send_vehicle_control_command",
            control_type="ENGINE_START",
            command_body=None,
            security_token="JWT",
        )


def test_beantech_timely_request_climate_start_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_climate_command",
        control_type="AIR_CONDITIONER_START",
        command_body={"allowStartEng": 1, "operationTime": 900, "temperature": 22},
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert request.headers["securityToken"] == "JWT"
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [
            {
                "controlType": "AIR_CONDITIONER_START",
                "cmdBody": {"allowStartEng": 1, "operationTime": 900, "temperature": 22},
            }
        ],
    }


def test_beantech_timely_request_climate_stop_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_climate_command",
        control_type="AIR_CONDITIONER_STOP",
        command_body=None,
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [{"controlType": "AIR_CONDITIONER_STOP"}],
    }


def test_beantech_result_request_uses_v3_endpoint_when_password_configured() -> None:
    client = _client(_FakeTransport(), bean_tech_security_password="ENCRYPTED==")
    command_id = "0" * 32 + "9359"
    request = client._build_bean_tech_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        command_id,
    )
    assert "/app-api/api/v3.0/vehicle/remote-ctrl/result" in request.url
    assert "msgType=remote" in request.url
    assert BEAN_VIN in request.url
    # The sign must use the canonical parameter (sorted, lowercased keys, no
    # separators) exactly as the retired add-on's SendBeanTechGetAsync did.
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET",
        "/app-api/api/v3.0/vehicle/remote-ctrl/result",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "msgtype=remote" + "seqno=" + command_id + "vin=" + BEAN_VIN,
    )


def test_beantech_result_request_keeps_t5_endpoint_without_password() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        "0" * 32 + "9359",
    )
    assert request.url.startswith(
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
    )


def test_beantech_records_request_shape_and_signature() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_records_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        page_num=3,
        page_size=7,
    )
    assert request.url == (
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/records/query"
    )
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "type": "SELF",
        "pageNum": 3,
        "pageSize": 7,
    }
    assert request.headers["Content-Type"] == "application/json; charset=UTF-8"
    # The sign must be over the exact encoded body, matching the retired add-on's
    # SendBeanTechPostAsync ("json=" + rawBody) and no security token.
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST",
        "/app-api/api/v3.0/vehicle/remote-ctrl/records/query",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "json=" + (request.body or b"").decode(),
    )


@pytest.mark.asyncio
async def test_beantech_remote_records_are_read_and_returned_raw() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_records=[
            {
                "code": "000000",
                "data": {
                    "pageNum": 1,
                    "total": 2,
                    "pages": 1,
                    "list": [
                        {
                            "resultMsg": "电池包插枪保温关闭成功",
                            "seqNo": "0123456789abcdef0123456789abcdef1234",
                        },
                        {
                            "resultMsg": "闭锁成功",
                            "seqNo": "0123456789abcdef0123456789abcdef9999",
                        },
                    ],
                },
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    records = await client.get_remote_command_records(
        VehicleIdentifier(BEAN_VIN), page_num=1, page_size=20
    )
    assert records["pageNum"] == 1
    assert records["total"] == 2
    assert records["pages"] == 1
    assert [item["resultMsg"] for item in records["list"]] == [
        "电池包插枪保温关闭成功",
        "闭锁成功",
    ]
    request = transport.calls[-1]
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/records/query")
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "type": "SELF",
        "pageNum": 1,
        "pageSize": 20,
    }


@pytest.mark.asyncio
async def test_beantech_remote_records_reject_non_beantech_platforms_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_records(VehicleIdentifier(VIN))
    assert len(transport.calls) == before


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
async def test_beantech_horn_and_lights_maps_to_whistle_flash() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    accepted = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn_and_lights")
    )
    assert accepted.command_id == BEAN_COMMAND_ID

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert sends[0]["commands"][0] == {
        "controlType": "WHISTLE_FLASH",
        "cmdBody": None,
    }


@pytest.mark.asyncio
async def test_beantech_seat_heating_start_and_stop_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_heating_start")
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_heating_stop")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "SEAT_HEATING_START",
            "cmdBody": {"leftFront": 3, "operationTime": 600},
        },
        {
            "controlType": "SEAT_HEATING_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 1},
        },
    ]
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_seat_heating_passenger_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_heating_start_passenger")
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_heating_stop_passenger")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "SEAT_HEATING_START",
            "cmdBody": {"rightFront": 3, "operationTime": 600},
        },
        {
            "controlType": "SEAT_HEATING_STOP",
            "cmdBody": {"rightFront": 0, "operationMode": 1},
        },
    ]
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_seat_ventilation_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_ventilation_start")
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_ventilation_stop")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "SEAT_VENTILATION_START",
            "cmdBody": {"leftFront": 3, "operationTime": 600},
        },
        {
            "controlType": "SEAT_VENTILATION_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 2},
        },
    ]
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_seat_ventilation_passenger_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_ventilation_start_passenger")
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "seat_ventilation_stop_passenger")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "SEAT_VENTILATION_START",
            "cmdBody": {"rightFront": 3, "operationTime": 600},
        },
        {
            "controlType": "SEAT_VENTILATION_STOP",
            "cmdBody": {"rightFront": 0, "operationMode": 2},
        },
    ]
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_cabin_clean_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "cabin_clean")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert sends[0]["commands"][0] == {
        "controlType": "CABIN_CLEANING_START",
        "cmdBody": {"operationTime": 60},
    }
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_comfort_warm_and_cool_cmdbody_exact() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "comfort_warm")
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(identifier, "comfort_cool")
    )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "COMFORT_MODE_CTRL",
            "cmdBody": {"action": 1, "modeId": "4982234", "type": "1"},
        },
        {
            "controlType": "COMFORT_MODE_CTRL",
            "cmdBody": {"action": 1, "modeId": "4982235", "type": "2"},
        },
    ]
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_comfort_off_multicommand_shape() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
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
async def test_beantech_comfort_off_requires_pin_and_rejects_legacy_path() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmConfigurationError):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "comfort_off")
        )
    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_battery_heat_commands_have_empty_cmdbody_and_skip_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(4)
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
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
    # Battery heating is PIN-exempt, so no security token is fetched even when
    # a PIN is configured, and the commands travel the timely path unsigned.
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )
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


def test_beantech_charge_result_request_uses_msg_type_charge() -> None:
    client = _client(_FakeTransport(), bean_tech_security_password="ENCRYPTED==")
    command_id = "0" * 32 + "9359"
    request = client._build_bean_tech_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        command_id,
        msg_type="charge",
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
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    results = await client.get_remote_command_results(
        identifier, BEAN_COMMAND_ID, msg_type="charge"
    )
    assert results == (
        RemoteCommandResultItem(BEAN_COMMAND_ID, "charge", "0", "充电设置成功"),
    )
    request = transport.calls[-1]
    assert "msgType=charge" in request.url
