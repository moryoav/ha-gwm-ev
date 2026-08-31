"""Offline Russia authentication state-machine and wire-contract tests."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections import deque
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import gwm_client.russia_auth as auth_module
from gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse
from gwm_client.client import GwmClient
from gwm_client.config import GwmClientConfig, RequestTimeouts
from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmRoutePolicyError,
    GwmSchemaError,
)
from gwm_client.models import GwmSession
from gwm_client.regions import Region
from gwm_client.russia_auth import (
    RussiaAuthenticated,
    RussiaAuthState,
    RussiaCredentials,
    RussiaVerificationRequired,
    _RussiaAuthProgress,
    authenticate_russia,
)
from gwm_client.russia_identity import RussiaBootstrapMaterial
from gwm_client.tls import LEGACY_CIPHER_STRING

FIXTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "russia_auth_contracts_v1.json"
    ).read_text(encoding="utf-8")
)
READ_FIXTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "russia_read_responses_v1.json"
    ).read_text(encoding="utf-8")
)
RESOURCE_DIR = (
    Path(__file__).resolve().parents[3]
    / "custom_components"
    / "gwm_ora"
    / "resources"
)
ACCOUNT = FIXTURE["credentials"]["account"]
PASSWORD = FIXTURE["credentials"]["password"]
CODE = FIXTURE["credentials"]["verification_code"]
DEVICE_ID = FIXTURE["credentials"]["device_id"]
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SENSITIVE = "SENSITIVE-RUSSIA-PRIVATE-MATERIAL"


class _FakeTransport:
    def __init__(
        self,
        *items: object,
        delay: float = 0,
        hang: bool = False,
    ) -> None:
        self.items = deque(items)
        self.requests: list[_TransportRequest] = []
        self.delay = delay
        self.hang = hang
        self.entered = asyncio.Event()
        self.active = 0
        self.max_active = 0
        self.close_calls = 0

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        del deadline, connect_timeout, read_timeout
        self.requests.append(request)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            if not self.items:
                raise AssertionError(f"unexpected operation {request.operation}")
            item = self.items.popleft()
            if isinstance(item, BaseException):
                raise item
            if type(item) is _TransportResponse:
                return item
            return _response(item)
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        self.close_calls += 1


def _response(
    value: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> _TransportResponse:
    return _TransportResponse(
        status=status,
        headers={} if headers is None else headers,
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


def _credentials(
    *,
    account: str = ACCOUNT,
    device_id: str = DEVICE_ID,
) -> RussiaCredentials:
    return RussiaCredentials(
        account=account,
        password=PASSWORD,
        country="RU",
        device_id=device_id,
    )


def _state(
    credentials: RussiaCredentials | None = None,
    **changes: object,
) -> RussiaAuthState:
    credentials = credentials or _credentials()
    values: dict[str, object] = {
        "account_binding": credentials.account_binding,
        "country": credentials.country,
        "device_id": credentials.device_id,
    }
    values.update(changes)
    return RussiaAuthState(**values)  # type: ignore[arg-type]


def _material() -> RussiaBootstrapMaterial:
    return RussiaBootstrapMaterial(
        certificate_data=(RESOURCE_DIR / "gwm_general_rus.cer").read_bytes(),
        transformed_private_key_data=(
            RESOURCE_DIR / "gwm_general_rus.key"
        ).read_bytes(),
        ca_bundle=(RESOURCE_DIR / "gwm_root_rus.pem").read_bytes(),
    )


def _legacy_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_ciphers(LEGACY_CIPHER_STRING)
    assert context.security_level == 0
    return context


def _session(
    state: RussiaAuthState,
    *,
    token: str | None = None,
    context: ssl.SSLContext | None = None,
) -> GwmSession:
    access_token = token or state.access_token
    assert access_token is not None
    return GwmSession(
        country=state.country,
        device_id=state.device_id,
        access_token=access_token,
        app_ssl_context=context or _legacy_context(),
    )


def _client(
    transport: _FakeTransport,
    *,
    session: GwmSession | None = None,
    total_timeout: float = 5,
) -> GwmClient:
    return GwmClient(
        GwmClientConfig(
            region=Region.RUSSIA,
            timeouts=RequestTimeouts(
                total=total_timeout,
                connect=min(1, total_timeout),
                read=min(1, total_timeout),
            ),
        ),
        session,
        transport=transport,
    )


def _patch_identity(monkeypatch: pytest.MonkeyPatch) -> ssl.SSLContext:
    context = _legacy_context()
    monkeypatch.setattr(
        auth_module,
        "create_russia_bootstrap_ssl_context",
        lambda material, *, now: context,
    )
    return context


def _deadline(seconds: float = 5) -> _Deadline:
    return _Deadline(asyncio.get_running_loop().time() + seconds)


async def _authenticate(
    transport: _FakeTransport,
    *,
    credentials: RussiaCredentials | None = None,
    state: RussiaAuthState | None = None,
    verification_code: str | None = None,
    progress: _RussiaAuthProgress | None = None,
    allow_password_login: bool = True,
) -> RussiaAuthenticated | RussiaVerificationRequired:
    return await authenticate_russia(
        config=GwmClientConfig(region=Region.RUSSIA),
        transport=transport,
        credentials=credentials or _credentials(),
        state=state,
        verification_code=verification_code,
        allow_password_login=allow_password_login,
        bootstrap_material=_material(),
        deadline=_deadline(),
        progress=progress or _RussiaAuthProgress(),
    )


def _success_data(name: str) -> object:
    return FIXTURE["responses"][name]


def _read_response(operation: str) -> object:
    return {
        "code": "000000",
        "description": "SYNTHETIC-SUCCESS",
        "data": READ_FIXTURE["responses"][operation],
    }


def test_credentials_state_and_outcomes_are_bound_immutable_and_repr_safe() -> None:
    credentials = _credentials(device_id="feedface-dead-beef-cafe-0123456789ab")
    state = _state(
        credentials,
        access_token="SYNTHETIC-ACCESS",
        refresh_token="SYNTHETIC-REFRESH",
        gw_id="SYNTHETIC-GW-ID",
    )

    assert credentials.device_id == "feedface-dead-beef-cafe-0123456789ab"
    assert state.matches(credentials)
    assert len(credentials.account_binding) == 64
    for secret in (ACCOUNT, PASSWORD, credentials.device_id, "SYNTHETIC-ACCESS"):
        assert secret not in repr(credentials)
        assert secret not in repr(state)

    with pytest.raises((AttributeError, TypeError)):
        state.access_token = SENSITIVE  # type: ignore[misc]
    assert not state.matches(_credentials(account="SYNTHETIC-other@example.invalid"))
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        RussiaCredentials(ACCOUNT, PASSWORD, "AU", DEVICE_ID)
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        replace(state, device_id="not a device")


def test_every_closed_auth_request_matches_exact_fixture_contract() -> None:
    credentials = _credentials()
    state = _state(
        credentials,
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    context = ssl.create_default_context()
    requests = {
        "login": auth_module._prepare_request(
            endpoint=auth_module._LOGIN,
            credentials=credentials,
            body=auth_module._password_login_body(credentials),
            access_token=None,
            ssl_context=context,
        ),
        "verified_login": auth_module._prepare_request(
            endpoint=auth_module._VERIFY_CODE,
            credentials=credentials,
            body=auth_module._verification_login_body(credentials, CODE),
            access_token=None,
            ssl_context=context,
        ),
        "request_verification": auth_module._prepare_request(
            endpoint=auth_module._REQUEST_VERIFICATION,
            credentials=credentials,
            body=auth_module._verification_request_body(credentials),
            access_token=None,
            ssl_context=context,
        ),
        "refresh": auth_module._prepare_request(
            endpoint=auth_module._REFRESH,
            credentials=credentials,
            body=auth_module._refresh_body(credentials, state),
            access_token=None,
            ssl_context=context,
        ),
        "get_user_info": auth_module._prepare_request(
            endpoint=auth_module._USER_INFO,
            credentials=credentials,
            body=None,
            access_token="SYNTHETIC-OLD-ACCESS",
            ssl_context=context,
        ),
    }

    assert set(requests) == set(FIXTURE["operations"])
    for name, request in requests.items():
        expected = FIXTURE["operations"][name]
        parsed = urlsplit(request.url)
        assert request.method == expected["method"]
        assert parsed.hostname == expected["host"]
        assert parsed.path == expected["path"]
        assert not parsed.query
        assert (None if request.body is None else request.body.decode()) == expected["body"]
        assert ("accessToken" in request.headers) is expected["access_token_header"]
        assert request.headers["deviceId"] == DEVICE_ID
        assert request.headers["iccid"] == DEVICE_ID
        assert set(
            name for name in request.headers if name.startswith("gwm-auth-")
        ) == {
            "gwm-auth-appkey",
            "gwm-auth-nonce",
            "gwm-auth-timestamp",
            "gwm-auth-sign",
        }
    assert b"countryCode" not in requests["login"].body  # type: ignore[operator]
    assert PASSWORD.encode() not in requests["verified_login"].body  # type: ignore[operator]


def test_full_hyphenated_russia_device_id_is_preserved_on_the_wire() -> None:
    device_id = "feedface-dead-beef-cafe-0123456789ab"
    credentials = _credentials(device_id=device_id)
    state = _state(
        credentials,
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    context = ssl.create_default_context()
    login = auth_module._prepare_request(
        endpoint=auth_module._LOGIN,
        credentials=credentials,
        body=auth_module._password_login_body(credentials),
        access_token=None,
        ssl_context=context,
    )
    refresh = auth_module._prepare_request(
        endpoint=auth_module._REFRESH,
        credentials=credentials,
        body=auth_module._refresh_body(credentials, state),
        access_token=None,
        ssl_context=context,
    )

    assert login.headers["deviceId"] == device_id
    assert login.headers["iccid"] == device_id
    assert refresh.headers["deviceId"] == device_id
    assert refresh.headers["iccid"] == device_id
    assert json.loads(login.body)["deviceId"] == device_id
    assert json.loads(refresh.body)["deviceId"] == device_id


@pytest.mark.asyncio
async def test_fresh_password_login_validates_profile_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_context = _patch_identity(monkeypatch)
    transport = _FakeTransport(
        _success_data("login"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(transport)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-NEW-ACCESS"
    assert result.state.refresh_token == "SYNTHETIC-NEW-REFRESH"
    assert result.state.gw_id == "9007199254740993"
    assert result.state.bean_id == "9007199254740995"
    assert result.session.app_ssl_context is app_context
    assert [request.operation for request in transport.requests] == [
        "login",
        "get_user_info",
    ]
    assert not hasattr(result.state, "email")


@pytest.mark.asyncio
async def test_stored_access_success_skips_refresh_and_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
        gw_id="SYNTHETIC-OLD-GW",
    )
    transport = _FakeTransport(_success_data("get_user_info"))

    result = await _authenticate(transport, state=state)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-OLD-ACCESS"
    assert result.state.refresh_token == "SYNTHETIC-OLD-REFRESH"
    assert result.state.gw_id == "9007199254740993"
    assert [request.operation for request in transport.requests] == [
        "get_user_info"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_existing_access_auth_rejection_refreshes_without_access_header_and_rotates(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    progress = _RussiaAuthProgress()
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _response({}, status=status),
        _success_data("refresh"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(transport, state=state, progress=progress)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-ROTATED-ACCESS"
    assert result.state.refresh_token == "SYNTHETIC-ROTATED-REFRESH"
    assert progress.existing_session_rejected
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]
    assert "accessToken" not in transport.requests[1].headers
    assert json.loads(transport.requests[1].body) == {
        "accessToken": "SYNTHETIC-OLD-ACCESS",
        "refreshToken": "SYNTHETIC-OLD-REFRESH",
        "deviceId": DEVICE_ID,
    }


@pytest.mark.asyncio
async def test_expired_access_api_code_refreshes_and_rotates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _response({"code": "550004", "data": {}}),
        _success_data("refresh"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(transport, state=state)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-ROTATED-ACCESS"
    assert result.state.refresh_token == "SYNTHETIC-ROTATED-REFRESH"
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
async def test_runtime_russia_refresh_installs_rotated_session() -> None:
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    context = _legacy_context()
    transport = _FakeTransport(
        _success_data("refresh"),
        _success_data("get_user_info"),
    )
    client = _client(transport, session=_session(state, context=context))

    result = await client.refresh_russia_session(_credentials(), state)

    assert result.state.access_token == "SYNTHETIC-ROTATED-ACCESS"
    assert result.state.refresh_token == "SYNTHETIC-ROTATED-REFRESH"
    assert result.session.app_ssl_context is context
    assert client._session == result.session
    assert [request.operation for request in transport.requests] == [
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_access_and_refresh_auth_rejections_fall_through_to_password_login(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _response({}, status=status),
        _response({}, status=status),
        _success_data("login"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(transport, state=state)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-NEW-ACCESS"
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "login",
        "get_user_info",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_resume_only_rejection_never_falls_through_to_password_or_sms(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _response({}, status=status),
        _response({}, status=status),
    )

    with pytest.raises(GwmAuthenticationError):
        await _authenticate(
            transport,
            state=state,
            allow_password_login=False,
        )

    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_refreshed_profile_auth_rejection_falls_through_to_password_login(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _response({}, status=status),
        _success_data("refresh"),
        _response({}, status=status),
        _success_data("login"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(transport, state=state)

    assert type(result) is RussiaAuthenticated
    assert result.state.access_token == "SYNTHETIC-NEW-ACCESS"
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
        "login",
        "get_user_info",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["refresh", "refreshed_profile"])
async def test_unknown_refresh_or_profile_error_stops_without_login(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    responses: list[object] = [_response({}, status=401)]
    if failure_stage == "refresh":
        responses.append({"code": "900001", "description": SENSITIVE})
    else:
        responses.extend(
            [
                _success_data("refresh"),
                {"code": "900001", "description": SENSITIVE},
            ]
        )
    transport = _FakeTransport(*responses)

    with pytest.raises(GwmApiError) as raised:
        await _authenticate(transport, state=state)

    assert raised.value.api_code == "900001"
    assert all(request.operation != "login" for request in transport.requests)
    assert len(transport.requests) == (2 if failure_stage == "refresh" else 3)


@pytest.mark.asyncio
async def test_exact_challenge_requests_one_code_and_returns_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    monkeypatch.setattr(auth_module, "_utc_now", lambda: NOW)
    transport = _FakeTransport(
        _success_data("verification_challenge"),
        {"code": "000000", "data": None},
    )

    result = await _authenticate(transport)

    assert type(result) is RussiaVerificationRequired
    assert result.code_requested
    assert not result.code_rejected
    assert result.state.verification_requested_at == NOW
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
    ]

    throttled = _FakeTransport(_success_data("verification_challenge"))
    repeated = await _authenticate(
        throttled,
        state=replace(result.state, verification_requested_at=NOW - timedelta(minutes=9)),
    )
    assert type(repeated) is RussiaVerificationRequired
    assert not repeated.code_requested
    assert len(throttled.requests) == 1


@pytest.mark.asyncio
async def test_failed_verification_delivery_publishes_no_throttle_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    monkeypatch.setattr(auth_module, "_utc_now", lambda: NOW)
    original = _state()
    transport = _FakeTransport(
        _success_data("verification_challenge"),
        {"code": "900001", "description": SENSITIVE},
    )

    with pytest.raises(GwmApiError) as raised:
        await _authenticate(transport, state=original)

    assert raised.value.operation == "request_verification"
    assert original.verification_requested_at is None
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_future_verification_timestamp_is_not_treated_as_throttled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    monkeypatch.setattr(auth_module, "_utc_now", lambda: NOW)
    state = _state(verification_requested_at=NOW + timedelta(minutes=1))
    transport = _FakeTransport(
        _success_data("verification_challenge"),
        {"code": "000000", "data": None},
    )

    result = await _authenticate(transport, state=state)

    assert type(result) is RussiaVerificationRequired
    assert result.code_requested
    assert result.state.verification_requested_at == NOW
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_verification_login_submits_code_once_without_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(
        _success_data("login"),
        _success_data("get_user_info"),
    )

    result = await _authenticate(
        transport,
        verification_code=f"  {CODE}  ",
    )

    assert type(result) is RussiaAuthenticated
    assert [request.operation for request in transport.requests] == [
        "verify_code",
        "get_user_info",
    ]
    submitted = json.loads(transport.requests[0].body)
    assert submitted["smsCode"] == CODE
    assert "password" not in submitted


@pytest.mark.asyncio
async def test_submitted_code_110641_propagates_without_inventing_rejection_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(_success_data("verification_challenge"))

    with pytest.raises(GwmApiError) as raised:
        await _authenticate(transport, verification_code=CODE)

    assert type(raised.value) is GwmApiError
    assert raised.value.api_code == "110641"
    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_verification_http_auth_status_is_definite_code_rejection(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(_response({}, status=status))

    result = await _authenticate(transport, verification_code=CODE)

    assert type(result) is RussiaVerificationRequired
    assert not result.code_requested
    assert result.code_rejected
    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_password_login_http_auth_status_never_requests_verification(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(_response({}, status=status))

    with pytest.raises(GwmAuthenticationError):
        await _authenticate(transport)

    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["110642", " 110641 "])
async def test_unknown_or_mutated_codes_do_not_trigger_hidden_side_effects(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(
        {
            "code": code,
            "description": SENSITIVE,
            "data": {"raw": SENSITIVE},
        }
    )

    with pytest.raises(GwmApiError) as raised:
        await _authenticate(transport)

    assert len(transport.requests) == 1
    assert type(raised.value) is GwmApiError
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_rate_limit_never_becomes_verification_or_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(
        _response(
            _success_data("verification_challenge"),
            status=429,
            headers={"Retry-After": "12"},
        )
    )

    with pytest.raises(GwmRateLimitError) as raised:
        await _authenticate(transport)

    assert raised.value.retry_after_seconds == 12
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_unknown_access_error_does_not_refresh_login_or_retire_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    progress = _RussiaAuthProgress()
    transport = _FakeTransport({"code": "607501", "data": None})

    with pytest.raises(GwmApiError) as raised:
        await _authenticate(transport, state=state, progress=progress)

    assert raised.value.api_code == "607501"
    assert not progress.existing_session_rejected
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_bootstrap_preflight_failure_performs_zero_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _FakeTransport(_success_data("login"))

    def fail(*_args: object, **_kwargs: object) -> ssl.SSLContext:
        raise ValueError(SENSITIVE)

    monkeypatch.setattr(auth_module, "create_russia_bootstrap_ssl_context", fail)

    with pytest.raises(GwmConfigurationError) as raised:
        await _authenticate(transport)

    assert transport.requests == []
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_network_failure_is_single_attempt_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport(GwmNetworkError(operation="login"))

    with pytest.raises(GwmNetworkError) as raised:
        await _authenticate(transport)

    assert len(transport.requests) == 1
    assert raised.value.operation == "login"
    assert raised.value.__context__ is None


def test_decoder_is_http_first_strict_and_preserves_numeric_identifier_precision() -> None:
    with pytest.raises(GwmAuthenticationError):
        auth_module._decode_auth_envelope(
            _response({"code": "000000", "data": {}}, status=403),
            operation="get_user_info",
            require_data=True,
        )
    with pytest.raises(GwmSchemaError):
        auth_module._decode_auth_envelope(
            _TransportResponse(200, {}, b'{"code":"000000","code":"000000"}'),
            operation="login",
            require_data=True,
        )

    login = auth_module._decode_auth_envelope(
        _response(_success_data("login")),
        operation="login",
        require_data=True,
    )
    _access, _refresh, gw_id, bean_id = auth_module._parse_login(login)
    assert gw_id == "9007199254740993"
    assert bean_id == "9007199254740995"


def test_decoder_rejects_malformed_deep_nonfinite_and_missing_data() -> None:
    nested: object = "leaf"
    for _index in range(66):
        nested = [nested]
    responses = [
        _TransportResponse(200, {}, b"\xff"),
        _TransportResponse(
            200,
            {},
            b'{"code":"000000","data":{},"data":{}}',
        ),
        _TransportResponse(200, {}, b'{"code":"000000","data":NaN}'),
        _TransportResponse(
            200,
            {},
            json.dumps({"code": "000000", "data": nested}).encode(),
        ),
        _response({"code": "000000"}),
    ]

    for response in responses:
        with pytest.raises(GwmSchemaError):
            auth_module._decode_auth_envelope(
                response,
                operation="login",
                require_data=True,
            )

    for malformed in (
        {},
        {"accessToken": True, "refreshToken": "SYNTHETIC-REFRESH"},
        {"accessToken": 1, "refreshToken": "SYNTHETIC-REFRESH"},
        {"accessToken": "with space", "refreshToken": "SYNTHETIC-REFRESH"},
        {"accessToken": "SYNTHETIC-ACCESS", "refreshToken": 1},
        {"accessToken": "SYNTHETIC-ACCESS", "refreshToken": 1.5},
    ):
        with pytest.raises(GwmSchemaError):
            auth_module._parse_login(malformed)


def test_request_registry_signer_and_h5_tls_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = _credentials()
    context = ssl.create_default_context()
    forged_endpoint = auth_module._AuthEndpoint(
        "login",
        "userAuth/loginAccount",
        "POST",
        False,
        True,
    )
    with pytest.raises(GwmRoutePolicyError):
        auth_module._prepare_request(
            endpoint=forged_endpoint,
            credentials=credentials,
            body=auth_module._password_login_body(credentials),
            access_token=None,
            ssl_context=context,
        )

    expected = auth_module.sign_request(
        auth_module.get_region_protocol(Region.RUSSIA)
        .gateway(auth_module.GatewayRole.H5_V1)
        .signing_profile,
        "POST",
        "https://rus-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/loginAccount",
        auth_module.encode_dotnet_json(auth_module._password_login_body(credentials)),
    )
    monkeypatch.setattr(
        auth_module,
        "sign_request",
        lambda *_args, **_kwargs: replace(
            expected,
            url="https://evil.invalid/app-api/api/v1.0/userAuth/loginAccount",
        ),
    )
    with pytest.raises(GwmRoutePolicyError):
        auth_module._prepare_request(
            endpoint=auth_module._LOGIN,
            credentials=credentials,
            body=auth_module._password_login_body(credentials),
            access_token=None,
            ssl_context=context,
        )

    monkeypatch.undo()
    with pytest.raises(GwmRoutePolicyError):
        auth_module._prepare_request(
            endpoint=auth_module._LOGIN,
            credentials=credentials,
            body=auth_module._password_login_body(credentials),
            access_token=None,
            ssl_context=_legacy_context(),
        )


@pytest.mark.asyncio
async def test_invalid_verification_code_is_local_and_does_not_preflight_or_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def identity(*_args: object, **_kwargs: object) -> ssl.SSLContext:
        nonlocal called
        called = True
        return _legacy_context()

    monkeypatch.setattr(auth_module, "create_russia_bootstrap_ssl_context", identity)
    transport = _FakeTransport()

    with pytest.raises(GwmConfigurationError) as raised:
        await _authenticate(transport, verification_code="bad code")

    assert raised.value.operation == "verify_code"
    assert not called
    assert transport.requests == []


@pytest.mark.asyncio
async def test_authentication_rejects_foreign_region_before_identity_or_network() -> None:
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await authenticate_russia(
            config=GwmClientConfig(region=Region.ANZ),
            transport=transport,
            credentials=_credentials(),
            state=None,
            verification_code=None,
            bootstrap_material=_material(),
            deadline=_deadline(),
            progress=_RussiaAuthProgress(),
        )
    assert transport.requests == []


@pytest.mark.asyncio
async def test_mismatched_account_verification_continuation_retires_old_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    old_credentials = _credentials()
    old_state = _state(
        old_credentials,
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    new_credentials = _credentials(account="SYNTHETIC-new-owner@example.invalid")
    transport = _FakeTransport(
        _success_data("verification_challenge"),
        {"code": "000000", "data": None},
    )
    client = _client(transport, session=_session(old_state))

    result = await client.authenticate_russia(
        new_credentials,
        state=old_state,
        bootstrap_material=_material(),
    )

    assert type(result) is RussiaVerificationRequired
    assert result.code_requested
    assert not client.authenticated
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
    ]
    assert "accessToken" not in transport.requests[0].headers
    assert json.loads(transport.requests[0].body)["account"] == new_credentials.account


@pytest.mark.asyncio
async def test_client_authentication_and_all_three_russia_reads_share_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_context = _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _success_data("get_user_info"),
        _read_response("acquire_vehicles"),
        _read_response("get_last_status"),
        _read_response("get_vehicle_basics"),
    )
    client = _client(transport)

    authenticated = await client.authenticate_russia(
        _credentials(),
        state=state,
        bootstrap_material=_material(),
    )
    assert type(authenticated) is RussiaAuthenticated
    vehicles = await client.acquire_vehicles()
    assert len(vehicles) == 1
    vehicle = vehicles[0]
    assert vehicle.identifier.value == READ_FIXTURE["identifier"]
    assert vehicle.vehicle_id == "9007199254740993"
    assert vehicle.model_name == "Synthetic Russia model"

    status = await client.get_last_status(vehicle.identifier)
    assert status.device_id == "9007199254740995"
    assert status.acquisition_time_ms == 1_787_747_696_789
    assert status.update_time_ms == 1_787_747_697_890
    assert status.latitude == 1.25
    assert status.longitude == -2.5
    assert [item.code for item in status.items] == ["2013021", "NESTED"]
    assert status.items[0].unit == "1"

    basics = await client.get_vehicle_basics(vehicle.identifier)
    assert basics.climate is not None
    assert basics.climate.temperature == "22"
    assert basics.climate.operation_time == "7"
    assert basics.climate.engine_operation_time == "9"

    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "acquire_vehicles",
        "get_last_status",
        "get_vehicle_basics",
    ]
    for request in transport.requests[1:]:
        assert request.headers["accessToken"] == "SYNTHETIC-OLD-ACCESS"
        assert request.ssl_context is app_context
    rendered = repr((authenticated, vehicles, status, basics))
    assert "SYNTHETIC-owner@example.invalid" not in rendered
    assert "SYNTHETIC-LICENSE-NOT-RETAINED" not in rendered


@pytest.mark.asyncio
async def test_rejected_auth_attempt_cannot_erase_newer_session_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    old_context = _legacy_context()
    replacement_context = _legacy_context()
    replacement_token = "SYNTHETIC-CONCURRENT-ACCESS"
    transport = _FakeTransport(
        _response({}, status=401),
        GwmNetworkError(operation="refresh_token"),
        _read_response("acquire_vehicles"),
        delay=0.02,
    )
    client = _client(transport, session=_session(state, context=old_context))
    authenticating = asyncio.create_task(
        client.authenticate_russia(
            _credentials(),
            state=state,
            bootstrap_material=_material(),
        )
    )
    async with asyncio.timeout(1):
        while len(transport.requests) < 2:
            await asyncio.sleep(0)

    client.replace_session(
        _session(
            state,
            token=replacement_token,
            context=replacement_context,
        )
    )
    with pytest.raises(GwmNetworkError):
        await authenticating

    assert client.authenticated
    await client.acquire_vehicles()
    read = transport.requests[-1]
    assert read.headers["accessToken"] == replacement_token
    assert read.ssl_context is replacement_context


@pytest.mark.asyncio
async def test_client_serializes_concurrent_russia_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(
        _success_data("get_user_info"),
        _success_data("get_user_info"),
        delay=0.01,
    )
    client = _client(transport)

    first, second = await asyncio.gather(
        client.authenticate_russia(
            _credentials(),
            state=state,
            bootstrap_material=_material(),
        ),
        client.authenticate_russia(
            _credentials(),
            state=state,
            bootstrap_material=_material(),
        ),
    )

    assert type(first) is RussiaAuthenticated
    assert type(second) is RussiaAuthenticated
    assert transport.max_active == 1


@pytest.mark.asyncio
async def test_client_deadline_preserves_unrejected_matching_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(hang=True)
    client = _client(
        transport,
        session=_session(state),
        total_timeout=1,
    )

    with pytest.raises(GwmDeadlineExceededError):
        await client.authenticate_russia(
            _credentials(),
            state=state,
            bootstrap_material=_material(),
            timeout=0.01,
        )

    assert client.authenticated
    assert len(transport.requests) <= 1


@pytest.mark.asyncio
async def test_external_cancellation_propagates_and_preserves_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    state = _state(
        access_token="SYNTHETIC-OLD-ACCESS",
        refresh_token="SYNTHETIC-OLD-REFRESH",
    )
    transport = _FakeTransport(hang=True)
    client = _client(transport, session=_session(state))
    task = asyncio.create_task(
        client.authenticate_russia(
            _credentials(),
            state=state,
            bootstrap_material=_material(),
        )
    )
    async with asyncio.timeout(1):
        await transport.entered.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert client.authenticated


@pytest.mark.asyncio
async def test_client_close_is_idempotent_and_rejects_future_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_identity(monkeypatch)
    transport = _FakeTransport()
    client = _client(transport)

    await client.aclose()
    await client.aclose()

    assert client.closed
    assert transport.close_calls == 0
    with pytest.raises(GwmClosedError):
        await client.authenticate_russia(
            _credentials(),
            bootstrap_material=_material(),
        )
    assert transport.requests == []
