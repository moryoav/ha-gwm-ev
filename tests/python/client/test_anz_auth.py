"""Offline ANZ authentication, session-reclaim, and read-parity tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import pytest

import gwm_client.anz_auth as anz_auth
from gwm_client._dotnet_json import encode_dotnet_json
from gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse
from gwm_client.anz_auth import (
    AnzAuthenticated,
    AnzAuthenticationMethod,
    AnzAuthState,
    AnzCredentials,
    AnzSessionReclaimRequired,
    AnzVerificationRequired,
)
from gwm_client.client import GwmClient
from gwm_client.config import GwmClientConfig, RequestTimeouts
from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmSignatureError,
)
from gwm_client.models import GwmSession
from gwm_client.signing import SignedRequest, SigningProfile

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "anz_auth_contracts_v1.json"
CURRENT_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "anz_auth_contracts_v2.json"
READ_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "anz_read_responses_v1.json"
NOW = datetime(2026, 8, 25, 12, 34, 56, 789000, tzinfo=UTC)
ACCESS = "SYNTHETIC-OLD-ACCESS"
REFRESH = "SYNTHETIC-OLD-REFRESH"
NEW_ACCESS = "SYNTHETIC-NEW-ACCESS"
NEW_REFRESH = "SYNTHETIC-NEW-REFRESH"
SENSITIVE = "SENSITIVE-anz-auth-material-019fea1b"


class _QueueTransport:
    def __init__(
        self,
        responses: Sequence[_TransportResponse | BaseException] | None = None,
        *,
        delay: float = 0,
        hang: bool = False,
    ) -> None:
        self.responses = list(responses or [])
        self.requests: list[_TransportRequest] = []
        self.deadlines: list[_Deadline] = []
        self.delay = delay
        self.hang = hang
        self.entered = asyncio.Event()
        self.active = 0
        self.max_active = 0

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        del connect_timeout, read_timeout
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            if not self.responses:
                raise AssertionError("unexpected request")
            response = self.responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        return None


def _response(
    data: object = ...,
    *,
    code: str = "000000",
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    description: str | None = None,
) -> _TransportResponse:
    envelope: dict[str, object] = {"code": code}
    if description is not None:
        envelope["description"] = description
    if data is not ...:
        envelope["data"] = data
    return _TransportResponse(
        status=status,
        headers={} if headers is None else headers,
        body=json.dumps(envelope, separators=(",", ":")).encode(),
    )


def _credentials() -> AnzCredentials:
    return AnzCredentials(
        account=" SYNTHETIC-owner+tag@example.invalid ",
        password="SYNTHETIC-PASSWORD",
        country=" au ",
        device_id="01234567-89AB-CDEF-0123-456789ABCDEF",
    )


def _current_credentials(*, country: str = "AU") -> AnzCredentials:
    return AnzCredentials(
        account=" SYNTHETIC-owner+tag@example.invalid ",
        password="SYNTHETIC-PASSWORD",
        country=country,
        device_id="01234567-89AB-CDEF-0123-456789ABCDEF",
        authentication_method=AnzAuthenticationMethod.CURRENT,
    )


def _default_context() -> ssl.SSLContext:
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


def _state(
    *,
    access: str | None = ACCESS,
    refresh: str | None = REFRESH,
    reclaim: bool = False,
) -> AnzAuthState:
    credentials = _credentials()
    return AnzAuthState(
        account_binding=credentials.account_binding,
        country=credentials.country,
        device_id=credentials.device_id,
        access_token=access,
        refresh_token=refresh,
        session_reclaim_required=reclaim,
    )


def _client(
    transport: _QueueTransport,
    *,
    session: GwmSession | None = None,
    total_timeout: float = 5,
    authentication_method: AnzAuthenticationMethod = AnzAuthenticationMethod.LEGACY,
) -> GwmClient:
    return GwmClient(
        GwmClientConfig(
            "aus",
            timeouts=RequestTimeouts(total=total_timeout, connect=1, read=1),
            anz_authentication_method=authentication_method.value,
        ),
        session,
        transport=transport,
    )


def _current_client(
    transport: _QueueTransport,
    *,
    session: GwmSession | None = None,
    total_timeout: float = 5,
) -> GwmClient:
    return _client(
        transport,
        session=session,
        total_timeout=total_timeout,
        authentication_method=AnzAuthenticationMethod.CURRENT,
    )


@pytest.fixture(autouse=True)
def _fixed_offline_clock_and_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(anz_auth, "_utc_now", lambda: NOW)
    monkeypatch.setattr(anz_auth, "_create_default_ssl_context", _default_context)


def test_credentials_state_and_outcomes_hide_all_sensitive_values() -> None:
    credentials = _credentials()
    assert credentials.account == "SYNTHETIC-owner+tag@example.invalid"
    assert credentials.password == "SYNTHETIC-PASSWORD"
    assert credentials.country == "AU"
    assert credentials.device_id == "0123456789abcdef0123456789abcdef"
    assert credentials.authentication_method is AnzAuthenticationMethod.LEGACY
    state = AnzAuthState.for_credentials(credentials)
    outcomes = (
        AnzVerificationRequired(state=state, code_requested=True),
        AnzSessionReclaimRequired(state=replace(state, session_reclaim_required=True)),
    )

    rendered = repr((credentials, state, outcomes))
    for secret in (
        credentials.account,
        credentials.password,
        credentials.device_id,
        credentials.account_binding,
    ):
        assert secret not in rendered


@pytest.mark.parametrize("method", ["", "current", "v2", "unknown", 7, None])
def test_credentials_reject_unknown_authentication_method(method: object) -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        AnzCredentials(
            "synthetic@example.invalid",
            "SYNTHETIC-PASSWORD",
            "AU",
            "0123",
            authentication_method=method,  # type: ignore[arg-type]
        )


def test_current_credentials_match_app_account_space_normalization() -> None:
    credentials = AnzCredentials(
        " synthetic + owner@example.invalid ",
        "SYNTHETIC-PASSWORD",
        "AU",
        "0123456789abcdef0123456789abcdef",
        authentication_method=AnzAuthenticationMethod.CURRENT,
    )

    assert credentials.account == "synthetic+owner@example.invalid"


def test_current_credentials_match_app_password_input_formatters() -> None:
    credentials = AnzCredentials(
        "synthetic@example.invalid",
        " S!YN-T_HETIC.password " + ("x" * 50),
        "AU",
        "0123456789abcdef0123456789abcdef",
        authentication_method=AnzAuthenticationMethod.CURRENT,
    )

    assert credentials.password == ("SYNTHETICpassword" + ("x" * 50))[:40]


def test_current_credentials_reject_password_removed_entirely_by_app_formatter() -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        AnzCredentials(
            "synthetic@example.invalid",
            " !-_ ",
            "AU",
            "0123456789abcdef0123456789abcdef",
            authentication_method=AnzAuthenticationMethod.CURRENT,
        )


def test_current_account_type_supports_email_and_phone_identifiers() -> None:
    assert anz_auth._current_account_type("synthetic@example.invalid") == "2"
    assert anz_auth._current_account_type("0412345678") == "1"


@pytest.mark.parametrize("country", ["", "GB", "ZZ", "A", "AUS"])
def test_credentials_reject_unknown_anz_registration_country(country: str) -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        AnzCredentials(
            "synthetic@example.invalid",
            "SYNTHETIC-PASSWORD",
            country,
            "0123",
        )


@pytest.mark.parametrize("country", ["AU", "NZ"])
def test_state_is_bound_to_exact_account_country_and_stable_device(country: str) -> None:
    credentials = AnzCredentials(
        "synthetic@example.invalid",
        "SYNTHETIC-PASSWORD",
        country,
        "0123456789abcdef0123456789abcdef",
    )
    state = AnzAuthState.for_credentials(credentials)
    assert state.matches(credentials)
    assert not state.matches(
        AnzCredentials(
            "different@example.invalid",
            credentials.password,
            country,
            credentials.device_id,
        )
    )
    assert not state.matches(
        AnzCredentials(
            credentials.account,
            credentials.password,
            country,
            credentials.device_id,
            authentication_method=AnzAuthenticationMethod.CURRENT,
        )
    )
    other_country = "NZ" if country == "AU" else "AU"
    assert not state.matches(
        AnzCredentials(
            credentials.account,
            credentials.password,
            other_country,
            credentials.device_id,
        )
    )


def test_all_anz_auth_requests_match_versioned_closed_wire_contract() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 1
    credentials = _credentials()
    context = _default_context()
    state = _state()
    cases = {
        "login": (
            anz_auth._LOGIN,
            anz_auth._login_body(credentials, verification_code=None),
            None,
        ),
        "verified_login": (
            anz_auth._LOGIN,
            anz_auth._login_body(credentials, verification_code="SYNTHETIC-246810"),
            None,
        ),
        "request_verification": (
            anz_auth._REQUEST_VERIFICATION,
            anz_auth._verification_request_body(credentials),
            None,
        ),
        "verify_code": (
            anz_auth._VERIFY_CODE,
            anz_auth._verification_check_body(credentials, "SYNTHETIC-246810"),
            None,
        ),
        "refresh": (
            anz_auth._REFRESH,
            anz_auth._refresh_body(credentials, state),
            ACCESS,
        ),
        "get_user_info": (anz_auth._USER_INFO, None, ACCESS),
    }

    for name, (endpoint, body, token) in cases.items():
        expected = fixture["operations"][name]
        request = anz_auth._prepare_request(
            endpoint=endpoint,
            credentials=credentials,
            body=body,
            access_token=token,
            ssl_context=context,
        )
        parsed = urlsplit(request.url)
        assert request.method == expected["method"]
        assert parsed.hostname == expected["host"]
        assert parsed.path == expected["path"]
        assert parsed.query == ""
        assert ("accessToken" in request.headers) is expected["access_token_header"]
        assert request.headers["deviceId"] == request.headers["iccid"]
        assert request.headers["deviceId"] == fixture["credentials"]["api_device_id"]
        assert request.headers["country"] == request.headers["regionCode"] == "AU"
        assert request.ssl_context is context
        signing_headers = {key for key in request.headers if key.startswith(expected["signing_prefix"])}
        assert len(signing_headers) == 4
        assert len(request.headers["bt-auth-nonce"]) == 16
        if expected["body"] is None:
            assert request.body is None
            assert "Content-Type" not in request.headers
        else:
            assert request.body == expected["body"].encode()
            assert request.headers["Content-Type"] == "application/json; charset=utf-8"
            assert expected["body"] not in repr(request)
        assert "Accept" not in request.headers


def test_current_anz_auth_requests_match_versioned_beta_wire_contract() -> None:
    fixture = json.loads(CURRENT_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 2
    credentials = _current_credentials()
    assert credentials.authentication_method.value == fixture["credentials"]["authentication_method"]
    context = _default_context()
    endpoints = anz_auth._auth_endpoints(credentials)
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id="SYNTHETIC-GW-ID",
    )
    cases = {
        "login": (
            endpoints["login"],
            anz_auth._login_body(credentials, verification_code=None),
            None,
            None,
        ),
        "verified_login": (
            endpoints["login"],
            anz_auth._login_body(credentials, verification_code="SYNTHETIC-246810"),
            None,
            None,
        ),
        "request_verification": (
            endpoints["request_verification"],
            anz_auth._verification_request_body(credentials),
            None,
            None,
        ),
        "verify_code": (
            endpoints["verify_code"],
            anz_auth._verification_check_body(credentials, "SYNTHETIC-246810"),
            None,
            None,
        ),
        "refresh": (
            endpoints["refresh_token"],
            anz_auth._refresh_body(credentials, state),
            ACCESS,
            "SYNTHETIC-GW-ID",
        ),
    }

    for name, (endpoint, body, token, gw_id) in cases.items():
        expected = fixture["operations"][name]
        request = anz_auth._prepare_request(
            endpoint=endpoint,
            credentials=credentials,
            body=body,
            access_token=token,
            ssl_context=context,
            gw_id=gw_id,
        )
        parsed = urlsplit(request.url)
        assert request.method == expected["method"]
        assert parsed.hostname == expected["host"]
        assert parsed.path == expected["path"]
        assert parsed.query == ""
        assert ("accessToken" in request.headers) is expected["access_token_header"]
        assert ("gwId" in request.headers) is expected["access_token_header"]
        assert request.headers["deviceId"] == fixture["credentials"]["api_device_id"]
        for header, value in fixture["required_headers"].items():
            assert request.headers[header] == value
        signing_headers = {key for key in request.headers if key.startswith(expected["signing_prefix"])}
        assert len(signing_headers) == 4
        assert len(request.headers["bt-auth-nonce"]) == expected.get(
            "nonce_length",
            fixture["credentials"]["nonce_length"],
        )
        assert request.body == (None if expected["body"] is None else expected["body"].encode())
        if expected["body"] is None:
            assert "Content-Type" not in request.headers
        else:
            assert request.headers["Content-Type"] == expected.get(
                "content_type",
                "application/json",
            )


def test_current_app_json_keeps_dart_compatible_text_while_legacy_encoder_is_unchanged() -> None:
    value = {"account": "owner+tag@example.invalid", "label": "Māori"}

    assert anz_auth._encode_current_app_json(value) == ('{"account":"owner+tag@example.invalid","label":"Māori"}')
    assert encode_dotnet_json(value) == ('{"account":"owner\\u002Btag@example.invalid","label":"M\\u0101ori"}')


def test_current_app_nonce_matches_sha256_epoch_millisecond_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamp = "1788148800123"
    monkeypatch.setattr(anz_auth.time, "time_ns", lambda: int(timestamp) * 1_000_000)

    assert anz_auth._new_current_app_nonce() == hashlib.sha256(timestamp.encode()).hexdigest()[:32]


@pytest.mark.parametrize(
    "code",
    ["-101", "550004", "551004", "551006", "607124"],
)
def test_current_app_session_expiry_codes_are_supported(code: str) -> None:
    assert anz_auth.is_current_anz_session_expired(GwmApiError(operation="acquire_vehicles", api_code=code))
    assert not anz_auth.is_current_anz_session_expired(
        GwmAuthenticationError(operation="acquire_vehicles", api_code=code)
    )


@pytest.mark.parametrize("code", ["551011", "607501", "900001"])
def test_non_session_expiry_codes_do_not_trigger_current_refresh(code: str) -> None:
    assert not anz_auth.is_current_anz_session_expired(GwmApiError(operation="acquire_vehicles", api_code=code))


def test_current_app_signer_uses_live_gateway_path_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    real_sign = anz_auth.sign_request

    def capture_sign(
        profile: SigningProfile,
        method: str,
        url: str,
        body: str | None,
        **kwargs: object,
    ) -> SignedRequest:
        captured.update(kwargs)
        return real_sign(profile, method, url, body, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(anz_auth, "sign_request", capture_sign)
    anz_auth._sign_current_app_request(
        anz_auth.get_region_protocol(anz_auth.Region.ANZ).gateway(anz_auth.GatewayRole.AUTH_V2).signing_profile,
        "POST",
        "https://aus-h5-gateway.gwmcloud.com/app-api/api/v2.0/userAuth/loginWithPassword",
        '{"account":"owner@example.invalid"}',
    )

    assert captured["request_target_policy"] == "path"
    assert captured["query_policy"] == "dart-current"
    assert captured["uri_component_safe"] == "-._~!*'()"


@pytest.mark.parametrize(
    "endpoint",
    [anz_auth._LOGIN, anz_auth._REFRESH, anz_auth._USER_INFO],
)
def test_current_auth_cannot_use_a_legacy_endpoint(endpoint: object) -> None:
    credentials = _current_credentials()
    with pytest.raises(GwmRoutePolicyError):
        anz_auth._prepare_request(
            endpoint=endpoint,  # type: ignore[arg-type]
            credentials=credentials,
            body=None,
            access_token=None,
            ssl_context=_default_context(),
        )


@pytest.mark.parametrize("mutation", ["host", "path", "query", "method", "body", "headers"])
def test_auth_request_registry_rejects_every_post_signing_route_mutation(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    real_sign = cast(
        Callable[[SigningProfile, str, str, str | None], SignedRequest],
        anz_auth.__dict__["sign_request"],
    )

    def tampered_sign(
        profile: SigningProfile,
        method: str,
        url: str,
        body: str | None,
    ) -> SignedRequest:
        signed = real_sign(profile, method, url, body)
        if mutation == "host":
            return replace(signed, url=signed.url.replace("aus-h5-gateway", "evil-gateway"))
        if mutation == "path":
            return replace(signed, url=signed.url.replace("loginAccount", "refreshToken"))
        if mutation == "query":
            return replace(signed, url=signed.url + "?escape=1")
        if mutation == "method":
            return replace(signed, method="GET")
        if mutation == "body":
            return replace(signed, body="{}")
        headers = dict(signed.headers)
        headers.pop("bt-auth-sign")
        return replace(signed, headers=headers)

    monkeypatch.setattr(anz_auth, "sign_request", tampered_sign)
    with pytest.raises(GwmRoutePolicyError) as raised:
        anz_auth._prepare_request(
            endpoint=anz_auth._LOGIN,
            credentials=_credentials(),
            body=anz_auth._login_body(_credentials(), verification_code=None),
            access_token=None,
            ssl_context=_default_context(),
        )
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("data", [..., None])
def test_verification_success_envelopes_do_not_require_data(data: object) -> None:
    assert (
        anz_auth._decode_auth_envelope(
            _response(data),
            operation="verify_code",
            require_data=False,
        )
        is None
    )


def test_auth_envelope_is_strict_secret_safe_and_http_first() -> None:
    duplicate = _TransportResponse(200, {}, b'{"code":"000000","code":"000000"}')
    with pytest.raises(GwmSchemaError):
        anz_auth._decode_auth_envelope(
            duplicate,
            operation="login",
            require_data=True,
        )
    with pytest.raises(GwmRateLimitError) as rate_limited:
        anz_auth._decode_auth_envelope(
            _response(code="999999", status=429, headers={"Retry-After": "12"}),
            operation="login",
            require_data=True,
        )
    assert rate_limited.value.retry_after_seconds == 12
    with pytest.raises(GwmHttpError) as http_failure:
        anz_auth._decode_auth_envelope(
            _response(code="309702", status=500, description=SENSITIVE),
            operation="login",
            require_data=True,
        )
    assert http_failure.value.status == 500
    assert SENSITIVE not in repr(http_failure.value)


def test_auth_signature_rejection_has_a_safe_specific_category() -> None:
    with pytest.raises(GwmSignatureError) as rejected:
        anz_auth._decode_auth_envelope(
            _response(code="607099", description=SENSITIVE),
            operation="login",
            require_data=True,
        )

    assert rejected.value.category == "signature_error"
    assert rejected.value.api_code == "607099"
    assert SENSITIVE not in repr(rejected.value)


@pytest.mark.asyncio
async def test_auth_deadline_is_rechecked_after_synchronous_envelope_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def delayed_challenge(*_args: object, **_kwargs: object) -> object:
        time.sleep(0.02)
        raise GwmApiError(operation="login", api_code="309702")

    monkeypatch.setattr(anz_auth, "_decode_auth_envelope", delayed_challenge)
    transport = _QueueTransport([_response({})])
    loop = asyncio.get_running_loop()
    with pytest.raises(GwmDeadlineExceededError):
        await anz_auth._request_data(
            config=GwmClientConfig("aus"),
            transport=transport,
            endpoint=anz_auth._LOGIN,
            credentials=_credentials(),
            body=anz_auth._login_body(_credentials(), verification_code=None),
            access_token=None,
            ssl_context=_default_context(),
            deadline=_Deadline(loop.time() + 0.005),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("challenge", ["309702", "110641"])
async def test_initial_challenge_requests_one_code_and_returns_continuation(
    challenge: str,
) -> None:
    transport = _QueueTransport([_response(code=challenge, description=SENSITIVE), _response()])
    client = _client(transport)
    result = await client.authenticate_anz(
        _credentials(),
        allow_session_reclaim=True,
    )

    assert type(result) is AnzVerificationRequired
    assert result.code_requested
    assert not result.code_rejected
    assert result.state.verification_requested_at == NOW
    assert result.state.session_reclaim_required
    assert not client.authenticated
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
    ]
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("challenge", ["309702", "308103", "110641"])
async def test_current_auth_challenge_uses_v2_verification_routes(
    challenge: str,
) -> None:
    credentials = _current_credentials()
    transport = _QueueTransport([_response(code=challenge, description=SENSITIVE), _response()])
    result = await _current_client(transport).authenticate_anz(
        credentials,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzVerificationRequired
    assert result.code_requested
    assert [urlsplit(request.url).path for request in transport.requests] == [
        "/app-api/api/v2.0/userAuth/loginWithPassword",
        "/app-api/api/v2.0/userAuth/getVerifyCode",
    ]


@pytest.mark.asyncio
async def test_current_auth_success_publishes_session_from_login_response() -> None:
    credentials = _current_credentials()
    transport = _QueueTransport(
        [
            _response(
                {
                    "accessToken": NEW_ACCESS,
                    "refreshToken": NEW_REFRESH,
                    "gwId": "SYNTHETIC-GW-ID",
                }
            )
        ]
    )
    client = _current_client(transport)

    result = await client.authenticate_anz(
        credentials,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.state.gw_id == "SYNTHETIC-GW-ID"
    assert result.session.gw_id == "SYNTHETIC-GW-ID"
    assert client.authenticated
    assert [urlsplit(request.url).path for request in transport.requests] == [
        "/app-api/api/v2.0/userAuth/loginWithPassword",
    ]


@pytest.mark.asyncio
async def test_current_auth_does_not_require_an_unevidenced_refresh_token() -> None:
    credentials = _current_credentials()
    transport = _QueueTransport([_response({"accessToken": NEW_ACCESS, "gwId": "SYNTHETIC-GW-ID"})])

    result = await _current_client(transport).authenticate_anz(
        credentials,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token is None
    assert result.state.gw_id == "SYNTHETIC-GW-ID"
    assert [request.operation for request in transport.requests] == ["login"]


@pytest.mark.asyncio
async def test_current_auth_credential_rejection_never_falls_back_to_legacy() -> None:
    credentials = _current_credentials()
    transport = _QueueTransport([_response(code="308001", description=SENSITIVE)])

    with pytest.raises(GwmAuthenticationError) as raised:
        await _current_client(transport).authenticate_anz(
            credentials,
            allow_session_reclaim=True,
        )

    assert raised.value.api_code == "308001"
    assert len(transport.requests) == 1
    assert urlsplit(transport.requests[0].url).path == ("/app-api/api/v2.0/userAuth/loginWithPassword")


@pytest.mark.asyncio
async def test_current_session_without_gw_id_requires_fresh_login() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
    )
    transport = _QueueTransport()

    result = await _current_client(transport).authenticate_anz(
        credentials,
        state=state,
    )

    assert type(result) is AnzSessionReclaimRequired
    assert result.state.access_token is None
    assert result.state.refresh_token is None
    assert result.state.gw_id is None
    assert transport.requests == []


@pytest.mark.asyncio
async def test_restored_current_session_skips_legacy_profile_validation() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id="SYNTHETIC-GW-ID",
    )
    transport = _QueueTransport()

    result = await _current_client(transport).authenticate_anz(
        credentials,
        state=state,
    )

    assert type(result) is AnzAuthenticated
    assert result.state == state
    assert result.session.gw_id == "SYNTHETIC-GW-ID"
    assert transport.requests == []


@pytest.mark.asyncio
async def test_current_session_refresh_uses_native_v1_contract_and_rotates() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id="SYNTHETIC-GW-ID",
    )
    context = _default_context()
    transport = _QueueTransport([_response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH})])
    client = _current_client(
        transport,
        session=GwmSession(
            "AU",
            credentials.device_id,
            ACCESS,
            context,
            gw_id="SYNTHETIC-GW-ID",
        ),
    )

    result = await client.refresh_current_anz_session(credentials, state)

    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.state.gw_id == "SYNTHETIC-GW-ID"
    assert result.session.app_ssl_context is context
    assert client._session == result.session
    request = transport.requests[0]
    assert request.operation == "refresh_token"
    assert urlsplit(request.url).path == "/app-api/api/v1.0/userAuth/refreshToken"
    assert request.body == (
        b'{"accessToken":"SYNTHETIC-OLD-ACCESS","refreshToken":"SYNTHETIC-OLD-REFRESH",'
        b'"deviceId":"0123456789abcdef0123456789abcdef"}'
    )
    assert b'"deviceId":"0123456789abcdef0123456789abcdef"' in (request.body or b"")
    assert request.headers["accessToken"] == ACCESS
    assert request.headers["gwId"] == "SYNTHETIC-GW-ID"
    assert len(request.headers["bt-auth-nonce"]) == 16
    assert request.headers["Content-Type"] == "application/json; charset=utf-8"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code",
    ["-101", "550004", "551004", "551006", "551011", "607124"],
)
async def test_current_refresh_rejection_retires_session(code: str) -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id="SYNTHETIC-GW-ID",
    )
    client = _current_client(
        _QueueTransport([_response(code=code, description=SENSITIVE)]),
        session=GwmSession(
            "AU",
            credentials.device_id,
            ACCESS,
            _default_context(),
            gw_id="SYNTHETIC-GW-ID",
        ),
    )

    with pytest.raises(GwmAuthenticationError) as raised:
        await client.refresh_current_anz_session(credentials, state)

    assert raised.value.api_code == code
    assert not client.authenticated
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_current_session_without_refresh_token_requires_reauthentication() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        gw_id="SYNTHETIC-GW-ID",
    )
    transport = _QueueTransport()
    client = _current_client(
        transport,
        session=GwmSession(
            "AU",
            credentials.device_id,
            ACCESS,
            _default_context(),
            gw_id="SYNTHETIC-GW-ID",
        ),
    )

    with pytest.raises(GwmAuthenticationError):
        await client.refresh_current_anz_session(credentials, state)

    assert not client.authenticated
    assert transport.requests == []


@pytest.mark.asyncio
async def test_unknown_current_refresh_failure_preserves_existing_session() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id="SYNTHETIC-GW-ID",
    )
    client = _current_client(
        _QueueTransport([_response(code="900001", description=SENSITIVE)]),
        session=GwmSession(
            "AU",
            credentials.device_id,
            ACCESS,
            _default_context(),
            gw_id="SYNTHETIC-GW-ID",
        ),
    )

    with pytest.raises(GwmApiError) as raised:
        await client.refresh_current_anz_session(credentials, state)

    assert raised.value.api_code == "900001"
    assert client.authenticated
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_every_fresh_login_requires_explicit_single_session_consent() -> None:
    transport = _QueueTransport()
    client = _client(transport)

    result = await client.authenticate_anz(_credentials())

    assert type(result) is AnzSessionReclaimRequired
    assert result.state.session_reclaim_required
    assert result.state.access_token is None
    assert result.state.refresh_token is None
    assert transport.requests == []
    assert not client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("age", "request_expected"),
    [
        (timedelta(minutes=9, seconds=59), False),
        (timedelta(minutes=10), True),
        (timedelta(minutes=-1), True),
    ],
)
async def test_verification_request_throttle_boundaries(
    age: timedelta,
    request_expected: bool,
) -> None:
    initial = AnzAuthState.for_credentials(_credentials())
    state = replace(initial, verification_requested_at=NOW - age)
    responses = [_response(code="309702")]
    if request_expected:
        responses.append(_response())
    transport = _QueueTransport(responses)

    result = await _client(transport).authenticate_anz(
        _credentials(),
        state=state,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzVerificationRequired
    assert result.code_requested is request_expected
    assert len(transport.requests) == 1 + int(request_expected)


@pytest.mark.asyncio
async def test_failed_verification_request_does_not_publish_throttle_timestamp() -> None:
    state = AnzAuthState.for_credentials(_credentials())
    transport = _QueueTransport(
        [
            _response(code="309702"),
            _response(code="900001", description=SENSITIVE),
            _response(code="309702"),
            _response(),
        ]
    )
    client = _client(transport)

    with pytest.raises(GwmApiError) as raised:
        await client.authenticate_anz(
            _credentials(),
            state=state,
            allow_session_reclaim=True,
        )
    assert raised.value.operation == "request_verification"
    assert state.verification_requested_at is None

    result = await client.authenticate_anz(
        _credentials(),
        state=state,
        allow_session_reclaim=True,
    )
    assert type(result) is AnzVerificationRequired
    assert result.code_requested
    assert result.state.verification_requested_at == NOW


@pytest.mark.asyncio
async def test_verification_continuation_checks_then_logs_in() -> None:
    state = replace(
        AnzAuthState.for_credentials(_credentials()),
        verification_requested_at=NOW - timedelta(minutes=1),
    )
    transport = _QueueTransport(
        [
            _response(),
            _response(
                {
                    "accessToken": NEW_ACCESS,
                    "refreshToken": NEW_REFRESH,
                    "gwId": SENSITIVE,
                    "email": SENSITIVE,
                }
            ),
            _response({"email": SENSITIVE}),
        ]
    )
    client = _client(transport)
    result = await client.authenticate_anz(
        _credentials(),
        state=state,
        verification_code=" 246810 ",
        allow_session_reclaim=True,
    )

    assert type(result) is AnzAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.state.verification_requested_at is None
    assert not result.state.session_reclaim_required
    assert client.authenticated
    assert [request.operation for request in transport.requests] == [
        "verify_code",
        "login",
        "get_user_info",
    ]
    assert b'"verifyCode":"246810"' in (transport.requests[1].body or b"")
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_current_verification_continuation_stays_on_v2_auth_routes() -> None:
    credentials = _current_credentials(country="NZ")
    state = replace(
        AnzAuthState.for_credentials(credentials),
        verification_requested_at=NOW - timedelta(minutes=1),
        session_reclaim_required=True,
    )
    transport = _QueueTransport(
        [
            _response(),
            _response(
                {
                    "accessToken": NEW_ACCESS,
                    "refreshToken": NEW_REFRESH,
                    "gwId": "SYNTHETIC-GW-ID",
                }
            ),
        ]
    )

    result = await _current_client(transport).authenticate_anz(
        credentials,
        state=state,
        verification_code="246810",
        allow_session_reclaim=True,
    )

    assert type(result) is AnzAuthenticated
    assert [urlsplit(request.url).path for request in transport.requests] == [
        "/app-api/api/v2.0/userAuth/checkVerifyCode",
        "/app-api/api/v2.0/userAuth/loginWithPassword",
    ]
    assert b'"countryCode":"+64"' in (transport.requests[0].body or b"")


@pytest.mark.asyncio
@pytest.mark.parametrize("rejected_at", ["check", "login"])
async def test_only_308011_rejects_code_and_unknown_failures_propagate(
    rejected_at: str,
) -> None:
    state = replace(
        AnzAuthState.for_credentials(_credentials()),
        verification_requested_at=NOW - timedelta(minutes=1),
    )
    rejected_responses = [_response(code="308011", description=SENSITIVE)]
    if rejected_at == "login":
        rejected_responses.insert(0, _response())
    rejected_transport = _QueueTransport(rejected_responses)
    rejected = await _client(rejected_transport).authenticate_anz(
        _credentials(),
        state=state,
        verification_code="246810",
        allow_session_reclaim=True,
    )
    assert type(rejected) is AnzVerificationRequired
    assert rejected.code_rejected
    assert rejected.state.verification_requested_at is None
    assert len(rejected_transport.requests) == (1 if rejected_at == "check" else 2)

    unknown_transport = _QueueTransport([_response(code="123456", description=SENSITIVE)])
    with pytest.raises(GwmApiError) as raised:
        await _client(unknown_transport).authenticate_anz(
            _credentials(),
            state=state,
            verification_code="246810",
            allow_session_reclaim=True,
        )
    assert raised.value.operation == "verify_code"
    assert len(unknown_transport.requests) == 1
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("rejected_at", ["check", "login"])
@pytest.mark.parametrize("rejection_code", ["308011", "308012"])
async def test_current_wrong_or_expired_code_returns_verification_form(
    rejected_at: str,
    rejection_code: str,
) -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        verification_requested_at=NOW - timedelta(minutes=1),
        session_reclaim_required=True,
    )
    responses = [_response(code=rejection_code, description=SENSITIVE)]
    if rejected_at == "login":
        responses.insert(0, _response())

    result = await _current_client(_QueueTransport(responses)).authenticate_anz(
        credentials,
        state=state,
        verification_code="246810",
        allow_session_reclaim=True,
    )

    assert type(result) is AnzVerificationRequired
    assert result.code_rejected
    assert result.state.verification_requested_at is None


@pytest.mark.asyncio
async def test_current_too_many_verification_failures_does_not_invite_retry() -> None:
    credentials = _current_credentials()
    state = replace(
        AnzAuthState.for_credentials(credentials),
        verification_requested_at=NOW - timedelta(minutes=1),
        session_reclaim_required=True,
    )

    with pytest.raises(GwmApiError) as raised:
        await _current_client(_QueueTransport([_response(code="318013")])).authenticate_anz(
            credentials,
            state=state,
            verification_code="246810",
            allow_session_reclaim=True,
        )

    assert raised.value.api_code == "318013"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "code"),
    [
        ("login", " 309702 "),
        ("profile", " 607501 "),
        ("verify_code", " 308011 "),
    ],
)
async def test_auth_side_effect_codes_require_an_exact_raw_string(
    stage: str,
    code: str,
) -> None:
    transport = _QueueTransport([_response(code=code, description=SENSITIVE)])
    if stage == "profile":
        state = _state()
        client = _client(
            transport,
            session=GwmSession("AU", state.device_id, ACCESS, _default_context()),
        )
        kwargs: dict[str, object] = {"state": state}
    else:
        state = _state(access=None, refresh=None, reclaim=True)
        client = _client(transport)
        kwargs = {
            "state": state,
            "allow_session_reclaim": True,
        }
        if stage == "verify_code":
            kwargs["verification_code"] = "246810"

    with pytest.raises(GwmApiError) as raised:
        await client.authenticate_anz(_credentials(), **kwargs)  # type: ignore[arg-type]
    assert type(raised.value) is GwmApiError
    assert raised.value.api_code is None
    assert len(transport.requests) == 1
    assert client.authenticated is (stage == "profile")


@pytest.mark.asyncio
async def test_valid_access_token_discards_profile_pii_and_uses_default_tls() -> None:
    state = _state()
    transport = _QueueTransport([_response({"gwId": SENSITIVE, "beanId": SENSITIVE, "email": SENSITIVE})])
    result = await _client(transport).authenticate_anz(_credentials(), state=state)

    assert type(result) is AnzAuthenticated
    assert result.state == state
    assert result.state.gw_id is None
    assert SENSITIVE not in repr(result.state)
    assert not hasattr(result.state, "email")
    assert [request.operation for request in transport.requests] == ["get_user_info"]
    assert result.session.app_ssl_context.security_level > 0
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_authenticated_anz_session_reads_all_versioned_response_fixtures() -> None:
    fixture = json.loads(READ_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 1
    transport = _QueueTransport(
        [
            _response({"email": SENSITIVE}),
            _response(fixture["responses"]["acquire_vehicles"]),
            _response(fixture["responses"]["get_last_status"]),
            _response(fixture["responses"]["get_vehicle_basics"]),
        ]
    )
    client = _client(transport)
    authenticated = await client.authenticate_anz(_credentials(), state=_state())
    assert type(authenticated) is AnzAuthenticated

    vehicles = await client.acquire_vehicles()
    assert len(vehicles) == 1
    vehicle = vehicles[0]
    assert vehicle.identifier.value == fixture["identifier"]
    assert vehicle.default_vehicle
    assert vehicle.model_name == "Synthetic ANZ model"
    assert not hasattr(vehicle, "email")
    assert not hasattr(vehicle, "license_number")

    status = await client.get_last_status(vehicle.identifier)
    assert status.device_id == "SYNTHETIC-TELEMATICS-ID"
    assert status.acquisition_time_ms == 1_787_661_296_789
    assert status.update_time_ms == 1_787_661_297_890
    assert status.latitude == -33.8688
    assert status.longitude == 151.2093
    assert [item.code for item in status.items] == ["SOC", "NESTED"]

    basics = await client.get_vehicle_basics(vehicle.identifier)
    assert basics.climate is not None
    assert basics.climate.temperature == "21.5"
    assert basics.climate.operation_time == "7"
    assert basics.climate.engine_operation_time == "9"

    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "acquire_vehicles",
        "get_last_status",
        "get_vehicle_basics",
    ]
    for request in transport.requests[1:]:
        assert request.headers["accessToken"] == ACCESS
        assert request.ssl_context is authenticated.session.app_ssl_context
    rendered = repr((authenticated, vehicles, status, basics))
    assert "SYNTHETIC-owner@example.invalid" not in rendered
    assert "SYNTHETIC-LICENSE-NOT-RETAINED" not in rendered


@pytest.mark.asyncio
async def test_rejected_access_refreshes_with_old_access_header_and_rotates_atomically() -> None:
    state = _state()
    transport = _QueueTransport(
        [
            _response(status=401),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"email": SENSITIVE}),
        ]
    )
    result = await _client(transport).authenticate_anz(_credentials(), state=state)

    assert type(result) is AnzAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]
    refresh_request = transport.requests[1]
    assert refresh_request.headers["accessToken"] == ACCESS
    assert ACCESS.encode() in (refresh_request.body or b"")
    assert REFRESH.encode() in (refresh_request.body or b"")
    assert transport.requests[2].headers["accessToken"] == NEW_ACCESS


@pytest.mark.asyncio
async def test_expired_access_api_code_refreshes_legacy_session() -> None:
    state = _state()
    transport = _QueueTransport(
        [
            _response(code="550004"),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"email": SENSITIVE}),
        ]
    )

    result = await _client(transport).authenticate_anz(_credentials(), state=state)

    assert type(result) is AnzAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
async def test_runtime_legacy_anz_refresh_installs_rotated_session() -> None:
    state = _state()
    context = _default_context()
    transport = _QueueTransport(
        [
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"email": SENSITIVE}),
        ]
    )
    client = _client(
        transport,
        session=GwmSession(
            "AU",
            state.device_id,
            ACCESS,
            context,
            gw_id=state.gw_id,
        ),
    )

    result = await client.refresh_legacy_anz_session(_credentials(), state)

    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.session.app_ssl_context is context
    assert client._session == result.session
    assert [request.operation for request in transport.requests] == [
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reclaim_at",
    ["access", "access_http", "refresh", "refreshed_profile"],
)
async def test_607501_returns_typed_reclaim_continuation_and_retires_session(
    reclaim_at: str,
) -> None:
    responses: list[_TransportResponse] = []
    if reclaim_at == "access":
        responses.append(_response(code="607501", description=SENSITIVE))
    elif reclaim_at == "access_http":
        responses.append(_response(code="607501", status=401, description=SENSITIVE))
    else:
        responses.append(_response(status=401))
        if reclaim_at == "refresh":
            responses.append(_response(code="607501", description=SENSITIVE))
        else:
            responses.extend(
                [
                    _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
                    _response(code="607501", description=SENSITIVE),
                ]
            )
    transport = _QueueTransport(responses)
    state = _state()
    client = _client(
        transport,
        session=GwmSession("AU", state.device_id, ACCESS, _default_context()),
    )

    result = await client.authenticate_anz(_credentials(), state=state)

    assert type(result) is AnzSessionReclaimRequired
    assert result.state.session_reclaim_required
    assert result.state.access_token is None
    assert result.state.refresh_token is None
    assert not client.authenticated
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_reclaim_marker_repeat_is_idempotent_and_does_zero_network() -> None:
    state = _state(access=None, refresh=None, reclaim=True)
    transport = _QueueTransport()
    result = await _client(transport).authenticate_anz(_credentials(), state=state)

    assert type(result) is AnzSessionReclaimRequired
    assert result.state == state
    assert transport.requests == []


@pytest.mark.asyncio
async def test_explicit_reclaim_permits_one_login_then_profile_validation() -> None:
    state = _state(access=None, refresh=None, reclaim=True)
    transport = _QueueTransport(
        [
            _response(
                {
                    "accessToken": NEW_ACCESS,
                    "refreshToken": NEW_REFRESH,
                    "email": SENSITIVE,
                }
            ),
            _response({"email": SENSITIVE}),
        ]
    )
    client = _client(transport)
    result = await client.authenticate_anz(
        _credentials(),
        state=state,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzAuthenticated
    assert not result.state.session_reclaim_required
    assert result.state.access_token == NEW_ACCESS
    assert [request.operation for request in transport.requests] == ["login", "get_user_info"]
    assert client.authenticated


@pytest.mark.asyncio
async def test_explicit_reclaim_never_loops_if_new_session_is_also_rejected() -> None:
    state = _state(access=None, refresh=None, reclaim=True)
    transport = _QueueTransport(
        [
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response(code="607501", description=SENSITIVE),
        ]
    )
    result = await _client(transport).authenticate_anz(
        _credentials(),
        state=state,
        allow_session_reclaim=True,
    )

    assert type(result) is AnzSessionReclaimRequired
    assert result.state.session_reclaim_required
    assert [request.operation for request in transport.requests] == ["login", "get_user_info"]


@pytest.mark.asyncio
async def test_reclaim_challenge_preserves_marker_and_requires_fresh_opt_in() -> None:
    state = _state(access=None, refresh=None, reclaim=True)
    first_transport = _QueueTransport([_response(code="309702"), _response()])
    challenged = await _client(first_transport).authenticate_anz(
        _credentials(),
        state=state,
        allow_session_reclaim=True,
    )
    assert type(challenged) is AnzVerificationRequired
    assert challenged.state.session_reclaim_required
    assert [request.operation for request in first_transport.requests] == [
        "login",
        "request_verification",
    ]

    repeat_transport = _QueueTransport()
    repeated = await _client(repeat_transport).authenticate_anz(
        _credentials(),
        state=challenged.state,
        verification_code="246810",
    )
    assert type(repeated) is AnzSessionReclaimRequired
    assert repeat_transport.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("allow", [None, 0, 1, "true"])
async def test_allow_session_reclaim_requires_exact_bool(allow: object) -> None:
    transport = _QueueTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(transport).authenticate_anz(
            _credentials(),
            state=_state(access=None, refresh=None, reclaim=True),
            allow_session_reclaim=allow,  # type: ignore[arg-type]
        )
    assert transport.requests == []


@pytest.mark.asyncio
async def test_unknown_access_api_error_does_not_refresh_login_or_retire_session() -> None:
    state = _state()
    old_context = _default_context()
    transport = _QueueTransport([_response(code="900001", description=SENSITIVE)])
    client = _client(
        transport,
        session=GwmSession("AU", state.device_id, ACCESS, old_context),
    )
    with pytest.raises(GwmApiError) as raised:
        await client.authenticate_anz(_credentials(), state=state)
    assert raised.value.api_code == "900001"
    assert [request.operation for request in transport.requests] == ["get_user_info"]
    assert client.authenticated
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_account_mismatch_discards_old_session_before_requiring_login_consent() -> None:
    old_credentials = AnzCredentials(
        "old@example.invalid",
        "SYNTHETIC-OLD-PASSWORD",
        "AU",
        _credentials().device_id,
    )
    old_state = AnzAuthState(
        account_binding=old_credentials.account_binding,
        country="AU",
        device_id=old_credentials.device_id,
        access_token=ACCESS,
        refresh_token=REFRESH,
    )
    transport = _QueueTransport()
    client = _client(
        transport,
        session=GwmSession("AU", old_state.device_id, ACCESS, _default_context()),
    )
    result = await client.authenticate_anz(_credentials(), state=old_state)

    assert type(result) is AnzSessionReclaimRequired
    assert result.state.session_reclaim_required
    assert not client.authenticated
    assert transport.requests == []


@pytest.mark.asyncio
async def test_reclaim_attempt_cannot_erase_newer_session_replacement() -> None:
    replacement_token = "SYNTHETIC-CONCURRENT-ACCESS"
    replacement_context = _default_context()
    transport = _QueueTransport(
        [
            _response(code="607501", description=SENSITIVE),
            _response([]),
        ],
        delay=0.02,
    )
    state = _state()
    client = _client(
        transport,
        session=GwmSession("AU", state.device_id, ACCESS, _default_context()),
    )
    authenticating = asyncio.create_task(client.authenticate_anz(_credentials(), state=state))
    async with asyncio.timeout(1):
        while not transport.requests:
            await asyncio.sleep(0)

    client.replace_session(GwmSession("AU", state.device_id, replacement_token, replacement_context))
    result = await authenticating
    assert type(result) is AnzSessionReclaimRequired

    assert client.authenticated
    await client.acquire_vehicles()
    read_request = transport.requests[-1]
    assert read_request.headers["accessToken"] == replacement_token
    assert read_request.ssl_context is replacement_context


@pytest.mark.asyncio
async def test_authentication_calls_are_serialized_per_client() -> None:
    transport = _QueueTransport(
        [_response({"email": SENSITIVE}), _response({"email": SENSITIVE})],
        delay=0.01,
    )
    client = _client(transport)
    state = _state()
    first, second = await asyncio.gather(
        client.authenticate_anz(_credentials(), state=state),
        client.authenticate_anz(_credentials(), state=state),
    )
    assert type(first) is AnzAuthenticated
    assert type(second) is AnzAuthenticated
    assert transport.max_active == 1


@pytest.mark.asyncio
async def test_deadline_cancels_auth_without_replacing_matching_session() -> None:
    state = _state()
    transport = _QueueTransport(hang=True)
    client = _client(
        transport,
        session=GwmSession("AU", state.device_id, ACCESS, _default_context()),
        total_timeout=1,
    )
    with pytest.raises(GwmDeadlineExceededError):
        await client.authenticate_anz(
            _credentials(),
            state=state,
            timeout=0.01,
        )
    assert client.authenticated


@pytest.mark.asyncio
async def test_authentication_rejects_foreign_region_before_transport() -> None:
    transport = _QueueTransport()
    client = GwmClient(GwmClientConfig("eu"), None, transport=transport)
    with pytest.raises(GwmConfigurationError):
        await client.authenticate_anz(_credentials())
    assert transport.requests == []


@pytest.mark.asyncio
async def test_injected_unexpected_transport_error_is_redacted_without_context() -> None:
    transport = _QueueTransport([RuntimeError(SENSITIVE)])
    with pytest.raises(GwmNetworkError) as raised:
        await _client(transport).authenticate_anz(_credentials(), state=_state())
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
