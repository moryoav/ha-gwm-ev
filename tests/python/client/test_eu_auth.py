"""Offline EU authentication, verification, refresh, and enrollment tests."""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import pytest

import gwm_client.eu_auth as eu_auth
from gwm_client._dotnet_json import encode_dotnet_json
from gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse
from gwm_client.client import GwmClient
from gwm_client.config import GwmClientConfig, RequestTimeouts
from gwm_client.crypto import GeneratedClientCertificateRequest
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
)
from gwm_client.eu_auth import (
    EuAuthenticated,
    EuAuthState,
    EuCredentials,
    EuVerificationRequired,
)
from gwm_client.eu_identity import EuBootstrapMaterial, EuIdentityError, EuIssuedIdentity
from gwm_client.models import GwmSession
from gwm_client.signing import SignedRequest, SigningProfile
from gwm_client.tls import create_gwm_ssl_context

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "eu_auth_contracts_v1.json"
READ_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "eu_read_responses_v1.json"
NOW = datetime(2026, 8, 24, 12, 34, 56, 789000, tzinfo=UTC)
CA_BUNDLE = b"SYNTHETIC-CA-BUNDLE"
ACCESS = "SYNTHETIC-OLD-ACCESS"
REFRESH = "SYNTHETIC-OLD-REFRESH"
NEW_ACCESS = "SYNTHETIC-NEW-ACCESS"
NEW_REFRESH = "SYNTHETIC-NEW-REFRESH"
GW_ID = "SYNTHETIC-GW-ID"
BEAN_ID = "SYNTHETIC-BEAN-ID"
SENSITIVE = "SENSITIVE-eu-auth-material-019fea1b"


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
        self.close_calls = 0

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
        self.close_calls += 1


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


def _credentials() -> EuCredentials:
    return EuCredentials(
        account=" SYNTHETIC-owner+tag@example.invalid ",
        password="SYNTHETIC-PASSWORD",
        country=" il ",
        device_id="01234567-89AB-CDEF-0123-456789ABCDEF",
    )


def _identity() -> EuIssuedIdentity:
    return EuIssuedIdentity(
        certificate=base64.b64encode(b"SYNTHETIC-CERT").decode(),
        private_key=base64.b64encode(b"SYNTHETIC-KEY").decode(),
    )


def _bootstrap() -> EuBootstrapMaterial:
    return EuBootstrapMaterial(
        certificate_data=b"SYNTHETIC-BOOTSTRAP-CERT",
        transformed_private_key_data=base64.b64encode(b"SYNTHETIC-BOOTSTRAP-KEY"),
        ca_bundle=CA_BUNDLE,
    )


def _default_context() -> ssl.SSLContext:
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


def _issued_context() -> ssl.SSLContext:
    return create_gwm_ssl_context()


def _state(
    *,
    access: str | None = ACCESS,
    refresh: str | None = REFRESH,
    gw_id: str | None = GW_ID,
    identity: EuIssuedIdentity | None = None,
) -> EuAuthState:
    credentials = _credentials()
    return EuAuthState(
        account_binding=credentials.account_binding,
        country=credentials.country,
        device_id=credentials.device_id,
        access_token=access,
        refresh_token=refresh,
        gw_id=gw_id,
        bean_id=BEAN_ID if gw_id is not None else None,
        issued_identity=identity,
    )


def _client(
    transport: _QueueTransport,
    *,
    session: GwmSession | None = None,
    total_timeout: float = 5,
) -> GwmClient:
    return GwmClient(
        GwmClientConfig(
            "eu",
            timeouts=RequestTimeouts(total=total_timeout, connect=1, read=1),
        ),
        session,
        transport=transport,
    )


@pytest.fixture(autouse=True)
def _fixed_offline_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eu_auth, "_utc_now", lambda: NOW)
    monkeypatch.setattr(eu_auth, "_create_default_ssl_context", _default_context)
    monkeypatch.setattr(
        eu_auth,
        "create_eu_issued_ssl_context",
        lambda identity, *, ca_bundle, now=None: _issued_context(),
    )
    monkeypatch.setattr(
        eu_auth,
        "create_eu_bootstrap_ssl_context",
        lambda material, *, now=None: _issued_context(),
    )


def test_credentials_state_and_outcomes_hide_all_sensitive_values() -> None:
    credentials = _credentials()
    assert credentials.account == "SYNTHETIC-owner+tag@example.invalid"
    assert credentials.password == "SYNTHETIC-PASSWORD"
    assert credentials.country == "IL"
    assert credentials.device_id == "0123456789abcdef0123456789abcdef"
    state = EuAuthState.for_credentials(credentials)
    outcome = EuVerificationRequired(state=state, code_requested=True)

    rendered = repr((credentials, state, outcome, _identity(), _bootstrap()))
    for secret in (
        credentials.account,
        credentials.password,
        credentials.device_id,
        credentials.account_binding,
        _identity().certificate,
        _identity().private_key,
    ):
        assert secret not in rendered


@pytest.mark.parametrize("country", ["", "US", "ZZ", "I", "ISR"])
def test_credentials_reject_unknown_eu_registration_country(country: str) -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        EuCredentials("synthetic@example.invalid", "SYNTHETIC-PASSWORD", country, "0123")


@pytest.mark.parametrize(
    ("country", "calling_code"),
    [("DE", "+49"), ("GB", "+44"), ("LV", "+371")],
)
def test_representative_eu_calling_codes_match_all_auth_bodies(
    country: str,
    calling_code: str,
) -> None:
    credentials = EuCredentials(
        "SYNTHETIC-owner@example.invalid",
        "SYNTHETIC-PASSWORD",
        country,
        "0123456789abcdef0123456789abcdef",
    )

    assert eu_auth._login_body(credentials, verification_code=None)["countryCode"] == calling_code
    assert eu_auth._verification_request_body(credentials)["countryCode"] == calling_code
    assert eu_auth._verification_check_body(credentials, "SYNTHETIC-CODE")["countryCode"] == calling_code


def test_state_is_bound_to_exact_account_country_and_stable_device() -> None:
    credentials = _credentials()
    state = EuAuthState.for_credentials(credentials)
    assert state.matches(credentials)
    assert not state.matches(
        EuCredentials(
            "different@example.invalid",
            credentials.password,
            credentials.country,
            credentials.device_id,
        )
    )
    assert not state.matches(
        EuCredentials(
            credentials.account,
            credentials.password,
            "GB",
            credentials.device_id,
        )
    )
    assert not state.matches(
        EuCredentials(
            credentials.account,
            credentials.password,
            credentials.country,
            "fedcba9876543210fedcba9876543210",
        )
    )


def test_dotnet_json_encoder_matches_default_encoder_escape_contract() -> None:
    ascii_value = "".join(chr(value) for value in range(128))
    expected = (
        '"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007'
        "\\b\\t\\n\\u000B\\f\\r\\u000E\\u000F\\u0010\\u0011\\u0012"
        "\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001A"
        "\\u001B\\u001C\\u001D\\u001E\\u001F !\\u0022#$%\\u0026\\u0027"
        "()*\\u002B,-./0123456789:;\\u003C=\\u003E?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        '[\\\\]^_\\u0060abcdefghijklmnopqrstuvwxyz{|}~\\u007F"'
    )
    assert encode_dotnet_json(ascii_value) == expected
    assert encode_dotnet_json("é😀") == '"\\u00E9\\uD83D\\uDE00"'


def test_all_eu_auth_requests_match_versioned_closed_wire_contract() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    credentials = _credentials()
    default_context = _default_context()
    bootstrap_context = _issued_context()
    state = _state()
    generated = GeneratedClientCertificateRequest("SYNTHETIC-CSR", "SYNTHETIC-KEY")
    cases = {
        "login": (
            eu_auth._LOGIN,
            eu_auth._login_body(credentials, verification_code=None),
            None,
            default_context,
            None,
        ),
        "verified_login": (
            eu_auth._LOGIN,
            eu_auth._login_body(credentials, verification_code="SYNTHETIC-246810"),
            None,
            default_context,
            None,
        ),
        "request_verification": (
            eu_auth._REQUEST_VERIFICATION,
            eu_auth._verification_request_body(credentials),
            None,
            default_context,
            None,
        ),
        "verify_code": (
            eu_auth._VERIFY_CODE,
            eu_auth._verification_check_body(credentials, "SYNTHETIC-246810"),
            None,
            default_context,
            None,
        ),
        "refresh": (
            eu_auth._REFRESH,
            eu_auth._refresh_body(credentials, state),
            None,
            default_context,
            None,
        ),
        "get_user_info": (
            eu_auth._USER_INFO,
            None,
            ACCESS,
            default_context,
            None,
        ),
        "enroll_certificate": (
            eu_auth._ENROLL,
            eu_auth._enrollment_body(generated, GW_ID),
            ACCESS,
            bootstrap_context,
            credentials.device_id + "1787574896789",
        ),
    }

    for name, (endpoint, body, token, context, enrollment_device) in cases.items():
        expected = fixture["operations"][name]
        request = eu_auth._prepare_request(
            endpoint=endpoint,
            credentials=credentials,
            body=body,
            access_token=token,
            ssl_context=context,
            enrollment_device_id=enrollment_device,
        )
        parsed = urlsplit(request.url)
        assert request.method == expected["method"]
        assert parsed.hostname == expected["host"]
        assert parsed.path == expected["path"]
        assert parsed.query == ""
        assert ("accessToken" in request.headers) is expected["access_token_header"]
        assert request.headers["deviceId"] == request.headers["iccid"]
        assert request.headers["country"] == request.headers["regionCode"] == "IL"
        assert not {"brandId", "communityBrand"} & set(request.headers)
        signing_headers = {key for key in request.headers if key.startswith(expected["signing_prefix"])}
        assert len(signing_headers) == 4
        if expected["body"] is None:
            assert request.body is None
            assert "Content-Type" not in request.headers
        else:
            assert request.body == expected["body"].encode()
            assert request.headers["Content-Type"] == "application/json; charset=utf-8"
            assert expected["body"] not in repr(request)
        assert "Accept" not in request.headers


@pytest.mark.parametrize("mutation", ["host", "path", "query", "method", "body", "headers"])
def test_auth_request_registry_rejects_every_post_signing_route_mutation(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    real_sign = cast(
        Callable[[SigningProfile, str, str, str | None], SignedRequest],
        eu_auth.__dict__["sign_request"],
    )

    def tampered_sign(
        profile: SigningProfile,
        method: str,
        url: str,
        body: str | None,
    ) -> SignedRequest:
        signed = real_sign(profile, method, url, body)
        if mutation == "host":
            return replace(signed, url=signed.url.replace("eu-h5-gateway", "evil-gateway"))
        if mutation == "path":
            return replace(signed, url=signed.url.replace("loginWithPassword", "refreshToken"))
        if mutation == "query":
            return replace(signed, url=signed.url + "?escape=1")
        if mutation == "method":
            return replace(signed, method="GET")
        if mutation == "body":
            return replace(signed, body="{}")
        headers = dict(signed.headers)
        headers.pop("gwm-auth-sign")
        return replace(signed, headers=headers)

    monkeypatch.setattr(eu_auth, "sign_request", tampered_sign)
    with pytest.raises(GwmRoutePolicyError) as raised:
        eu_auth._prepare_request(
            endpoint=eu_auth._LOGIN,
            credentials=_credentials(),
            body=eu_auth._login_body(_credentials(), verification_code=None),
            access_token=None,
            ssl_context=_default_context(),
            enrollment_device_id=None,
        )
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("data", [..., None])
def test_verification_success_envelopes_do_not_require_data(data: object) -> None:
    response = _response(data)
    assert (
        eu_auth._decode_auth_envelope(
            response,
            operation="verify_code",
            require_data=False,
        )
        is None
    )


def test_auth_envelope_rejects_duplicates_non_string_success_and_maps_rate_limit() -> None:
    duplicate = _TransportResponse(200, {}, b'{"code":"000000","code":"000000"}')
    with pytest.raises(GwmSchemaError):
        eu_auth._decode_auth_envelope(duplicate, operation="login", require_data=True)
    with pytest.raises(GwmApiError):
        eu_auth._decode_auth_envelope(
            _TransportResponse(200, {}, b'{"code":0,"data":{}}'),
            operation="login",
            require_data=True,
        )
    with pytest.raises(GwmRateLimitError) as raised:
        eu_auth._decode_auth_envelope(
            _response(code="999999", status=429, headers={"Retry-After": "12"}),
            operation="login",
            require_data=True,
        )
    assert raised.value.retry_after_seconds == 12


def test_http_failure_precedes_application_challenge_classification() -> None:
    with pytest.raises(GwmHttpError) as raised:
        eu_auth._decode_auth_envelope(
            _response(code="308103", status=500),
            operation="login",
            require_data=True,
        )
    assert raised.value.status == 500


@pytest.mark.asyncio
async def test_auth_deadline_is_rechecked_after_synchronous_envelope_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def delayed_challenge(*_args: object, **_kwargs: object) -> object:
        time.sleep(0.02)
        raise GwmApiError(operation="login", api_code="308103")

    monkeypatch.setattr(eu_auth, "_decode_auth_envelope", delayed_challenge)
    transport = _QueueTransport([_response({})])
    loop = asyncio.get_running_loop()

    with pytest.raises(GwmDeadlineExceededError):
        await eu_auth._request_data(
            config=GwmClientConfig("eu"),
            transport=transport,
            endpoint=eu_auth._LOGIN,
            credentials=_credentials(),
            body=eu_auth._login_body(_credentials(), verification_code=None),
            access_token=None,
            ssl_context=_default_context(),
            deadline=_Deadline(loop.time() + 0.005),
        )


@pytest.mark.asyncio
async def test_initial_challenge_requests_one_code_and_returns_continuation_state() -> None:
    transport = _QueueTransport(
        [
            _response(code="308103", description=SENSITIVE),
            _response(),
        ]
    )
    client = _client(transport)
    result = await client.authenticate_eu(
        _credentials(),
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )

    assert type(result) is EuVerificationRequired
    assert result.code_requested
    assert not result.code_rejected
    assert result.state.verification_requested_at == NOW
    assert not client.authenticated
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
    ]
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_rejected_access_and_refresh_are_removed_before_verification_continuation() -> None:
    state = _state(identity=_identity())
    old_session = GwmSession("IL", state.device_id, ACCESS, _issued_context())
    transport = _QueueTransport(
        [
            _response(status=401),
            _response(status=401),
            _response(code="308103"),
            _response(),
        ]
    )
    client = _client(transport, session=old_session)
    result = await client.authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
    )

    assert type(result) is EuVerificationRequired
    assert result.state.access_token is None
    assert result.state.refresh_token is None
    assert not client.authenticated
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "login",
        "request_verification",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("age", "request_expected"),
    [
        (timedelta(minutes=9, seconds=59), False),
        (timedelta(minutes=10), True),
        (timedelta(minutes=10, milliseconds=1), True),
        (timedelta(minutes=-1), True),
    ],
)
async def test_verification_request_throttle_boundaries(
    age: timedelta,
    request_expected: bool,
) -> None:
    state = EuAuthState.for_credentials(_credentials())
    state = EuAuthState(
        account_binding=state.account_binding,
        country=state.country,
        device_id=state.device_id,
        verification_requested_at=NOW - age,
    )
    responses = [_response(code="110641")]
    if request_expected:
        responses.append(_response(None))
    transport = _QueueTransport(responses)
    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )

    assert type(result) is EuVerificationRequired
    assert result.code_requested is request_expected
    assert len(transport.requests) == 1 + int(request_expected)


@pytest.mark.asyncio
async def test_failed_verification_request_does_not_publish_throttle_timestamp() -> None:
    state = EuAuthState.for_credentials(_credentials())
    transport = _QueueTransport(
        [
            _response(code="308103"),
            _response(code="900001", description=SENSITIVE),
            _response(code="308103"),
            _response(),
        ]
    )
    client = _client(transport)

    with pytest.raises(GwmApiError) as raised:
        await client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert raised.value.operation == "request_verification"
    assert state.verification_requested_at is None

    result = await client.authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )
    assert type(result) is EuVerificationRequired
    assert result.code_requested
    assert result.state.verification_requested_at == NOW
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
        "login",
        "request_verification",
    ]


@pytest.mark.asyncio
async def test_verification_continuation_checks_then_logs_in_and_reuses_identity() -> None:
    identity = _identity()
    state = _state(access=None, refresh=None, identity=identity)
    transport = _QueueTransport(
        [
            _response(),
            _response(
                {
                    "accessToken": NEW_ACCESS,
                    "refreshToken": NEW_REFRESH,
                    "gwId": GW_ID,
                    "beanId": BEAN_ID,
                    "email": SENSITIVE,
                }
            ),
        ]
    )
    client = _client(transport)
    result = await client.authenticate_eu(
        _credentials(),
        state=state,
        verification_code=" 246810 ",
        ca_bundle=CA_BUNDLE,
    )

    assert type(result) is EuAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.state.issued_identity is identity
    assert result.state.verification_requested_at is None
    assert client.authenticated
    assert [request.operation for request in transport.requests] == ["verify_code", "login"]
    assert b'"validCodeMode":"1"' in (transport.requests[1].body or b"")
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_only_known_rejected_code_returns_outcome_and_other_failures_propagate() -> None:
    requested_state = EuAuthState.for_credentials(_credentials())
    requested_state = EuAuthState(
        account_binding=requested_state.account_binding,
        country=requested_state.country,
        device_id=requested_state.device_id,
        verification_requested_at=NOW - timedelta(minutes=1),
    )
    rejected_transport = _QueueTransport([_response(code="110641", description=SENSITIVE)])
    rejected = await _client(rejected_transport).authenticate_eu(
        _credentials(),
        state=requested_state,
        verification_code="246810",
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )
    assert type(rejected) is EuVerificationRequired
    assert rejected.code_rejected
    assert rejected.state.verification_requested_at is None
    assert len(rejected_transport.requests) == 1

    unknown_check = _QueueTransport([_response(code="123456", description=SENSITIVE)])
    with pytest.raises(GwmApiError) as raised:
        await _client(unknown_check).authenticate_eu(
            _credentials(),
            state=requested_state,
            verification_code="246810",
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert raised.value.operation == "verify_code"
    assert len(unknown_check.requests) == 1

    login_failure = _QueueTransport([_response(), _response(code="900001", description=SENSITIVE)])
    with pytest.raises(GwmApiError) as raised:
        await _client(login_failure).authenticate_eu(
            _credentials(),
            state=requested_state,
            verification_code="246810",
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert raised.value.operation == "login"
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_valid_access_token_discards_profile_pii_and_never_touches_bootstrap() -> None:
    identity = _identity()
    state = _state(identity=identity)
    transport = _QueueTransport(
        [_response({"gwId": GW_ID, "beanId": BEAN_ID, "email": SENSITIVE, "firstName": SENSITIVE})]
    )
    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
        bootstrap_material=None,
    )

    assert type(result) is EuAuthenticated
    assert result.state == state
    assert not hasattr(result.state, "email")
    assert not hasattr(result.state, "first_name")
    assert [request.operation for request in transport.requests] == ["get_user_info"]
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_authenticated_eu_session_reads_all_versioned_response_fixtures() -> None:
    fixture = json.loads(READ_FIXTURE_PATH.read_text(encoding="utf-8"))
    identity = _identity()
    transport = _QueueTransport(
        [
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
            _response(fixture["responses"]["acquire_vehicles"]),
            _response(fixture["responses"]["get_last_status"]),
            _response(fixture["responses"]["get_vehicle_basics"]),
        ]
    )
    client = _client(transport)

    authenticated = await client.authenticate_eu(
        _credentials(),
        state=_state(identity=identity),
        ca_bundle=CA_BUNDLE,
    )
    assert type(authenticated) is EuAuthenticated

    vehicles = await client.acquire_vehicles()
    assert len(vehicles) == 1
    vehicle = vehicles[0]
    assert vehicle.identifier.value == fixture["identifier"]
    assert vehicle.default_vehicle
    assert vehicle.model_name == "Synthetic EU model"
    assert not hasattr(vehicle, "email")
    assert not hasattr(vehicle, "license_number")

    status = await client.get_last_status(vehicle.identifier)
    assert status.device_id == "SYNTHETIC-TELEMATICS-ID"
    assert status.acquisition_time_ms == 1_787_574_896_789
    assert status.update_time_ms == 1_787_574_897_890
    assert status.latitude == 1.25
    assert status.longitude == -2.5
    assert [item.code for item in status.items] == ["SOC", "NESTED"]
    assert status.items[0].value == 73
    assert tuple(status.items[1].value["levels"]) == (1, None, "synthetic")  # type: ignore[index]

    basics = await client.get_vehicle_basics(vehicle.identifier)
    assert basics.climate is not None
    assert basics.climate.temperature == "22.0"
    assert basics.climate.operation_time is None
    assert basics.climate.engine_operation_time == "15"

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
async def test_rejected_access_refreshes_without_token_header_and_rotates_atomically() -> None:
    identity = _identity()
    state = _state(identity=identity)
    transport = _QueueTransport(
        [
            _response(code="607501", status=401),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"gwId": GW_ID, "beanId": BEAN_ID, "email": SENSITIVE}),
        ]
    )
    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
    )

    assert type(result) is EuAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]
    refresh_request = transport.requests[1]
    assert "accessToken" not in refresh_request.headers
    assert refresh_request.body is not None
    assert ACCESS.encode() in refresh_request.body
    assert REFRESH.encode() in refresh_request.body
    assert transport.requests[2].headers["accessToken"] == NEW_ACCESS


@pytest.mark.asyncio
async def test_expired_access_api_code_refreshes_and_rotates_atomically() -> None:
    identity = _identity()
    state = _state(identity=identity)
    transport = _QueueTransport(
        [
            _response(code="550004"),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
        ]
    )

    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
    )

    assert type(result) is EuAuthenticated
    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
async def test_runtime_eu_refresh_installs_rotated_session() -> None:
    state = _state(identity=_identity())
    context = _issued_context()
    transport = _QueueTransport(
        [
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
        ]
    )
    client = _client(
        transport,
        session=GwmSession("IL", state.device_id, ACCESS, context),
    )

    result = await client.refresh_eu_session(_credentials(), state)

    assert result.state.access_token == NEW_ACCESS
    assert result.state.refresh_token == NEW_REFRESH
    assert result.session.app_ssl_context is context
    assert client._session == result.session
    assert [request.operation for request in transport.requests] == [
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
async def test_refreshed_token_rejection_falls_through_to_fresh_verification() -> None:
    state = _state(identity=_identity())
    transport = _QueueTransport(
        [
            _response(status=401),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response(status=401),
            _response(code="308103"),
            _response(),
        ]
    )
    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=state,
        ca_bundle=CA_BUNDLE,
    )

    assert type(result) is EuVerificationRequired
    assert result.state.access_token is None
    assert result.state.refresh_token is None
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
        "login",
        "request_verification",
    ]


@pytest.mark.asyncio
async def test_resume_only_rejection_never_falls_through_to_password_or_sms() -> None:
    state = _state(identity=_identity())
    transport = _QueueTransport(
        [
            _response(status=401),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response(status=401),
        ]
    )

    with pytest.raises(GwmAuthenticationError):
        await _client(transport).authenticate_eu(
            _credentials(),
            state=state,
            allow_password_login=False,
            ca_bundle=CA_BUNDLE,
        )

    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "refresh_token",
        "get_user_info",
    ]


@pytest.mark.asyncio
async def test_unknown_access_api_error_does_not_trigger_refresh_or_login() -> None:
    transport = _QueueTransport([_response(code="900001", description=SENSITIVE)])
    with pytest.raises(GwmApiError) as raised:
        await _client(transport).authenticate_eu(
            _credentials(),
            state=_state(identity=_identity()),
            ca_bundle=CA_BUNDLE,
        )
    assert raised.value.api_code == "900001"
    assert [request.operation for request in transport.requests] == ["get_user_info"]
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_profile_identity_change_enrolls_with_one_instant_and_atomic_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = GeneratedClientCertificateRequest(
        csr="SYNTHETIC-CSR",
        private_key=base64.b64encode(b"SYNTHETIC-NEW-KEY").decode(),
    )
    captured: dict[str, object] = {}

    def generate(
        country: str | None, device_id: str | None, *, now: datetime | None = None
    ) -> GeneratedClientCertificateRequest:
        captured.update(country=country, device_id=device_id, now=now)
        return generated

    monkeypatch.setattr(eu_auth, "generate_client_certificate_request", generate)
    monkeypatch.setattr(
        eu_auth,
        "create_eu_bootstrap_ssl_context",
        lambda material, *, now=None: _issued_context(),
    )
    old_identity = _identity()
    encoded = base64.b64encode(b"SYNTHETIC-ISSUED-CERT").decode()
    transport = _QueueTransport(
        [
            _response({"gwId": "SYNTHETIC-NEW-GW-ID", "beanId": "SYNTHETIC-NEW-BEAN-ID"}),
            _response({"encoded": encoded, "issuer": SENSITIVE, "serialnumber": SENSITIVE}),
        ]
    )
    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=_state(identity=old_identity),
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )

    assert type(result) is EuAuthenticated
    assert result.state.gw_id == "SYNTHETIC-NEW-GW-ID"
    assert result.state.issued_identity is not old_identity
    assert result.state.issued_identity is not None
    assert result.state.issued_identity.certificate == encoded
    assert result.state.issued_identity.private_key == generated.private_key
    assert captured == {
        "country": "IL",
        "device_id": _credentials().device_id,
        "now": NOW,
    }
    enrollment = transport.requests[1]
    assert enrollment.operation == "enroll_certificate"
    assert enrollment.headers["accessToken"] == ACCESS
    assert enrollment.headers["deviceId"] == _credentials().device_id + "1787574896789"
    assert enrollment.headers["iccid"] == enrollment.headers["deviceId"]
    assert enrollment.body == b'{"csr":"SYNTHETIC-CSR","phone":"SYNTHETIC-NEW-GW-ID"}'
    assert SENSITIVE not in repr(result)


@pytest.mark.asyncio
async def test_enrollment_failure_preserves_matching_existing_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        eu_auth,
        "create_eu_issued_ssl_context",
        lambda identity, *, ca_bundle, now=None: (_ for _ in ()).throw(EuIdentityError("identity_renewal_required")),
    )
    monkeypatch.setattr(
        eu_auth,
        "generate_client_certificate_request",
        lambda country, device_id, *, now=None: GeneratedClientCertificateRequest(
            "SYNTHETIC-CSR",
            base64.b64encode(b"SYNTHETIC-NEW-KEY").decode(),
        ),
    )
    monkeypatch.setattr(
        eu_auth,
        "create_eu_bootstrap_ssl_context",
        lambda material, *, now=None: _issued_context(),
    )
    old_context = _issued_context()
    old_session = GwmSession("IL", _credentials().device_id, ACCESS, old_context)
    state = _state(identity=_identity())
    transport = _QueueTransport(
        [
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
            GwmNetworkError(operation="enroll_certificate"),
            _response([]),
        ]
    )
    client = _client(transport, session=old_session)
    with pytest.raises(GwmNetworkError):
        await client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert client.authenticated

    await client.acquire_vehicles()
    read_request = transport.requests[-1]
    assert read_request.operation == "acquire_vehicles"
    assert read_request.ssl_context is old_context
    assert read_request.headers["accessToken"] == ACCESS


@pytest.mark.asyncio
@pytest.mark.parametrize("category", ["identity_chain_invalid", "identity_expired"])
async def test_definitively_invalid_identity_is_retired_if_renewal_fails(
    monkeypatch: pytest.MonkeyPatch,
    category: str,
) -> None:
    monkeypatch.setattr(
        eu_auth,
        "create_eu_issued_ssl_context",
        lambda identity, *, ca_bundle, now=None: (_ for _ in ()).throw(EuIdentityError(category)),
    )
    monkeypatch.setattr(
        eu_auth,
        "generate_client_certificate_request",
        lambda country, device_id, *, now=None: GeneratedClientCertificateRequest(
            "SYNTHETIC-CSR",
            base64.b64encode(b"SYNTHETIC-NEW-KEY").decode(),
        ),
    )
    state = _state(identity=_identity())
    client = _client(
        _QueueTransport(
            [
                _response({"gwId": GW_ID, "beanId": BEAN_ID}),
                GwmNetworkError(operation="enroll_certificate"),
            ]
        ),
        session=GwmSession("IL", state.device_id, ACCESS, _issued_context()),
    )

    with pytest.raises(GwmNetworkError):
        await client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert not client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "category",
    ["identity_renewal_required", "identity_chain_invalid"],
)
async def test_reusable_identity_context_race_renews_once(
    monkeypatch: pytest.MonkeyPatch,
    category: str,
) -> None:
    generated = GeneratedClientCertificateRequest(
        "SYNTHETIC-CSR",
        base64.b64encode(b"SYNTHETIC-NEW-KEY").decode(),
    )
    context_calls = 0

    def create_context(
        identity: EuIssuedIdentity,
        *,
        ca_bundle: bytes,
        now: datetime | None = None,
    ) -> ssl.SSLContext:
        nonlocal context_calls
        del identity, ca_bundle, now
        context_calls += 1
        if context_calls == 1:
            raise EuIdentityError(category)
        return _issued_context()

    monkeypatch.setattr(eu_auth, "create_eu_issued_ssl_context", create_context)
    monkeypatch.setattr(
        eu_auth,
        "generate_client_certificate_request",
        lambda country, device_id, *, now=None: generated,
    )
    monkeypatch.setattr(
        eu_auth,
        "create_eu_bootstrap_ssl_context",
        lambda material, *, now=None: _issued_context(),
    )
    transport = _QueueTransport(
        [
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
            _response({"encoded": base64.b64encode(b"SYNTHETIC-RENEWED-CERT").decode()}),
        ]
    )

    result = await _client(transport).authenticate_eu(
        _credentials(),
        state=_state(identity=_identity()),
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )

    assert type(result) is EuAuthenticated
    assert context_calls == 2
    assert [request.operation for request in transport.requests] == [
        "get_user_info",
        "enroll_certificate",
    ]


@pytest.mark.asyncio
async def test_ca_context_failure_is_configuration_error_without_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        eu_auth,
        "create_eu_issued_ssl_context",
        lambda identity, *, ca_bundle, now=None: (_ for _ in ()).throw(EuIdentityError("ca_bundle_invalid")),
    )
    transport = _QueueTransport([_response({"gwId": GW_ID, "beanId": BEAN_ID})])

    with pytest.raises(GwmConfigurationError):
        await _client(transport).authenticate_eu(
            _credentials(),
            state=_state(identity=_identity()),
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert [request.operation for request in transport.requests] == ["get_user_info"]


@pytest.mark.asyncio
async def test_bootstrap_ca_mismatch_fails_before_transport() -> None:
    transport = _QueueTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(transport).authenticate_eu(
            _credentials(),
            ca_bundle=b"SYNTHETIC-DIFFERENT-CA",
            bootstrap_material=_bootstrap(),
        )
    assert transport.requests == []


@pytest.mark.asyncio
async def test_fresh_auth_requires_usable_bootstrap_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_transport = _QueueTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(missing_transport).authenticate_eu(
            _credentials(),
            ca_bundle=CA_BUNDLE,
        )
    assert missing_transport.requests == []

    monkeypatch.setattr(
        eu_auth,
        "create_eu_bootstrap_ssl_context",
        lambda material, *, now=None: (_ for _ in ()).throw(EuIdentityError("bootstrap_identity_invalid")),
    )
    invalid_transport = _QueueTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(invalid_transport).authenticate_eu(
            _credentials(),
            ca_bundle=CA_BUNDLE,
            bootstrap_material=_bootstrap(),
        )
    assert invalid_transport.requests == []


@pytest.mark.asyncio
async def test_account_mismatch_discards_old_state_and_session_before_login() -> None:
    old_credentials = EuCredentials(
        "old@example.invalid",
        "SYNTHETIC-OLD-PASSWORD",
        "IL",
        _credentials().device_id,
    )
    old_state = EuAuthState(
        account_binding=old_credentials.account_binding,
        country="IL",
        device_id=old_credentials.device_id,
        access_token=ACCESS,
        refresh_token=REFRESH,
        gw_id=GW_ID,
        bean_id=BEAN_ID,
        issued_identity=_identity(),
    )
    old_session = GwmSession("IL", old_credentials.device_id, ACCESS, _issued_context())
    transport = _QueueTransport([_response(code="308103"), _response()])
    client = _client(transport, session=old_session)
    result = await client.authenticate_eu(
        _credentials(),
        state=old_state,
        ca_bundle=CA_BUNDLE,
        bootstrap_material=_bootstrap(),
    )

    assert type(result) is EuVerificationRequired
    assert not client.authenticated
    assert [request.operation for request in transport.requests] == [
        "login",
        "request_verification",
    ]
    assert ACCESS not in transport.requests[0].headers.values()


@pytest.mark.asyncio
async def test_refresh_validation_failure_retires_definitively_rejected_session() -> None:
    old_context = _issued_context()
    state = _state(identity=_identity())
    transport = _QueueTransport(
        [
            _response(status=401),
            _response({"accessToken": NEW_ACCESS, "refreshToken": NEW_REFRESH}),
            _response({"gwId": GW_ID}),
        ]
    )
    client = _client(
        transport,
        session=GwmSession("IL", state.device_id, ACCESS, old_context),
    )
    with pytest.raises(GwmSchemaError):
        await client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
        )
    assert not client.authenticated
    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
    assert len(transport.requests) == 3


@pytest.mark.asyncio
async def test_rejected_auth_attempt_cannot_erase_newer_session_replacement() -> None:
    replacement_token = "SYNTHETIC-CONCURRENT-ACCESS"
    replacement_context = _issued_context()
    transport = _QueueTransport(
        [
            _response(status=401),
            GwmNetworkError(operation="refresh_token"),
            _response([]),
        ],
        delay=0.02,
    )
    state = _state(identity=_identity())
    client = _client(
        transport,
        session=GwmSession("IL", state.device_id, ACCESS, _issued_context()),
    )
    authenticating = asyncio.create_task(
        client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
        )
    )
    async with asyncio.timeout(1):
        while len(transport.requests) < 2:
            await asyncio.sleep(0)

    client.replace_session(
        GwmSession(
            "IL",
            state.device_id,
            replacement_token,
            replacement_context,
        )
    )
    with pytest.raises(GwmNetworkError):
        await authenticating

    assert client.authenticated
    await client.acquire_vehicles()
    read_request = transport.requests[-1]
    assert read_request.headers["accessToken"] == replacement_token
    assert read_request.ssl_context is replacement_context


@pytest.mark.asyncio
async def test_successful_auth_attempt_cannot_overwrite_newer_session_replacement() -> None:
    replacement_token = "SYNTHETIC-CONCURRENT-SUCCESS-ACCESS"
    replacement_context = _issued_context()
    transport = _QueueTransport(
        [
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
            _response([]),
        ],
        delay=0.02,
    )
    state = _state(identity=_identity())
    client = _client(
        transport,
        session=GwmSession("IL", state.device_id, ACCESS, _issued_context()),
    )
    authenticating = asyncio.create_task(
        client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
        )
    )
    async with asyncio.timeout(1):
        while not transport.requests:
            await asyncio.sleep(0)

    client.replace_session(
        GwmSession(
            "IL",
            state.device_id,
            replacement_token,
            replacement_context,
        )
    )
    result = await authenticating
    assert type(result) is EuAuthenticated

    await client.acquire_vehicles()
    read_request = transport.requests[-1]
    assert read_request.headers["accessToken"] == replacement_token
    assert read_request.ssl_context is replacement_context


@pytest.mark.asyncio
async def test_authentication_calls_are_serialized_per_client() -> None:
    identity = _identity()
    transport = _QueueTransport(
        [
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
            _response({"gwId": GW_ID, "beanId": BEAN_ID}),
        ],
        delay=0.01,
    )
    client = _client(transport)
    state = _state(identity=identity)
    first, second = await asyncio.gather(
        client.authenticate_eu(_credentials(), state=state, ca_bundle=CA_BUNDLE),
        client.authenticate_eu(_credentials(), state=state, ca_bundle=CA_BUNDLE),
    )
    assert type(first) is EuAuthenticated
    assert type(second) is EuAuthenticated
    assert transport.max_active == 1


@pytest.mark.asyncio
async def test_deadline_cancels_auth_without_replacing_matching_session() -> None:
    state = _state(identity=_identity())
    old_context = _issued_context()
    transport = _QueueTransport(hang=True)
    client = _client(
        transport,
        session=GwmSession("IL", state.device_id, ACCESS, old_context),
        total_timeout=1,
    )
    with pytest.raises(GwmDeadlineExceededError):
        await client.authenticate_eu(
            _credentials(),
            state=state,
            ca_bundle=CA_BUNDLE,
            timeout=0.01,
        )
    assert client.authenticated


@pytest.mark.asyncio
async def test_finish_authentication_checks_deadline_before_identity_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        eu_auth,
        "create_eu_issued_ssl_context",
        lambda identity, *, ca_bundle, now=None: pytest.fail("identity work began after deadline"),
    )
    loop = asyncio.get_running_loop()

    with pytest.raises(GwmDeadlineExceededError):
        await eu_auth._finish_authentication(
            config=GwmClientConfig("eu"),
            transport=_QueueTransport(),
            credentials=_credentials(),
            state=_state(identity=_identity()),
            ca_bundle=CA_BUNDLE,
            bootstrap_material=None,
            bootstrap_context=None,
            deadline=_Deadline(loop.time() - 1),
            progress=eu_auth._EuAuthProgress(),
        )


@pytest.mark.asyncio
async def test_blocking_crypto_cancellation_waits_for_worker_cleanup() -> None:
    entered = threading.Event()
    release = threading.Event()

    def worker() -> str:
        entered.set()
        release.wait(timeout=5)
        return "cleaned"

    task = asyncio.create_task(eu_auth._blocking_call(worker))
    while not entered.is_set():
        await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0.01)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_authentication_rejects_foreign_region_before_transport() -> None:
    transport = _QueueTransport()
    client = GwmClient(GwmClientConfig("aus"), None, transport=transport)
    with pytest.raises(GwmConfigurationError):
        await client.authenticate_eu(_credentials(), ca_bundle=CA_BUNDLE)
    assert transport.requests == []


@pytest.mark.asyncio
async def test_read_before_authentication_is_rejected_without_transport() -> None:
    transport = _QueueTransport()
    client = _client(transport)
    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
    assert transport.requests == []


@pytest.mark.asyncio
async def test_injected_unexpected_transport_error_is_redacted_without_context() -> None:
    transport = _QueueTransport([RuntimeError(SENSITIVE)])
    with pytest.raises(GwmNetworkError) as raised:
        await _client(transport).authenticate_eu(
            _credentials(),
            state=_state(identity=_identity()),
            ca_bundle=CA_BUNDLE,
        )
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
