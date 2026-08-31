"""Offline typed-client request, response, deadline, and lifecycle tests."""

from __future__ import annotations

import asyncio
import inspect
import json
import math
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

import gwm_client.client as client_module
from gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse
from gwm_client.client import _READ_ENDPOINTS, GwmClient
from gwm_client.config import GwmClientConfig, RequestTimeouts
from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmOptionalEndpointError,
    GwmRateLimitError,
    GwmRoutePolicyError,
    GwmSchemaError,
)
from gwm_client.models import (
    CloudVehicleBasics,
    CloudVehicleStatus,
    GwmSession,
    VehicleIdentifier,
)
from gwm_client.regions import GatewayRole, Region, get_region_protocol
from gwm_client.signing import SignedRequest
from gwm_client.tls import LEGACY_CIPHER_STRING
from gwm_client.transport import AiohttpTransport

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "read_contracts_v1.json"
ACCESS_TOKEN = "SYNTHETIC-TASK4-TOKEN"
SENSITIVE = "SENSITIVE-client-material-019fea1b"


class _RecordingTransport:
    def __init__(
        self,
        responses: list[_TransportResponse] | None = None,
        *,
        error: BaseException | None = None,
        hang: bool = False,
        delay: float = 0,
    ) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.hang = hang
        self.delay = delay
        self.requests: list[_TransportRequest] = []
        self.deadlines: list[_Deadline] = []
        self.timeout_pairs: list[tuple[float, float]] = []
        self.entered = asyncio.Event()
        self.close_calls = 0
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
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.timeout_pairs.append((connect_timeout, read_timeout))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.error is not None:
                raise self.error
            return self.responses.pop(0)
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        self.close_calls += 1


class _FalseyRecordingTransport(_RecordingTransport):
    def __bool__(self) -> bool:
        return False


class _BlockingCloseTransport(_RecordingTransport):
    def __init__(self) -> None:
        super().__init__()
        self.close_started = asyncio.Event()
        self.close_release = asyncio.Event()

    async def aclose(self) -> None:
        self.close_calls += 1
        self.close_started.set()
        await self.close_release.wait()


class _DrainingTransport(_RecordingTransport):
    def __init__(self) -> None:
        super().__init__([_operation_response("acquire_vehicles")])
        self.release = asyncio.Event()

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.timeout_pairs.append((connect_timeout, read_timeout))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            await self.release.wait()
            return self.responses.pop(0)
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        assert self.active == 0
        self.close_calls += 1


class _SynchronousDelayTransport(_RecordingTransport):
    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.timeout_pairs.append((connect_timeout, read_timeout))
        time.sleep(self.delay)
        return self.responses.pop(0)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _tls_context(region: Region) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if region in {Region.EU, Region.RUSSIA}:
        context.set_ciphers(LEGACY_CIPHER_STRING)
    return context


def _session(region: Region, *, token: str = ACCESS_TOKEN) -> GwmSession:
    case = _fixture()["regions"][region.value]
    return GwmSession(
        country=case["country"],
        device_id=case["device_id"],
        access_token=token,
        app_ssl_context=_tls_context(region),
    )


def _response(data: object, *, status: int = 200, headers: Mapping[str, str] | None = None) -> _TransportResponse:
    return _TransportResponse(
        status=status,
        headers=headers or {"Content-Type": "application/json"},
        body=json.dumps(
            {"code": "000000", "description": "synthetic", "data": data},
            separators=(",", ":"),
        ).encode(),
    )


def _operation_response(operation: str) -> _TransportResponse:
    if operation == "acquire_vehicles":
        return _response(
            [
                {
                    "vin": "SYNTHETIC+OPAQUE/ID=",
                    "defaultVehicle": True,
                    "modelName": "Synthetic model",
                    "licenseNumber": "MUST-NOT-BE-RETAINED",
                }
            ]
        )
    if operation == "get_last_status":
        return _response(
            {
                "acquisitionTime": 1_721_462_400_123,
                "updateTime": 1_721_462_401_234,
                "items": [{"code": "SYNTHETIC-CODE", "value": "synthetic"}],
            }
        )
    return _response({"config": {"airConditionerTemperature": "22.0", "airConditionerStatusTime": "15"}})


async def _invoke(client: GwmClient, operation: str) -> object:
    identifier = VehicleIdentifier(_fixture()["identifier"])
    if operation == "acquire_vehicles":
        return await client.acquire_vehicles()
    if operation == "get_last_status":
        return await client.get_last_status(identifier)
    if operation == "get_vehicle_basics":
        return await client.get_vehicle_basics(identifier)
    raise AssertionError(operation)


@pytest.mark.asyncio
async def test_command_tls_context_is_loaded_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(Region.ANZ)
    event_loop_thread = threading.get_ident()
    context_threads: list[int] = []

    def create_context(_purpose: ssl.Purpose) -> ssl.SSLContext:
        context_threads.append(threading.get_ident())
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(client_module.ssl, "create_default_context", create_context)
    client = GwmClient(
        GwmClientConfig(Region.ANZ),
        session,
        transport=_RecordingTransport(),
    )

    assert context_threads == []

    async def action(_session: GwmSession, _deadline: _Deadline) -> object:
        return object()

    await client._execute_authenticated_command(
        "test_command",
        timeout=None,
        action=action,
    )

    assert len(context_threads) == 1
    assert context_threads[0] != event_loop_thread


@pytest.mark.asyncio
async def test_versioned_read_fixture_matches_all_regions_and_operations() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1

    for region_value, region_case in fixture["regions"].items():
        region = Region(region_value)
        for operation_case in fixture["operations"]:
            operation = operation_case["operation"]
            context = _tls_context(region)
            session = GwmSession(
                country=region_case["country"],
                device_id=region_case["device_id"],
                access_token=ACCESS_TOKEN,
                app_ssl_context=context,
            )
            transport = _RecordingTransport([_operation_response(operation)])
            client = GwmClient(GwmClientConfig(region=region), session, transport=transport)

            result = await _invoke(client, operation)

            assert len(transport.requests) == 1
            request = transport.requests[0]
            parsed = urlsplit(request.url)
            assert request.operation == operation
            assert request.method == "GET"
            assert parsed.hostname == region_case["host"]
            assert parsed.path == operation_case["path"]
            assert parsed.query == operation_case["queries"][region_value]
            assert request.ssl_context is context
            assert request.headers["deviceId"] == region_case["normalized_device_id"]
            assert request.headers["iccid"] == region_case["normalized_device_id"]
            assert request.headers["accessToken"] == ACCESS_TOKEN
            assert request.headers["country"] == region_case["country"]
            assert request.headers["Accept"] == "application/json"
            assert any(name.startswith(region_case["signing_prefix"]) for name in request.headers)
            assert all(name not in request.headers for name in region_case["absent_headers"])
            assert ACCESS_TOKEN not in repr(request)
            assert transport.timeout_pairs == [(10.0, 20.0)]
            assert transport.deadlines[0].expires_at > asyncio.get_running_loop().time()
            if operation == "acquire_vehicles":
                assert result[0].identifier.value == fixture["identifier"]
            elif operation == "get_last_status":
                assert isinstance(result, CloudVehicleStatus)
            else:
                assert isinstance(result, CloudVehicleBasics)
            await client.aclose()
            assert transport.close_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "expected_query"),
    [
        ("acquire_vehicles", ""),
        (
            "get_last_status",
            "vin=SYNTHETIC%2BOPAQUE%2FID%3D",
        ),
        (
            "get_vehicle_basics",
            "flag=true&vin=SYNTHETIC%2BOPAQUE%2FID%3D",
        ),
    ],
)
async def test_current_anz_session_uses_native_vehicle_read_signing_policy(
    operation: str,
    expected_query: str,
) -> None:
    device_id = "0123456789abcdef0123456789abcdef"
    transport = _RecordingTransport([_operation_response(operation)])
    client = GwmClient(
        GwmClientConfig(
            Region.ANZ,
            anz_authentication_method="current_v2",
        ),
        GwmSession(
            country="AU",
            device_id=device_id,
            access_token=ACCESS_TOKEN,
            app_ssl_context=_tls_context(Region.ANZ),
            gw_id="SYNTHETIC-GW-ID",
        ),
        transport=transport,
    )

    await _invoke(client, operation)

    request = transport.requests[0]
    parsed = urlsplit(request.url)
    assert parsed.hostname == "aus-h5-gateway.gwmcloud.com"
    assert parsed.query == expected_query
    assert request.headers["deviceId"] == request.headers["iccid"] == device_id
    assert request.headers["accessToken"] == ACCESS_TOKEN
    assert request.headers["gwId"] == "SYNTHETIC-GW-ID"
    assert request.headers["language"] == "en"
    assert request.headers["cVer"] == "1.0.6"
    assert request.headers["ip"] == "0.0.0.0"
    assert request.headers["secVersion"] == "2.0"
    assert len(request.headers["bt-auth-nonce"]) == 16


def test_current_anz_session_requires_the_access_token_and_gw_id_pair() -> None:
    with pytest.raises(GwmConfigurationError):
        GwmClient(
            GwmClientConfig(
                Region.ANZ,
                anz_authentication_method="current_v2",
            ),
            GwmSession(
                country="AU",
                device_id="0123456789abcdef0123456789abcdef",
                access_token=ACCESS_TOKEN,
                app_ssl_context=_tls_context(Region.ANZ),
            ),
            transport=_RecordingTransport([]),
        )


def test_only_closed_operation_surfaces_and_typed_public_methods_exist() -> None:
    assert set(_READ_ENDPOINTS) == {
        "acquire_vehicles",
        "get_last_status",
        "get_vehicle_basics",
    }
    public_coroutines = {
        name for name, value in inspect.getmembers(GwmClient, inspect.iscoroutinefunction) if not name.startswith("_")
    }
    assert public_coroutines == {
        "aclose",
        "acquire_vehicles",
        "authenticate_anz",
        "authenticate_eu",
        "authenticate_russia",
        "get_charging_plan",
        "get_last_status",
        "get_remote_command_results",
        "get_vehicle_basics",
        "send_close_windows_command",
        "send_climate_command",
        "send_lock_command",
        "set_charging_plan",
        "update_climate_defaults",
    }
    for forbidden in (
        "request",
        "send",
        "login",
        "refresh_token",
        "send_command",
    ):
        assert not hasattr(GwmClient, forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "signed",
    [
        SignedRequest(
            "GET",
            "http://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            {},
            None,
        ),
        SignedRequest(
            "GET",
            "https://evil.example.invalid/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            {},
            None,
        ),
        SignedRequest(
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/user/loginAccount",
            {},
            None,
        ),
        SignedRequest(
            "GET",
            "https://eu-app-gateway.gwmcloud.com:443/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            {},
            None,
        ),
        SignedRequest(
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles?extra=1",
            {},
            None,
        ),
        SignedRequest(
            "POST",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            {},
            "{}",
        ),
        SignedRequest(
            "GET",
            "https://eu-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
            {"accessToken": SENSITIVE},
            None,
        ),
    ],
)
async def test_post_signing_route_validation_blocks_every_unsafe_shape(
    monkeypatch: pytest.MonkeyPatch,
    signed: SignedRequest,
) -> None:
    transport = _RecordingTransport([_operation_response("acquire_vehicles")])
    client = GwmClient(GwmClientConfig(region=Region.EU), _session(Region.EU), transport=transport)
    monkeypatch.setattr("gwm_client.client.sign_request", lambda *_args, **_kwargs: signed)

    with pytest.raises(GwmRoutePolicyError):
        await client.acquire_vehicles()
    assert transport.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (401, {}, GwmAuthenticationError),
        (403, {}, GwmAuthenticationError),
        (429, {"Retry-After": "60"}, GwmRateLimitError),
        (500, {}, GwmHttpError),
        (418, {}, GwmHttpError),
    ],
)
async def test_http_statuses_map_to_secret_safe_categories(
    status: int,
    headers: Mapping[str, str],
    expected: type[Exception],
) -> None:
    transport = _RecordingTransport([_TransportResponse(status=status, headers=headers, body=SENSITIVE.encode())])
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(expected) as raised:
        await client.acquire_vehicles()
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    if isinstance(raised.value, GwmRateLimitError):
        assert raised.value.retry_after_seconds == 60


@pytest.mark.asyncio
async def test_oversized_retry_after_remains_bounded_rate_limit_error() -> None:
    transport = _RecordingTransport([_TransportResponse(429, {"Retry-After": "9" * 5000}, b"")])
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmRateLimitError) as raised:
        await client.acquire_vehicles()
    assert raised.value.retry_after_seconds is None


@pytest.mark.asyncio
async def test_api_error_discards_cloud_description_and_body() -> None:
    body = json.dumps({"code": "607501", "description": SENSITIVE, "data": {"raw": SENSITIVE}}).encode()
    transport = _RecordingTransport([_TransportResponse(200, {}, body)])
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmApiError) as raised:
        await client.acquire_vehicles()
    assert raised.value.api_code == "607501"
    assert SENSITIVE not in repr(raised.value)
    assert SENSITIVE not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"\xff",
        b'{"code":"000000","code":"000000","data":[]}',
        b'{"code":"000000","data":NaN}',
        b'{"code":"000000"}',
        b'{"code":"000000","data":{}}',
    ],
)
async def test_malformed_envelopes_and_typed_payloads_are_schema_errors(body: bytes) -> None:
    transport = _RecordingTransport([_TransportResponse(200, {}, body)])
    client = GwmClient(GwmClientConfig(region=Region.EU), _session(Region.EU), transport=transport)

    with pytest.raises(GwmSchemaError) as raised:
        await client.acquire_vehicles()
    decoded = body.decode("utf-8", errors="ignore")
    if decoded:
        assert decoded not in repr(raised.value)
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_numeric_zero_is_not_protocol_success() -> None:
    body = b'{"code":0,"description":"not-success","data":[]}'
    transport = _RecordingTransport([_TransportResponse(200, {}, body)])
    client = GwmClient(GwmClientConfig(region=Region.RUSSIA), _session(Region.RUSSIA), transport=transport)

    with pytest.raises(GwmApiError) as raised:
        await client.acquire_vehicles()
    assert raised.value.api_code is None


@pytest.mark.asyncio
async def test_total_deadline_covers_transport_and_maps_timeout_without_context() -> None:
    transport = _RecordingTransport(hang=True)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmDeadlineExceededError) as raised:
        await client.acquire_vehicles(timeout=0.01)
    assert raised.value.__context__ is None
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_total_deadline_covers_synchronous_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def slow_decoder(
        data: object,
        *,
        allow_numbers_for_strings: bool,
    ) -> tuple[object, ...]:
        nonlocal called
        assert data == []
        assert not allow_numbers_for_strings
        called = True
        time.sleep(0.075)
        return ()

    monkeypatch.setattr(client_module, "parse_cloud_vehicles", slow_decoder)
    transport = _RecordingTransport([_response([])])
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmDeadlineExceededError):
        await client.acquire_vehicles(timeout=0.05)
    assert called


@pytest.mark.asyncio
async def test_deadline_precedes_synchronous_decoder_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_invalid_decoder(
        _data: object,
        *,
        allow_numbers_for_strings: bool,
    ) -> tuple[object, ...]:
        assert not allow_numbers_for_strings
        time.sleep(0.075)
        raise ValueError("sensitive-decoder-detail")

    monkeypatch.setattr(client_module, "parse_cloud_vehicles", slow_invalid_decoder)
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=_RecordingTransport([_response([])]),
    )

    with pytest.raises(GwmDeadlineExceededError):
        await client.acquire_vehicles(timeout=0.05)


@pytest.mark.asyncio
async def test_deadline_precedes_synchronous_envelope_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_invalid_envelope(
        _response_value: _TransportResponse,
        *,
        operation: str,
    ) -> object:
        assert operation == "acquire_vehicles"
        time.sleep(0.075)
        raise GwmSchemaError(operation=operation)

    monkeypatch.setattr(client_module, "_decode_envelope", slow_invalid_envelope)
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=_RecordingTransport([_response([])]),
    )

    with pytest.raises(GwmDeadlineExceededError):
        await client.acquire_vehicles(timeout=0.05)


@pytest.mark.asyncio
async def test_nonfinite_exponent_is_rejected_even_in_ignored_field() -> None:
    response = _TransportResponse(
        status=200,
        headers={"Content-Type": "application/json"},
        body=(b'{"code":"000000","data":[{"vin":"SYNTHETIC-ID","ignored":1e999}]}'),
    )
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=_RecordingTransport([response]),
    )

    with pytest.raises(GwmSchemaError):
        await client.acquire_vehicles()


@pytest.mark.asyncio
async def test_expired_deadline_precedes_invalid_late_transport_response() -> None:
    invalid = _TransportResponse(status=200, headers={}, body=b"not-json")
    transport = _SynchronousDelayTransport([invalid], delay=0.075)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmDeadlineExceededError):
        await client.acquire_vehicles(timeout=0.05)


@pytest.mark.asyncio
async def test_external_cancellation_propagates_unchanged() -> None:
    transport = _RecordingTransport(hang=True)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)
    task = asyncio.create_task(client.acquire_vehicles())
    await transport.entered.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_account_requests_do_not_overlap() -> None:
    transport = _RecordingTransport(
        [_operation_response("acquire_vehicles"), _operation_response("acquire_vehicles")],
        delay=0.01,
    )
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    await asyncio.gather(client.acquire_vehicles(), client.acquire_vehicles())

    assert transport.max_active == 1
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_session_replacement_affects_only_future_requests_and_is_redacted() -> None:
    transport = _RecordingTransport([_operation_response("acquire_vehicles"), _operation_response("acquire_vehicles")])
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ, token="SYNTHETIC-FIRST-TOKEN"),
        transport=transport,
    )
    await client.acquire_vehicles()
    replacement = _session(Region.ANZ, token="SYNTHETIC-SECOND-TOKEN")
    client.replace_session(replacement)
    await client.acquire_vehicles()

    assert transport.requests[0].headers["accessToken"] == "SYNTHETIC-FIRST-TOKEN"
    assert transport.requests[1].headers["accessToken"] == "SYNTHETIC-SECOND-TOKEN"
    assert "SYNTHETIC-SECOND-TOKEN" not in repr(replacement)


@pytest.mark.asyncio
async def test_client_lifecycle_is_idempotent_and_respects_transport_ownership() -> None:
    external = _RecordingTransport([_operation_response("acquire_vehicles")])
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=external)
    await client.aclose()
    await client.aclose()
    assert client.closed
    assert external.close_calls == 0
    with pytest.raises(GwmClosedError):
        await client.acquire_vehicles()
    with pytest.raises(GwmClosedError):
        client.replace_session(_session(Region.ANZ))

    owned = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ))
    transport = owned._transport
    assert isinstance(transport, AiohttpTransport)
    await owned.aclose()
    assert transport.closed


@pytest.mark.asyncio
async def test_falsey_external_transport_is_not_replaced_or_owned() -> None:
    transport = _FalseyRecordingTransport([_operation_response("acquire_vehicles")])
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=transport,
    )

    await client.acquire_vehicles()
    await client.aclose()
    assert client._transport is transport
    assert transport.close_calls == 0


@pytest.mark.asyncio
async def test_cancelled_owned_transport_close_can_be_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _BlockingCloseTransport()
    monkeypatch.setattr(AiohttpTransport, "create_owned", lambda **_kwargs: transport)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ))
    closing = asyncio.create_task(client.aclose())
    await transport.close_started.wait()
    closing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closing

    assert not client.closed
    transport.close_release.set()
    await client.aclose()
    assert client.closed
    assert transport.close_calls == 2


@pytest.mark.asyncio
async def test_close_drains_active_request_and_rejects_queued_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _DrainingTransport()
    monkeypatch.setattr(AiohttpTransport, "create_owned", lambda **_kwargs: transport)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ))
    active = asyncio.create_task(client.acquire_vehicles())
    await transport.entered.wait()
    queued = asyncio.create_task(client.acquire_vehicles())
    await asyncio.sleep(0)
    closing = asyncio.create_task(client.aclose())
    await asyncio.sleep(0)

    assert not closing.done()
    transport.release.set()
    assert await active
    with pytest.raises(GwmClosedError):
        await queued
    await closing
    assert client.closed
    assert len(transport.requests) == 1
    assert transport.close_calls == 1


@pytest.mark.asyncio
async def test_forged_endpoint_is_rejected_before_transport() -> None:
    transport = _RecordingTransport()
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)
    endpoint = _READ_ENDPOINTS["acquire_vehicles"]
    forged = replace(endpoint, path="globalapp/vehicle/forgedRead")

    with pytest.raises(GwmRoutePolicyError):
        await client._execute(forged, identifier=None, timeout=None)
    assert transport.requests == []


@pytest.mark.asyncio
async def test_forged_identifier_encoding_is_rejected_before_transport() -> None:
    class ForgedIdentifier(VehicleIdentifier):
        @property
        def encoded(self) -> str:
            return "SYNTHETIC-ID&extra=forged"

    transport = _RecordingTransport()
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(ForgedIdentifier("SYNTHETIC-ID"))
    with pytest.raises(GwmRoutePolicyError):
        await client.get_vehicle_basics(object())  # type: ignore[arg-type]
    assert transport.requests == []


def test_client_rejects_mutable_config_and_session_ducks() -> None:
    class MutableConfig:
        region = Region.ANZ
        timeouts = RequestTimeouts()
        max_response_bytes = 1024

    class MutableSession:
        country = "AU"
        device_id = "feedface"
        access_token = ACCESS_TOKEN
        app_ssl_context = _tls_context(Region.ANZ)

    with pytest.raises(GwmConfigurationError):
        GwmClient(MutableConfig(), _session(Region.ANZ), transport=_RecordingTransport())  # type: ignore[arg-type]
    with pytest.raises(GwmConfigurationError):
        GwmClient(
            GwmClientConfig(region=Region.ANZ),
            MutableSession(),  # type: ignore[arg-type]
            transport=_RecordingTransport(),
        )


def test_session_validation_requires_exact_region_country_headers_and_tls() -> None:
    before = ssl.create_default_context()
    fingerprint = (
        before.security_level,
        before.minimum_version,
        before.maximum_version,
        before.check_hostname,
        before.verify_mode,
    )
    invalid_cases = [
        GwmSession("IL", "feedface", ACCESS_TOKEN, _tls_context(Region.ANZ)),
        GwmSession("AU", "feedface", ACCESS_TOKEN, _tls_context(Region.EU)),
        GwmSession("au", "feedface", ACCESS_TOKEN, _tls_context(Region.ANZ)),
        GwmSession("AU", "not-a-device", ACCESS_TOKEN, _tls_context(Region.ANZ)),
        GwmSession("AU", "feedface", "token with spaces", _tls_context(Region.ANZ)),
    ]

    for session in invalid_cases:
        with pytest.raises(GwmConfigurationError) as raised:
            GwmClient(GwmClientConfig(region=Region.ANZ), session, transport=_RecordingTransport())
        assert ACCESS_TOKEN not in repr(raised.value)

    after = ssl.create_default_context()
    assert (
        after.security_level,
        after.minimum_version,
        after.maximum_version,
        after.check_hostname,
        after.verify_mode,
    ) == fingerprint


@pytest.mark.asyncio
async def test_mutated_tls_policy_is_revalidated_before_every_request() -> None:
    transport = _RecordingTransport([_operation_response("acquire_vehicles")])
    context = _tls_context(Region.ANZ)
    session = GwmSession("AU", "feedface", ACCESS_TOKEN, context)
    client = GwmClient(GwmClientConfig(region=Region.ANZ), session, transport=transport)
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

    with pytest.raises(GwmConfigurationError):
        await client.acquire_vehicles()
    assert transport.requests == []


@pytest.mark.asyncio
async def test_unexpected_transport_error_is_sanitized_without_context() -> None:
    transport = _RecordingTransport(error=RuntimeError(SENSITIVE))
    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)

    with pytest.raises(GwmNetworkError) as raised:
        await client.acquire_vehicles()
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_typed_transport_error_is_reconstructed_without_sensitive_cause() -> None:
    try:
        raise RuntimeError(SENSITIVE)
    except RuntimeError as source:
        try:
            raise GwmNetworkError(operation="acquire_vehicles") from source
        except GwmNetworkError as tainted:
            transport = _RecordingTransport(error=tainted)

    client = GwmClient(GwmClientConfig(region=Region.ANZ), _session(Region.ANZ), transport=transport)
    with pytest.raises(GwmNetworkError) as raised:
        await client.acquire_vehicles()
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize("timeout", [0, -1, math.inf, math.nan, True, 31])
@pytest.mark.asyncio
async def test_per_call_timeout_override_is_bounded(timeout: float) -> None:
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ, timeouts=RequestTimeouts(total=30)),
        _session(Region.ANZ),
        transport=_RecordingTransport(),
    )
    with pytest.raises(GwmConfigurationError):
        await client.acquire_vehicles(timeout=timeout)


def test_region_fixture_tls_role_matches_protocol() -> None:
    fixture = _fixture()
    for value, case in fixture["regions"].items():
        protocol = get_region_protocol(value)
        assert protocol.gateway(GatewayRole.APP_V1).tls_mode.value == case["tls_mode"]


def _api_failure(code: str) -> _TransportResponse:
    return _TransportResponse(
        status=200,
        headers={"Content-Type": "application/json"},
        body=json.dumps(
            {"code": code, "description": SENSITIVE, "data": {"raw": SENSITIVE}},
            separators=(",", ":"),
        ).encode(),
    )


@pytest.mark.asyncio
async def test_exact_anz_basics_607099_is_typed_optional_endpoint_failure() -> None:
    transport = _RecordingTransport([_api_failure("607099")])
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=transport,
    )

    with pytest.raises(GwmOptionalEndpointError) as raised:
        await client.get_vehicle_basics(VehicleIdentifier(_fixture()["identifier"]))
    assert raised.value.api_code == "607099"
    assert raised.value.operation == "get_vehicle_basics"
    assert SENSITIVE not in repr(raised.value)
    assert client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("region", "operation", "code"),
    [
        (Region.ANZ, "get_vehicle_basics", "607098"),
        (Region.ANZ, "acquire_vehicles", "607099"),
        (Region.ANZ, "get_last_status", "607099"),
        (Region.EU, "get_vehicle_basics", "607099"),
        (Region.RUSSIA, "get_vehicle_basics", "607099"),
    ],
)
async def test_optional_basics_classification_is_exactly_region_operation_and_code_scoped(
    region: Region,
    operation: str,
    code: str,
) -> None:
    transport = _RecordingTransport([_api_failure(code)])
    client = GwmClient(GwmClientConfig(region=region), _session(region), transport=transport)

    with pytest.raises(GwmApiError) as raised:
        await _invoke(client, operation)
    assert type(raised.value) is GwmApiError
    assert raised.value.api_code == code
    assert client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "code"),
    [
        ("get_vehicle_basics", " 607099 "),
        ("acquire_vehicles", " 607501 "),
    ],
)
async def test_anz_regional_application_codes_require_an_exact_raw_string(
    operation: str,
    code: str,
) -> None:
    transport = _RecordingTransport([_api_failure(code)])
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=transport,
    )

    with pytest.raises(GwmApiError) as raised:
        await _invoke(client, operation)
    assert type(raised.value) is GwmApiError
    assert raised.value.api_code == code.strip()
    assert client.authenticated


@pytest.mark.asyncio
async def test_exact_anz_read_607501_retires_matching_session() -> None:
    transport = _RecordingTransport([_api_failure("607501")])
    client = GwmClient(
        GwmClientConfig(region=Region.ANZ),
        _session(Region.ANZ),
        transport=transport,
    )

    with pytest.raises(GwmAuthenticationError) as raised:
        await client.acquire_vehicles()
    assert raised.value.api_code == "607501"
    assert SENSITIVE not in repr(raised.value)
    assert not client.authenticated

    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("region", "code"),
    [
        (Region.ANZ, "607502"),
        (Region.EU, "607501"),
        (Region.RUSSIA, "607501"),
    ],
)
async def test_read_authentication_retirement_is_exactly_anz_607501(
    region: Region,
    code: str,
) -> None:
    transport = _RecordingTransport([_api_failure(code)])
    client = GwmClient(GwmClientConfig(region=region), _session(region), transport=transport)

    with pytest.raises(GwmApiError) as raised:
        await client.acquire_vehicles()
    assert type(raised.value) is GwmApiError
    assert raised.value.api_code == code
    assert client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_russia_http_authentication_read_retires_matching_session(status: int) -> None:
    transport = _RecordingTransport([_TransportResponse(status, {}, b"")])
    client = GwmClient(
        GwmClientConfig(region=Region.RUSSIA),
        _session(Region.RUSSIA),
        transport=transport,
    )

    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
    assert not client.authenticated

    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("region", [Region.ANZ, Region.RUSSIA])
async def test_rejected_read_cannot_erase_newer_session_replacement(region: Region) -> None:
    replacement_token = "SYNTHETIC-CONCURRENT-READ-TOKEN"
    replacement_context = _tls_context(region)
    rejection = _api_failure("607501") if region is Region.ANZ else _TransportResponse(401, {}, b"")
    transport = _RecordingTransport(
        [rejection, _operation_response("acquire_vehicles")],
        delay=0.02,
    )
    client = GwmClient(
        GwmClientConfig(region=region),
        _session(region),
        transport=transport,
    )
    reading = asyncio.create_task(client.acquire_vehicles())
    async with asyncio.timeout(1):
        await transport.entered.wait()

    original = _session(region)
    client.replace_session(
        GwmSession(
            original.country,
            original.device_id,
            replacement_token,
            replacement_context,
        )
    )
    with pytest.raises(GwmAuthenticationError):
        await reading

    assert client.authenticated
    await client.acquire_vehicles()
    replacement_request = transport.requests[-1]
    assert replacement_request.headers["accessToken"] == replacement_token
    assert replacement_request.ssl_context is replacement_context
