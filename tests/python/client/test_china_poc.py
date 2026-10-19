"""Offline reuse-only China discovery/status POC contract tests."""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlsplit

import aiohttp
import pytest

from custom_components.gwm_ora import gwm_client
from custom_components.gwm_ora.gwm_client._protocol import _Deadline
from custom_components.gwm_ora.gwm_client.china_crypto import encrypt_g_app
from custom_components.gwm_ora.gwm_client.china_poc import (
    ChinaPocClient,
    ChinaPocConfig,
    ChinaPocStatus,
    ChinaPocVehicle,
    ChinaReusedSession,
    normalize_china_device_id,
)
from custom_components.gwm_ora.gwm_client.china_transport import (
    ChinaAiohttpTransport,
    _ChinaTransportRequest,
    _ChinaTransportResponse,
)
from custom_components.gwm_ora.gwm_client.config import RequestTimeouts
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier

_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "china_poc_contracts_v1.json"
_CONTRACT = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
_SESSION_VALUES = cast(dict[str, str], _CONTRACT["session"])
_CLOCK = datetime.fromisoformat(cast(str, _CONTRACT["clock"]))
VIN = "LGWTEST0000000001"
OTHER_VIN = "LGWTEST0000000002"
SENSITIVE = "SENSITIVE-china-client-material-019fea1b"


class _Content:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def iter_chunked(self, size: int) -> AsyncIterator[bytes]:
        assert size == 64 * 1024
        for chunk in self.chunks:
            yield chunk


class _Response:
    def __init__(self, body: bytes, *, gzip_body: bool) -> None:
        wire = gzip.compress(body, mtime=0) if gzip_body else body
        self.status = 200
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(wire)),
            **({"Content-Encoding": "gzip"} if gzip_body else {}),
        }
        split = max(1, len(wire) // 3)
        self.content = _Content([wire[:split], wire[split : split * 2], wire[split * 2 :]])


class _Context:
    def __init__(self, response: _Response) -> None:
        self.response = response

    async def __aenter__(self) -> _Response:
        return self.response

    async def __aexit__(self, *_exc_info: object) -> None:
        return None


class _SyntheticServiceSession:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.closed = False
        self.trust_env = False
        self.auto_decompress = False
        self.skip_auto_headers = frozenset({"Accept", "Accept-Encoding", "User-Agent"})
        self.headers: dict[str, str] = {}
        self.cookie_jar = aiohttp.DummyCookieJar()
        self._default_auth: object | None = None
        self._default_proxy: object | None = None
        self._default_proxy_auth: object | None = None
        self._raise_for_status = False
        self._retry_connection = False
        self._middlewares: tuple[object, ...] = ()
        self._trace_configs: list[object] = []
        self._request_class = aiohttp.ClientRequest
        self._response_class = aiohttp.ClientResponse

    def request(self, *args: object, **kwargs: object) -> _Context:
        self.calls.append((args, kwargs))
        return _Context(self.responses.pop(0))

    async def close(self) -> None:
        self.closed = True


class _QueueTransport:
    def __init__(self, outcomes: list[_ChinaTransportResponse | BaseException] | None = None) -> None:
        self.outcomes = list(outcomes or [])
        self.requests: list[_ChinaTransportRequest] = []
        self.deadlines: list[_Deadline] = []
        self.active = 0
        self.max_active = 0
        self.close_calls = 0
        self.hang = False
        self.block_on_request: int | None = None
        self.block_entered = asyncio.Event()
        self.block_release = asyncio.Event()

    async def execute(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _ChinaTransportResponse:
        assert connect_timeout == 10
        assert read_timeout == 20
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.block_on_request == len(self.requests):
                self.block_entered.set()
                await self.block_release.wait()
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        self.close_calls += 1


def _session(**changes: str) -> ChinaReusedSession:
    values = dict(_SESSION_VALUES)
    values.update(changes)
    return ChinaReusedSession(**values)


def _response(value: object, *, status: int = 200, headers: Mapping[str, str] | None = None) -> _ChinaTransportResponse:
    return _ChinaTransportResponse(
        status,
        headers or {"content-type": "application/json"},
        json.dumps(value, separators=(",", ":")).encode(),
    )


def _discovery_response(*, platform: str = "navinfo") -> _ChinaTransportResponse:
    return _response(
        {
            "code": "000000",
            "data": {
                "acquireVehiclesList": [
                    {
                        "vin": VIN,
                        "vehicleId": "synthetic-vehicle",
                        "belongPlatform": platform,
                        "vehicleNetworkType": 2,
                    }
                ]
            },
        }
    )


def _status_response(*, code: str | int = 0) -> _ChinaTransportResponse:
    return _response(
        {
            "header": {"c": code},
            "body": {
                "vehicleSts": {
                    "lastUpdate": "1723456789000",
                    "battSts": {"battSoc": "78"},
                }
            },
        }
    )


def test_versioned_contract_is_explicitly_synthetic() -> None:
    assert _CONTRACT["schema_version"] == 1
    provenance = cast(str, _CONTRACT["provenance"])
    assert "fully synthetic" in provenance
    assert "captured" in provenance


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("01234567-89ab-cdef-0123-456789abcdef", "0123456789abcdef0123456789abcdef"),
        ("abcdef", "abcdef00000000000000000000000000"),
        ("0123456789abcdef0123456789abcdefFFFF", "0123456789abcdef0123456789abcdef"),
    ],
)
def test_device_id_normalization_matches_addon_rule(source: str, expected: str) -> None:
    assert normalize_china_device_id(source) == expected


@pytest.mark.parametrize("value", ["", "-", "not_hex", "g" * 32, "a" * 129, 123])
def test_device_id_normalization_rejects_unsafe_sources(value: object) -> None:
    with pytest.raises(ValueError, match="^china_device_id_invalid$"):
        normalize_china_device_id(value)  # type: ignore[arg-type]


def test_minimal_session_normalizes_identity_and_has_secret_safe_repr() -> None:
    session = _session(device_id="01234567-89ab-cdef-0123-456789abcdef")
    assert session.device_id == _SESSION_VALUES["device_id"]
    rendered = repr(session)
    assert rendered == "ChinaReusedSession()"
    for value in _SESSION_VALUES.values():
        assert value not in rendered


@pytest.mark.parametrize(
    "changes",
    [
        {"g_token": ""},
        {"bean_tech_access_token": "x\ny"},
        {"user_id": "x y"},
        {"bean_id": "x" * (16 * 1024 + 1)},
        {"auto_ai_token_id": ""},
    ],
)
def test_minimal_session_rejects_incomplete_or_header_unsafe_state(changes: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="^china_session_invalid$"):
        _session(**changes)


@pytest.mark.asyncio
async def test_end_to_end_selected_transport_reads_gzip_discovery_and_status_exactly() -> None:
    discovery_body = json.dumps(_CONTRACT["discovery_response"], separators=(",", ":")).encode()
    status_body = json.dumps(_CONTRACT["status_response"], separators=(",", ":")).encode()
    service = _SyntheticServiceSession(
        [_Response(discovery_body, gzip_body=True), _Response(status_body, gzip_body=True)]
    )
    transport = ChinaAiohttpTransport(
        cast(aiohttp.ClientSession, service),
        max_compressed_bytes=4096,
        max_response_bytes=4096,
    )
    client = ChinaPocClient(
        ChinaPocConfig(max_compressed_bytes=4096, max_response_bytes=4096),
        _session(),
        transport=transport,
        clock=lambda: _CLOCK,
    )

    vehicles = await client.acquire_vehicles()
    assert len(vehicles) == 2
    assert all(type(vehicle) is ChinaPocVehicle for vehicle in vehicles)
    status = await client.get_last_status(vehicles[0].identifier)
    assert status == ChinaPocStatus(
        identifier=vehicles[0].identifier,
        last_update_ms=1723456789000,
        section_count=2,
        signal_count=5,
    )
    assert len(service.calls) == 2

    discovery_args, discovery_options = service.calls[0]
    discovery_contract = cast(dict[str, str], _CONTRACT["discovery_request"])
    assert discovery_args[0] == "POST"
    assert str(discovery_args[1]) == discovery_contract["url"]
    assert discovery_options["data"] == discovery_contract["body"].encode()
    discovery_headers = cast(Mapping[str, str], discovery_options["headers"])
    assert discovery_headers["Timestamp"] == discovery_contract["timestamp"]
    assert discovery_headers["Sign"] == discovery_contract["signature"]
    assert discovery_headers["Authorization"] == _SESSION_VALUES["bean_tech_access_token"]
    assert discovery_headers["G-TOKEN"] == _SESSION_VALUES["g_token"]
    assert discovery_headers["Content-Type"] == "application/json; charset=UTF-8"
    assert len(cast(bytes, discovery_options["data"])) == 21

    status_args, status_options = service.calls[1]
    status_contract = cast(dict[str, str], _CONTRACT["status_request"])
    status_url = urlsplit(str(status_args[1]))
    assert status_args[0] == "GET"
    assert str(status_args[1]) == status_contract["url"]
    assert f"{status_url.scheme}://{status_url.netloc}{status_url.path}" == status_contract["url_without_query"]
    assert status_options["data"] is None
    status_headers = cast(Mapping[str, str], status_options["headers"])
    assert status_headers["time"] == status_contract["timestamp"]
    assert status_headers["sign"] == status_contract["signature"]
    wrapper = json.loads(unquote(status_url.query[2:]))
    assert list(wrapper) == ["body", "header"]
    assert wrapper["body"] == {"vin": VIN}
    assert wrapper["header"]["fn"] == status_contract["function"]
    assert wrapper["header"]["ts"] == status_contract["china_timestamp"]
    assert wrapper["header"]["mobileId"] == _SESSION_VALUES["device_id"]
    assert wrapper["header"]["tk"] == _SESSION_VALUES["auto_ai_token_id"]

    await client.aclose()
    assert not service.closed
    assert not transport.closed
    for secret in (*_SESSION_VALUES.values(), VIN, OTHER_VIN):
        assert secret not in repr(client)
        assert secret not in repr(vehicles)
        assert secret not in repr(status)


@pytest.mark.asyncio
async def test_status_requires_previously_discovered_matching_navinfo_vehicle() -> None:
    transport = _QueueTransport([_discovery_response(platform="other-platform")])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    unknown = VehicleIdentifier(VIN)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(unknown)
    vehicles = await client.acquire_vehicles()
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(vehicles[0].identifier)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(VehicleIdentifier(OTHER_VIN))
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_g_app_encrypted_data_and_case_insensitive_fields_are_supported() -> None:
    logical = json.dumps(
        {"AcquireVehiclesList": [{"VIN": VIN, "BelongPlatform": "NaViNfO"}]},
        separators=(",", ":"),
    )
    encrypted = encrypt_g_app(logical, salt=b"12345678")
    transport = _QueueTransport([_response({"CODE": 200, "DATA": encrypted}), _status_response()])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicles = await client.acquire_vehicles()
    status = await client.get_last_status(vehicles[0].identifier)
    assert status.last_update_ms == 1723456789000


@pytest.mark.asyncio
async def test_deep_encrypted_g_app_payload_is_a_schema_error() -> None:
    deeply_nested = "[" * 70 + "0" + "]" * 70
    encrypted = encrypt_g_app(deeply_nested, salt=b"12345678")
    transport = _QueueTransport([_response({"code": "000000", "data": encrypted})])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    with pytest.raises(GwmSchemaError):
        await client.acquire_vehicles()


@pytest.mark.asyncio
async def test_status_identifier_lookup_matches_csharp_case_insensitive_contract() -> None:
    transport = _QueueTransport([_discovery_response(), _status_response()])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    await client.acquire_vehicles()
    status = await client.get_last_status(VehicleIdentifier(VIN.lower()))
    assert status.identifier.value == VIN
    wrapper = json.loads(unquote(urlsplit(transport.requests[1].url).query[2:]))
    assert wrapper["body"]["vin"] == VIN


@pytest.mark.asyncio
async def test_auto_ai_proxy_envelope_is_unwrapped() -> None:
    proxy_status = {
        "code": "000000",
        "data": {
            "header": {"c": "0"},
            "body": {"vehicleSts": {"lastUpdate": 1723456789000, "carStatus": {"odo": "1"}}},
        },
    }
    transport = _QueueTransport([_discovery_response(), _response(proxy_status)])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicle = (await client.acquire_vehicles())[0]
    status = await client.get_last_status(vehicle.identifier)
    assert status.section_count == 1
    assert status.signal_count == 2


@pytest.mark.asyncio
async def test_status_wrapper_uses_exact_dotnet_special_character_escaping() -> None:
    token = "SYNTHETIC+AUTO<&>'`"
    transport = _QueueTransport([_discovery_response(), _status_response()])
    client = ChinaPocClient(
        ChinaPocConfig(),
        _session(auto_ai_token_id=token),
        transport=transport,
        clock=lambda: _CLOCK,
    )
    vehicle = (await client.acquire_vehicles())[0]
    await client.get_last_status(vehicle.identifier)
    request = transport.requests[1]
    expected_payload = (
        '{"body":{"vin":"LGWTEST0000000001"},"header":{"brandType":"gwm",'
        '"cVer":"2.1.5","fn":"GW.M.GET_VEHICLE_STATE","fv":"0202",'
        '"mobileId":"0123456789abcdef0123456789abcdef","osType":"Android",'
        '"osVer":"","rs":"2","ts":"20240812175949123",'
        '"tk":"SYNTHETIC\\u002BAUTO\\u003C\\u0026\\u003E\\u0027\\u0060","v":"1.0"}}'
    )
    assert unquote(urlsplit(request.url).query[2:]) == expected_payload
    assert request.headers["token"] == token


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["1", 1013, "999999"])
async def test_g_app_unknown_and_risk_codes_stop_without_other_calls(code: str | int) -> None:
    transport = _QueueTransport([_response({"code": code, "description": SENSITIVE})])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    with pytest.raises(GwmApiError) as raised:
        await client.acquire_vehicles()
    assert len(transport.requests) == 1
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["1", 7, "999999"])
async def test_auto_ai_nonzero_code_stops_without_exposing_message(code: str | int) -> None:
    transport = _QueueTransport(
        [_discovery_response(), _response({"header": {"c": code, "m": SENSITIVE}, "body": {}})]
    )
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicle = (await client.acquire_vehicles())[0]
    with pytest.raises(GwmApiError) as raised:
        await client.get_last_status(vehicle.identifier)
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_ChinaTransportResponse(401, {}, b"secret"), GwmAuthenticationError),
        (_ChinaTransportResponse(429, {"retry-after": "12"}, b"secret"), GwmRateLimitError),
        (_ChinaTransportResponse(503, {}, b"secret"), GwmHttpError),
    ],
)
async def test_http_failures_are_typed_without_parsing_sensitive_bodies(
    response: _ChinaTransportResponse,
    expected: type[Exception],
) -> None:
    transport = _QueueTransport([response])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    with pytest.raises(expected) as raised:
        await client.acquire_vehicles()
    assert "secret" not in str(raised.value)
    assert "secret" not in repr(raised.value)


@pytest.mark.asyncio
async def test_auto_ai_auth_rejection_revokes_discovered_status_eligibility() -> None:
    transport = _QueueTransport(
        [_discovery_response(), _ChinaTransportResponse(401, {}, b"sensitive")]
    )
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicle = (await client.acquire_vehicles())[0]
    with pytest.raises(GwmAuthenticationError):
        await client.get_last_status(vehicle.identifier)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(vehicle.identifier)
    assert len(transport.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        GwmTlsError(operation="acquire_vehicles"),
        GwmRedirectError(operation="acquire_vehicles"),
        GwmResponseTooLargeError(operation="acquire_vehicles"),
    ],
)
async def test_client_preserves_safe_transport_error_categories(error: Exception) -> None:
    transport = _QueueTransport([error])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    with pytest.raises(type(error)) as raised:
        await client.acquire_vehicles()
    assert raised.value.__suppress_context__


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b"[]",
        b'{"code":"000000","CODE":"000000","data":[]}',
        b'{"code":"000000","data":NaN}',
        b'{"code":"000000","data":{"acquireVehiclesList":[{"vin":"invalid"}]}}',
        b'{"code":"000000","data":{"acquireVehiclesList":[null]}}',
        b"\xff",
    ],
)
async def test_malformed_discovery_responses_fail_as_schema_errors(body: bytes) -> None:
    transport = _QueueTransport([_ChinaTransportResponse(200, {}, body)])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    with pytest.raises(GwmSchemaError):
        await client.acquire_vehicles()


@pytest.mark.asyncio
async def test_duplicate_vehicle_and_malformed_status_fail_closed() -> None:
    duplicate = _response(
        {
            "code": "000000",
            "data": {"acquireVehiclesList": [{"vin": VIN}, {"vin": VIN.lower()}]},
        }
    )
    duplicate_transport = _QueueTransport([duplicate])
    duplicate_client = ChinaPocClient(
        ChinaPocConfig(), _session(), transport=duplicate_transport, clock=lambda: _CLOCK
    )
    with pytest.raises(GwmSchemaError):
        await duplicate_client.acquire_vehicles()

    status_transport = _QueueTransport([_discovery_response(), _response({"header": {"c": 0}, "body": []})])
    status_client = ChinaPocClient(
        ChinaPocConfig(), _session(), transport=status_transport, clock=lambda: _CLOCK
    )
    vehicle = (await status_client.acquire_vehicles())[0]
    with pytest.raises(GwmSchemaError):
        await status_client.get_last_status(vehicle.identifier)

    empty_transport = _QueueTransport([_discovery_response(), _response({"header": {"c": 0}, "body": {}})])
    empty_client = ChinaPocClient(
        ChinaPocConfig(), _session(), transport=empty_transport, clock=lambda: _CLOCK
    )
    empty_vehicle = (await empty_client.acquire_vehicles())[0]
    with pytest.raises(GwmSchemaError):
        await empty_client.get_last_status(empty_vehicle.identifier)


@pytest.mark.asyncio
async def test_failed_rediscovery_revokes_previous_status_eligibility() -> None:
    transport = _QueueTransport([_discovery_response(), GwmNetworkError(operation="acquire_vehicles")])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicle = (await client.acquire_vehicles())[0]
    with pytest.raises(GwmNetworkError):
        await client.acquire_vehicles()
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(vehicle.identifier)
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_concurrent_rediscovery_waits_for_complete_inflight_status_snapshot() -> None:
    transport = _QueueTransport([_discovery_response(), _status_response(), _discovery_response()])
    transport.block_on_request = 2
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    vehicle = (await client.acquire_vehicles())[0]

    status_task = asyncio.create_task(client.get_last_status(vehicle.identifier))
    await transport.block_entered.wait()
    rediscovery_task = asyncio.create_task(client.acquire_vehicles())
    await asyncio.sleep(0)
    transport.block_release.set()

    status = await status_task
    replacement = await rediscovery_task
    assert status.last_update_ms == 1723456789000
    assert replacement[0].identifier == vehicle.identifier
    assert [request.operation for request in transport.requests] == [
        "acquire_vehicles",
        "get_last_status",
        "acquire_vehicles",
    ]


@pytest.mark.asyncio
async def test_close_waits_for_complete_logical_read() -> None:
    transport = _QueueTransport([_discovery_response()])
    transport.block_on_request = 1
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    read_task = asyncio.create_task(client.acquire_vehicles())
    await transport.block_entered.wait()
    close_task = asyncio.create_task(client.aclose())
    await asyncio.sleep(0)
    assert not close_task.done()
    transport.block_release.set()
    vehicles = await read_task
    await close_task
    assert len(vehicles) == 1
    assert client.closed


@pytest.mark.asyncio
async def test_timeout_cancellation_serialization_and_unexpected_errors_are_safe() -> None:
    hanging = _QueueTransport()
    hanging.hang = True
    client = ChinaPocClient(
        ChinaPocConfig(),
        _session(),
        transport=hanging,
        clock=lambda: _CLOCK,
    )
    with pytest.raises(GwmDeadlineExceededError):
        await client.acquire_vehicles(timeout=0.01)

    cancelling = asyncio.create_task(client.acquire_vehicles(timeout=1))
    while len(hanging.requests) < 2:
        await asyncio.sleep(0)
    cancelling.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelling

    broken = _QueueTransport([RuntimeError(SENSITIVE)])
    broken_client = ChinaPocClient(
        ChinaPocConfig(), _session(), transport=broken, clock=lambda: _CLOCK
    )
    with pytest.raises(GwmNetworkError) as raised:
        await broken_client.acquire_vehicles()
    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_client_serializes_reads_and_does_not_close_injected_transport() -> None:
    transport = _QueueTransport([_discovery_response(), _discovery_response()])
    client = ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=lambda: _CLOCK)
    first, second = await asyncio.gather(client.acquire_vehicles(), client.acquire_vehicles())
    assert first == second
    assert transport.max_active == 1
    await client.aclose()
    await client.aclose()
    assert client.closed
    assert transport.close_calls == 0
    with pytest.raises(GwmClosedError):
        await client.acquire_vehicles()


def test_config_clock_and_closed_surface_fail_safely() -> None:
    for value in (True, 0, 16 * 1024 * 1024 + 1):
        with pytest.raises(ValueError, match="^response_limit_invalid$"):
            ChinaPocConfig(max_response_bytes=value)  # type: ignore[arg-type]
    transport = _QueueTransport()
    with pytest.raises(GwmConfigurationError):
        ChinaPocClient(ChinaPocConfig(), _session(), transport=transport, clock=object())  # type: ignore[arg-type]
    assert not hasattr(ChinaPocClient, "request_sms_code")
    assert not hasattr(ChinaPocClient, "login")
    assert not hasattr(ChinaPocClient, "refresh")
    assert not hasattr(ChinaPocClient, "send_command")
    assert not hasattr(ChinaPocClient, "set_charging_plan")
    assert "ChinaPocClient" not in gwm_client.__all__


@pytest.mark.asyncio
async def test_invalid_clock_and_timeout_stop_before_transport() -> None:
    transport = _QueueTransport()
    naive_client = ChinaPocClient(
        ChinaPocConfig(),
        _session(),
        transport=transport,
        clock=lambda: datetime(2024, 1, 1),
    )
    with pytest.raises(GwmConfigurationError):
        await naive_client.acquire_vehicles()
    aware_client = ChinaPocClient(
        ChinaPocConfig(),
        _session(),
        transport=transport,
        clock=lambda: datetime(2024, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(GwmConfigurationError):
        await aware_client.acquire_vehicles(timeout=float("nan"))
    huge_client = ChinaPocClient(
        ChinaPocConfig(timeouts=RequestTimeouts(total=1e308, connect=1, read=1)),
        _session(),
        transport=transport,
        clock=lambda: datetime(2024, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(GwmConfigurationError):
        await huge_client.acquire_vehicles()
    assert transport.requests == []
