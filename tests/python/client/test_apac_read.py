"""Synthetic tests: the isolated read client uses only its injected transport."""

import asyncio
import json
import ssl
from datetime import UTC, datetime

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.errors import GwmClosedError, GwmDeadlineExceededError, GwmSchemaError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.models import CloudVehicleBasics
from custom_components.gwm_ora.gwm_client.regions import TlsMode
from custom_components.gwm_ora.gwm_client.snapshots import map_vehicle_snapshot


class FakeTransport:
    def __init__(self, *, payloads: dict[str, object] | None = None, error: BaseException | None = None) -> None:
        """Record read operations and optionally inject synthetic data or errors."""
        self.operations: list[str] = []
        self.requests = []
        self.payloads = payloads or {}
        self.error = error

    async def execute(self, request, **_kwargs):
        """Return typed synthetic read payloads without opening a connection."""
        self.operations.append(request.operation)
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        data = [{"vin": "SYNTHETIC-VEHICLE"}] if request.operation == "acquire_vehicles" else {"items": []}
        data = self.payloads.get(request.operation, data)
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

    async def aclose(self) -> None:
        """Satisfy the interface without closing any caller-owned resources."""
        pass


def _client(transport: FakeTransport, *, country: str = "PK", owns_transport: bool = False) -> ApacReadClient:
    """Create an isolated read client with a synthetic validated context."""
    material = ApacMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key",
        "synthetic-secret",
    )
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    session = ApacReadSession("a" * 32, "synthetic-token", context, country=country)
    return ApacReadClient(material=material, session=session, transport=transport, owns_transport=owns_transport)


@pytest.mark.asyncio
async def test_discovery_and_status_use_only_injected_transport() -> None:
    """Route discovery and status through the injected transport only."""
    transport = FakeTransport()
    client = _client(transport)
    vehicles = await client.acquire_vehicles()
    assert vehicles[0].identifier.value == "SYNTHETIC-VEHICLE"
    status = await client.get_last_status("SYNTHETIC-VEHICLE")
    assert status.items == ()
    assert transport.operations == ["acquire_vehicles", "get_last_status"]


@pytest.mark.asyncio
async def test_write_operation_fails_before_transport() -> None:
    """Reject a write operation before any transport dispatch."""
    transport = FakeTransport()
    client = _client(transport)
    with pytest.raises(ValueError, match="^apac_operation_not_supported$"):
        await client._read("set_charging_plan")  # type: ignore[arg-type]
    assert transport.operations == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation,payload",
    [
        ("acquire_vehicles", {}),
        ("get_last_status", {"items": "private-value"}),
        ("get_vehicle_basics", {"config": "private-value"}),
    ],
)
async def test_malformed_read_payloads_use_redacted_client_errors(operation: str, payload: object) -> None:
    """Expose the same typed schema contract as the existing regional client."""
    transport = FakeTransport(payloads={operation: payload})
    client = _client(transport)
    with pytest.raises(GwmSchemaError) as error:
        action = getattr(client, operation)
        await action(*(() if operation == "acquire_vehicles" else ("SYNTHETIC-VEHICLE",)))
    assert error.value.operation == operation
    assert "private" not in str(error.value)
    assert transport.operations == [operation]


@pytest.mark.asyncio
async def test_timeout_uses_the_client_deadline_error_without_retry() -> None:
    """Translate timeouts without exposing transport details or retrying."""
    transport = FakeTransport(error=TimeoutError("private-value"))
    with pytest.raises(GwmDeadlineExceededError) as error:
        await _client(transport).acquire_vehicles()
    assert error.value.operation == "acquire_vehicles"
    assert "private" not in str(error.value)
    assert transport.operations == ["acquire_vehicles"]


@pytest.mark.asyncio
async def test_read_cancellation_propagates_without_retry() -> None:
    """Preserve task cancellation instead of reporting it as a timeout."""
    transport = FakeTransport(error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await _client(transport).acquire_vehicles()
    assert transport.operations == ["acquire_vehicles"]


@pytest.mark.asyncio
async def test_queued_reads_are_signed_only_after_the_lock_is_acquired(monkeypatch) -> None:
    """Build timestamps and nonces immediately before transport dispatch."""
    import custom_components.gwm_ora.gwm_client.apac_read as reads

    client = _client(FakeTransport())
    original = reads.prepare_apac_request
    prepared = []

    def prepare(**kwargs):
        """Observe preparation without changing the real request builder."""
        prepared.append(kwargs["operation"])
        return original(**kwargs)

    monkeypatch.setattr(reads, "prepare_apac_request", prepare)
    await client._lock.acquire()
    task = asyncio.create_task(client.acquire_vehicles())
    try:
        await asyncio.sleep(0)
        assert prepared == []
    finally:
        client._lock.release()
        await task
    assert prepared == ["acquire_vehicles"]


@pytest.mark.asyncio
@pytest.mark.parametrize("country", ["TH", "MY", "ID", "PK"])
async def test_basics_preserves_numeric_and_string_climate_values(country: str) -> None:
    """Assert APAC's numeric tolerance through the actual basics read method."""
    transport = FakeTransport(
        payloads={
            "get_vehicle_basics": {
                "config": {
                    "airConditionerTemperature": 23,
                    "airConditionerStatusTime": 0,
                    "engineStatusTime": "15",
                    "unrelatedPrivateField": "synthetic-private",
                }
            }
        }
    )
    basics = await _client(transport, country=country).get_vehicle_basics("SYNTHETIC-VEHICLE")
    assert basics.climate is not None
    assert basics.climate.temperature == "23"
    assert basics.climate.operation_time == "0"
    assert basics.climate.engine_operation_time == "15"
    assert "synthetic-private" not in repr(basics)
    assert transport.operations == ["get_vehicle_basics"]
    assert transport.requests[0].headers["country"] == country
    assert transport.requests[0].url.endswith("?vin=SYNTHETIC-VEHICLE&flag=true")


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"config": None}])
async def test_missing_basics_configuration_stays_unknown(payload: object) -> None:
    """Do not manufacture climate settings when the cloud omits them."""
    transport = FakeTransport(payloads={"get_vehicle_basics": payload})
    assert (await _client(transport).get_vehicle_basics("SYNTHETIC-VEHICLE")).climate is None


@pytest.mark.asyncio
@pytest.mark.parametrize("config", [[], 23, True, "synthetic-private"])
async def test_malformed_basics_configuration_fails_closed(config: object) -> None:
    """Reject config shapes that cannot represent climate settings."""
    transport = FakeTransport(payloads={"get_vehicle_basics": {"config": config}})
    with pytest.raises(GwmSchemaError) as error:
        await _client(transport).get_vehicle_basics("SYNTHETIC-VEHICLE")
    assert error.value.operation == "get_vehicle_basics"
    assert "synthetic-private" not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("country", ["TH", "MY", "ID", "PK"])
@pytest.mark.parametrize("soc", [0, "50.5", 80])
async def test_nonempty_status_preserves_values_and_reaches_the_shared_snapshot(country: str, soc: object) -> None:
    """Verify synthetic status semantics through the client and snapshot mapper."""
    transport = FakeTransport(
        payloads={
            "get_last_status": {
                "deviceId": 12345,
                "acquisitionTime": "1700000000123",
                "updateTime": 1700000000456,
                "latitude": "0",
                "longitude": "34.75",
                "items": [
                    {"code": 2013021, "value": soc, "unit": "%"},
                    {"code": "2011501", "value": "125.5", "unit": "km"},
                ],
            }
        }
    )
    client = _client(transport, country=country)
    vehicle = (await client.acquire_vehicles())[0]
    status = await client.get_last_status(vehicle.identifier.value)
    assert status.device_id == "12345"
    assert status.acquisition_time_ms == 1700000000123
    assert status.update_time_ms == 1700000000456
    assert status.latitude == 0.0
    assert status.longitude == 34.75
    assert [(item.code, item.value, item.unit) for item in status.items] == [
        ("2013021", soc, "%"),
        ("2011501", "125.5", "km"),
    ]
    snapshot = map_vehicle_snapshot(
        vehicle,
        status,
        CloudVehicleBasics(),
        refreshed_at=datetime(2026, 10, 30, tzinfo=UTC),
        remote_commands_available=False,
        charging_control_available=False,
    )
    assert snapshot.values.soc == float(soc)
    assert snapshot.values.range_km == 125.5
    assert snapshot.raw_items["2013021"].unit == "%"
    assert snapshot.raw_items["2011501"].value == "125.5"
    assert not snapshot.capabilities.remote_commands
    assert not snapshot.capabilities.charging_control
    assert transport.requests[-1].headers["country"] == country


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"items": None}, {"items": []}])
async def test_missing_status_items_remain_unknown(payload: object) -> None:
    """Keep an omitted signal unknown rather than treating it as a zero."""
    transport = FakeTransport(payloads={"get_last_status": payload})
    client = _client(transport)
    vehicle = (await client.acquire_vehicles())[0]
    status = await client.get_last_status(vehicle.identifier.value)
    snapshot = map_vehicle_snapshot(
        vehicle,
        status,
        CloudVehicleBasics(),
        refreshed_at=datetime(2026, 10, 30, tzinfo=UTC),
        remote_commands_available=False,
    )
    assert status.items == ()
    assert snapshot.values.soc is None
    assert snapshot.values.range_km is None


@pytest.mark.asyncio
@pytest.mark.parametrize("owns_transport", [False, True])
async def test_closing_drains_the_active_read_and_rejects_queued_requests(owns_transport: bool) -> None:
    """No queued read may dispatch after shutdown starts, even on borrowed transports."""
    entered = asyncio.Event()
    release = asyncio.Event()
    close_calls = []

    class Transport(FakeTransport):
        async def execute(self, request, **kwargs):
            """Hold one active request until shutdown is waiting."""
            entered.set()
            await release.wait()
            return await super().execute(request, **kwargs)

        async def aclose(self):
            """Record ownership-sensitive disposal without network activity."""
            close_calls.append("closed")

    transport = Transport()
    client = _client(transport, owns_transport=owns_transport)
    active = asyncio.create_task(client.acquire_vehicles())
    await entered.wait()
    queued = asyncio.create_task(client.acquire_vehicles())
    await asyncio.sleep(0)
    closing = asyncio.create_task(client.aclose())
    await asyncio.sleep(0)
    assert not closing.done()
    release.set()
    await active
    with pytest.raises(GwmClosedError):
        await queued
    await closing
    await client.aclose()
    with pytest.raises(GwmClosedError):
        await client.acquire_vehicles()
    assert transport.operations == ["acquire_vehicles"]
    assert close_calls == (["closed"] if owns_transport else [])


@pytest.mark.asyncio
async def test_cancelled_transport_close_can_be_retried() -> None:
    """Do not mark a transport closed when its cleanup was interrupted."""
    calls = []

    class Transport(FakeTransport):
        async def aclose(self):
            """Simulate one interrupted cleanup before a successful retry."""
            calls.append("close")
            if len(calls) == 1:
                raise asyncio.CancelledError()

    client = _client(Transport(), owns_transport=True)
    with pytest.raises(asyncio.CancelledError):
        await client.aclose()
    assert client.authenticated
    await client.aclose()
    assert not client.authenticated
    assert calls == ["close", "close"]
