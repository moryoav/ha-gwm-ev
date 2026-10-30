"""Synthetic tests: the isolated read client uses only its injected transport."""

import asyncio
import json
import ssl

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.errors import GwmDeadlineExceededError, GwmSchemaError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.regions import TlsMode


class FakeTransport:
    def __init__(self, *, payloads: dict[str, object] | None = None, error: BaseException | None = None) -> None:
        self.operations: list[str] = []
        self.requests = []
        self.payloads = payloads or {}
        self.error = error

    async def execute(self, request, **_kwargs):
        self.operations.append(request.operation)
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        data = [{"vin": "SYNTHETIC-VEHICLE"}] if request.operation == "acquire_vehicles" else {"items": []}
        data = self.payloads.get(request.operation, data)
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

    async def aclose(self) -> None:
        pass


def _client(transport: FakeTransport, *, country: str = "PK") -> ApacReadClient:
    material = ApacMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key", "synthetic-secret",
    )
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    session = ApacReadSession("a" * 32, "synthetic-token", context, country=country)
    return ApacReadClient(material=material, session=session, transport=transport)


@pytest.mark.asyncio
async def test_discovery_and_status_use_only_injected_transport() -> None:
    transport = FakeTransport()
    client = _client(transport)
    vehicles = await client.acquire_vehicles()
    assert vehicles[0].identifier.value == "SYNTHETIC-VEHICLE"
    status = await client.get_last_status("SYNTHETIC-VEHICLE")
    assert status.items == ()
    assert transport.operations == ["acquire_vehicles", "get_last_status"]


@pytest.mark.asyncio
async def test_write_operation_fails_before_transport() -> None:
    transport = FakeTransport()
    client = _client(transport)
    with pytest.raises(ValueError, match="^apac_operation_not_supported$"):
        await client._read("set_charging_plan")  # type: ignore[arg-type]
    assert transport.operations == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation,payload", [("acquire_vehicles", {}), ("get_last_status", {"items": "private-value"}), ("get_vehicle_basics", {"config": "private-value"})])
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
    transport = FakeTransport(payloads={"get_vehicle_basics": {"config": {
        "airConditionerTemperature": 23, "airConditionerStatusTime": 0,
        "engineStatusTime": "15", "unrelatedPrivateField": "synthetic-private",
    }}})
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
