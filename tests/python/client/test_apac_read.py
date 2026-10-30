"""Synthetic tests: the isolated read client uses only its injected transport."""

import asyncio
import json
import ssl

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.errors import GwmDeadlineExceededError, GwmSchemaError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


class FakeTransport:
    def __init__(self, *, payloads: dict[str, object] | None = None, error: BaseException | None = None) -> None:
        self.operations: list[str] = []
        self.payloads = payloads or {}
        self.error = error

    async def execute(self, request, **_kwargs):
        self.operations.append(request.operation)
        if self.error is not None:
            raise self.error
        data = [{"vin": "SYNTHETIC-VEHICLE"}] if request.operation == "acquire_vehicles" else {"items": []}
        data = self.payloads.get(request.operation, data)
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

    async def aclose(self) -> None:
        pass


def _client(transport: FakeTransport) -> ApacReadClient:
    material = ApacMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key", "synthetic-secret",
    )
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    session = ApacReadSession("a" * 32, "synthetic-token", context, country="PK")
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
