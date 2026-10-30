"""Synthetic tests: the isolated read client uses only its injected transport."""

import json
import ssl

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


class FakeTransport:
    def __init__(self) -> None:
        self.operations: list[str] = []

    async def execute(self, request, **_kwargs):
        self.operations.append(request.operation)
        data = [{"vin": "SYNTHETIC-VEHICLE"}] if request.operation == "acquire_vehicles" else {"items": []}
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
