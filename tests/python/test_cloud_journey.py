"""Real client-to-entity polling with only the HTTP boundary replaced."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from support.overseas import _default_context, _QueueTransport, _response

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.binary_sensor import async_setup_entry as setup_binary_sensors
from custom_components.gwm_ora.cloud_runtime import GwmCloudClient
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.gwm_client import GwmClient, GwmClientConfig, GwmNetworkError, GwmSession
from custom_components.gwm_ora.sensor import async_setup_entry as setup_sensors

VIN = "LGWTEST0000000001"


def _poll(soc, window=None):
    items = [{"code": "2013021", "value": str(soc), "unit": "%"}]
    if window is not None:
        items.append({"code": "2210001", "value": str(window)})
    return [
        _response([{"vin": VIN, "brandName": "GWM", "modelName": "Synthetic"}]),
        _response({"items": items}),
        _response({"config": {}}),
    ]


@pytest.mark.asyncio
async def test_wire_poll_reaches_entities_clears_missing_values_and_recovers_from_outage(tmp_path):
    transport = _QueueTransport([
        *_poll(67, 1),
        *_poll(50),
        _response([{"vin": VIN}]), GwmNetworkError(operation="get_last_status"),
        *_poll(40, 3),
    ])
    client = GwmClient(
        GwmClientConfig("aus"),
        GwmSession("AU", "0123456789abcdef0123456789abcdef", "SYNTHETIC-ACCESS", _default_context()),
        transport=transport,
    )
    runtime = GwmCloudClient("aus", client, clock=lambda: datetime(2026, 11, 5, tzinfo=UTC))
    hass = HomeAssistant(str(tmp_path))
    coordinator = GwmDataUpdateCoordinator(hass, SimpleNamespace(), cloud_client=runtime)
    entry = SimpleNamespace(runtime_data=SimpleNamespace(coordinator=coordinator), async_on_unload=lambda _callback: None)

    try:
        await coordinator.async_refresh()
        assert coordinator.last_update_success
        sensors, binary = [], []
        await setup_sensors(hass, entry, sensors.extend)
        await setup_binary_sensors(hass, entry, binary.extend)
        soc = next(entity for entity in sensors if entity.entity_description.key == "soc")
        window = next(entity for entity in binary if entity.entity_description.key == "window_front_left_open")
        identity = (soc.unique_id, window.unique_id)
        assert soc.native_value == 67
        assert window.is_on is False
        assert soc.available and window.available
        assert not soc.remote_commands_available

        await coordinator.async_refresh()
        assert soc.native_value == 50
        assert window.is_on is None
        assert soc.available and window.available

        await coordinator.async_refresh()
        assert not coordinator.last_update_success
        assert not soc.available and not window.available

        await coordinator.async_refresh()
        assert soc.native_value == 40
        assert window.is_on is True
        assert soc.available and window.available
        assert (soc.unique_id, window.unique_id) == identity
        assert [request.operation for request in transport.requests] == [
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
            "acquire_vehicles", "get_last_status",
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
        ]
        assert not transport.responses
    finally:
        await runtime.aclose()
