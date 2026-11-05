"""Real client-to-entity polling with only the HTTP boundary replaced."""

import logging
from datetime import UTC, datetime, timedelta
from types import MappingProxyType, SimpleNamespace

import pytest

pytest.importorskip("homeassistant")

from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry, entity_registry
from homeassistant.helpers.entity_platform import EntityPlatform
from support.overseas import _default_context, _QueueTransport, _response

from custom_components.gwm_ora import binary_sensor, sensor
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
    # Newer HA releases separate registry creation from loading.
    if setup_registry := getattr(device_registry, "async_setup", None):
        setup_registry(hass)
    await device_registry.async_load(hass)
    await entity_registry.async_load(hass)
    coordinator = GwmDataUpdateCoordinator(hass, SimpleNamespace(), cloud_client=runtime)
    entry = ConfigEntry(
        data={}, discovery_keys=MappingProxyType({}), domain="gwm_ora", entry_id="synthetic-journey",
        minor_version=1, options={}, source="user", subentries_data=None, title="GWM test",
        unique_id="synthetic-journey", version=1,
    )
    entry.runtime_data = SimpleNamespace(coordinator=coordinator)
    hass.config_entries = ConfigEntries(hass, {})
    # The journey starts with an existing entry and authenticated HTTP session.
    hass.config_entries._entries[entry.entry_id] = entry
    platforms = []

    def published(entity):
        assert entity.entity_id is not None
        state = hass.states.get(entity.entity_id)
        assert state is not None
        return state.state

    try:
        await coordinator.async_refresh()
        assert coordinator.last_update_success
        sensors, binary = [], []
        await setup_sensors(hass, entry, sensors.extend)
        await setup_binary_sensors(hass, entry, binary.extend)
        soc = next(entity for entity in sensors if entity.entity_description.key == "soc")
        window = next(entity for entity in binary if entity.entity_description.key == "window_front_left_open")
        for domain, module, entity in (("sensor", sensor, soc), ("binary_sensor", binary_sensor, window)):
            platform = EntityPlatform(
                hass=hass, logger=logging.getLogger(__name__), domain=domain, platform_name="gwm_ora",
                platform=module, scan_interval=timedelta(seconds=30), entity_namespace=None,
            )
            platform.config_entry = entry
            platform.async_prepare()
            platforms.append(platform)
            entity.entity_id = f"{domain}.gwm_journey"
            await platform.async_add_entities([entity])
        await hass.async_block_till_done()
        identity = (soc.unique_id, window.unique_id)
        assert soc.native_value == 67
        assert window.is_on is False
        assert soc.available and window.available
        assert not soc.remote_commands_available
        assert float(published(soc)) == 67
        assert published(window) == STATE_OFF

        await coordinator.async_refresh()
        await hass.async_block_till_done()
        assert soc.native_value == 50
        assert window.is_on is None
        assert soc.available and window.available
        assert float(published(soc)) == 50
        assert published(window) == STATE_UNKNOWN

        await coordinator.async_refresh()
        await hass.async_block_till_done()
        assert not coordinator.last_update_success
        assert not soc.available and not window.available
        assert published(soc) == STATE_UNAVAILABLE
        assert published(window) == STATE_UNAVAILABLE

        await coordinator.async_refresh()
        await hass.async_block_till_done()
        assert soc.native_value == 40
        assert window.is_on is True
        assert soc.available and window.available
        assert (soc.unique_id, window.unique_id) == identity
        assert float(published(soc)) == 40
        assert published(window) == STATE_ON
        assert [request.operation for request in transport.requests] == [
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
            "acquire_vehicles", "get_last_status",
            "acquire_vehicles", "get_last_status", "get_vehicle_basics",
        ]
        assert not transport.responses
    finally:
        for platform in platforms:
            await platform.async_reset()
        await runtime.aclose()
