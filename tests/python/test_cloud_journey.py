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
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    CLOCK,
    FIXTURE,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
)
from support.overseas import _default_context, _QueueTransport, _response

from custom_components.gwm_ora import binary_sensor, sensor
from custom_components.gwm_ora.binary_sensor import async_setup_entry as setup_binary_sensors
from custom_components.gwm_ora.cloud_auth import GwmCloudCredentials, cloud_entry_data, cloud_unique_id
from custom_components.gwm_ora.cloud_commands import GwmCommandApi
from custom_components.gwm_ora.cloud_runtime import GwmCloudClient
from custom_components.gwm_ora.cloud_storage import cloud_state_store
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.gwm_client import GwmClient, GwmClientConfig, GwmNetworkError, GwmSession
from custom_components.gwm_ora.lock import GwmDoorLock
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


@pytest.mark.asyncio
async def test_beantech_lock_entity_resumes_v3_polling_after_restart(tmp_path):
    wire_credentials = _credentials()
    credentials = GwmCloudCredentials(
        "cn", "CN", wire_credentials.phone, device_id=wire_credentials.device_id,
    )
    unique_id = cloud_unique_id(credentials)
    entry_data = cloud_entry_data(credentials)
    discovery = FIXTURE["responses"]["discovery"]
    state = _complete_state(wire_credentials)
    first_store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    await first_store.async_save_auth_state(credentials, state)
    first_wire = _FakeTransport(
        acquire_vehicles=[discovery],
        authorize_bean_tech_lock=[{"code": "000000", "data": "synthetic-security-token"}],
        send_lock_command=[{"code": "000000"}],
    )
    first_client = _client(first_wire)
    await first_client.authenticate(wire_credentials, state=state)
    first_runtime = GwmCloudClient("cn", first_client)
    first = GwmCommandApi(
        first_runtime, first_store, credentials, enabled=True, security_pin=None,
        bean_tech_lock_credential="A" * 64, clock=lambda: CLOCK,
    )
    tracked = []
    try:
        entity = GwmDoorLock(first, SimpleNamespace(async_track_command=tracked.append), BEAN_VIN)
        await entity.async_lock()
        assert len(tracked) == 1 and tracked[0]["state"] == "in_progress"
        command_id = str(tracked[0]["id"])
        assert [request.operation for request in first_wire.calls] == [
            "acquire_vehicles", "authorize_bean_tech_lock", "send_lock_command",
        ]
    finally:
        await first_runtime.aclose()

    second_store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    saved = await second_store.async_load_auth_state(entry_data)
    assert saved == state
    second_wire = _FakeTransport(
        acquire_vehicles=[discovery],
        get_remote_command_result=[
            {"code": "000000", "data": {"messageList": [{"messageData": {"resultCode": code}}]}}
            for code in ("2", "0")
        ],
    )
    second_client = _client(second_wire)
    await second_client.authenticate(wire_credentials, state=saved)
    second_runtime = GwmCloudClient("cn", second_client)
    second = GwmCommandApi(
        second_runtime, second_store, credentials, enabled=True, security_pin=None, clock=lambda: CLOCK,
    )
    try:
        assert [item["id"] for item in await second.async_restore(entry_data)] == [command_id]
        assert (await second.async_get_command(command_id))["state"] == "in_progress"
        assert (await second.async_get_command(command_id))["state"] == "completed"
        assert [request.operation for request in second_wire.calls] == [
            "acquire_vehicles", "get_remote_command_result", "get_remote_command_result",
        ]
        for request in second_wire.calls[1:]:
            assert "/api/v3.0/vehicle/remote-ctrl/result?" in request.url
            assert f"seqNo={BEAN_COMMAND_ID}" in request.url
            assert "securityToken" not in request.headers
        persisted = await second_store.async_get_command_journal(entry_data)
        assert len(persisted) == 1 and persisted[0].state == "completed"
    finally:
        await second_runtime.aclose()
