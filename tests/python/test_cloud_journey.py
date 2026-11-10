"""Integration journeys through real cloud clients and Home Assistant entities."""

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("homeassistant")

from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry, entity_registry
from homeassistant.helpers.entity_platform import EntityPlatform
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    FIXTURE,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
)
from support.overseas import _default_context, _QueueTransport, _response

from custom_components.gwm_ora import async_setup_entry, bean_tech_lock, binary_sensor, cloud_runtime, sensor
from custom_components.gwm_ora import coordinator as coordinator_module
from custom_components.gwm_ora.binary_sensor import async_setup_entry as setup_binary_sensors
from custom_components.gwm_ora.button import GwmChinaRemoteButton, GwmCloseWindowsButton
from custom_components.gwm_ora.cloud_auth import (
    GwmCloudAuthenticator,
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_runtime import GwmCloudBootstrap, GwmCloudClient, stage_cloud_bootstrap
from custom_components.gwm_ora.config_flow import GwmOptionsFlow
from custom_components.gwm_ora.const import (
    CONF_BEAN_TECH_LOCK_CREDENTIAL,
    CONF_ENABLE_REMOTE_COMMANDS,
    CONF_SECURITY_PIN,
)
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.gwm_client import (
    ChinaAuthenticated,
    GwmClient,
    GwmClientConfig,
    GwmNetworkError,
    GwmSession,
)
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
    hass.config_entries = ConfigEntries(hass, {})
    await hass.config_entries.async_initialize()
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
@pytest.mark.parametrize(("action", "auth_operation", "send_operation", "journal_name"), [
    ("lock", "authorize_bean_tech_lock", "send_lock_command", "Authorized door lock"),
    ("close_windows", "authorize_bean_tech_command", "send_close_windows_command", "Authorized window close"),
    ("remote_start", "authorize_bean_tech_command", "send_vehicle_control_command", "Authorized remote start"),
])
async def test_beantech_pin_entity_resumes_v3_polling_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    action: str, auth_operation: str, send_operation: str, journal_name: str,
) -> None:
    """Save the options PIN, send the entity command, and recover its v3 result after restart."""
    wire_credentials = _credentials()
    credentials = GwmCloudCredentials(
        "cn", "CN", wire_credentials.phone, device_id=wire_credentials.device_id,
    )
    unique_id = cloud_unique_id(credentials)
    entry_data = cloud_entry_data(credentials)
    discovery = FIXTURE["responses"]["discovery"]
    state = _complete_state(wire_credentials)
    first_wire = _FakeTransport(
        acquire_vehicles=[discovery],
        **{
            auth_operation: [{"code": "000000", "data": "synthetic-security-token"}],
            send_operation: [{"code": "000000"}],
        },
    )
    first_client = _client(first_wire)
    await first_client.authenticate(wire_credentials, state=state)
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = ConfigEntries(hass, {})
    def new_entry() -> ConfigEntry:
        """Construct the same account entry in each Home Assistant process."""
        return ConfigEntry(
            data=entry_data, discovery_keys=MappingProxyType({}), domain="gwm_ora",
            entry_id="synthetic-beantech", minor_version=1,
            options={CONF_ENABLE_REMOTE_COMMANDS: True},
            source="user", subentries_data=None, title="GWM China test", unique_id=unique_id, version=1,
        )

    entry = new_entry()
    hass.config_entries._entries[entry.entry_id] = entry
    install_emulator = AsyncMock()
    monkeypatch.setattr(bean_tech_lock, "async_process_requirements", install_emulator)
    options = GwmOptionsFlow()
    options.hass = hass
    options.handler = entry.entry_id
    form = await options.async_step_init()
    result = await options.async_step_init(form["data_schema"]({CONF_SECURITY_PIN: "000123"}))
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert CONF_SECURITY_PIN not in result["data"]
    encoded = result["data"][CONF_BEAN_TECH_LOCK_CREDENTIAL]
    assert hashlib.sha256(encoded.encode("ascii")).hexdigest() == (
        "f9ec3538c5ca1328d085ff0340cebb4008d379b66b735bc6885e7cc57432808b"
    )
    install_emulator.assert_awaited_once_with(hass, "gwm_ora", ["unicorn==2.1.4"], is_built_in=False)
    hass.config_entries.async_update_entry(entry, options=result["data"])
    bootstrap = GwmCloudBootstrap.from_authentication(credentials, ChinaAuthenticated(state))
    stage_cloud_bootstrap(hass, unique_id, bootstrap)
    monkeypatch.setattr(cloud_runtime, "ChinaClient", lambda *args, **kwargs: first_client)
    monkeypatch.setattr(ConfigEntries, "async_forward_entry_setups", AsyncMock())
    monkeypatch.setattr(GwmDataUpdateCoordinator, "async_config_entry_first_refresh", AsyncMock())
    assert await async_setup_entry(hass, entry)
    runtime = entry.runtime_data
    try:
        if action == "lock":
            await GwmDoorLock(runtime.api, runtime.coordinator, BEAN_VIN).async_lock()
        elif action == "close_windows":
            await GwmCloseWindowsButton(runtime.api, runtime.coordinator, BEAN_VIN).async_press()
        else:
            await GwmChinaRemoteButton(
                runtime.api, runtime.coordinator, BEAN_VIN, "remote_start", "remote_start",
            ).async_press()
        accepted, = await runtime.state_store.async_get_command_journal(entry_data)
        assert accepted.state == "accepted"
        assert accepted.command_name == journal_name
        assert accepted.journal_id in runtime.coordinator._command_tasks
        assert [request.operation for request in first_wire.calls] == [
            "acquire_vehicles", auth_operation, send_operation,
        ]
        assert json.loads(first_wire.calls[1].body)["securityPwd"] == encoded
        if action == "remote_start":
            assert json.loads(first_wire.calls[2].body)["commands"] == [
                {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 900}}
            ]
    finally:
        await runtime.coordinator.async_cancel_command_tasks()
        await runtime.cloud.aclose()

    restarted_hass = HomeAssistant(str(tmp_path))
    restarted_hass.config_entries = ConfigEntries(restarted_hass, {})
    restarted_entry = new_entry()
    restarted_hass.config_entries._entries[restarted_entry.entry_id] = restarted_entry
    second_wire = _FakeTransport(
        acquire_vehicles=[discovery],
        get_remote_command_result=[
            {"code": "000000", "data": {"messageList": [{"messageData": {"resultCode": code}}]}}
            for code in ("2", "0")
        ],
    )
    second_client = _client(second_wire)
    await second_client.authenticate(wire_credentials, state=state)
    resume_session = AsyncMock(return_value=ChinaAuthenticated(state))
    monkeypatch.setattr(GwmCloudAuthenticator, "async_authenticate", resume_session)
    monkeypatch.setattr(cloud_runtime, "ChinaClient", lambda *args, **kwargs: second_client)
    monkeypatch.setattr(
        coordinator_module, "asyncio", SimpleNamespace(sleep=lambda _: asyncio.sleep(0), gather=asyncio.gather),
    )
    monkeypatch.setattr(GwmDataUpdateCoordinator, "_async_refresh_after_completed_command", AsyncMock())
    assert await async_setup_entry(restarted_hass, restarted_entry)
    restarted = restarted_entry.runtime_data
    try:
        resume_session.assert_awaited_once_with(
            credentials, state=state, allow_session_reclaim=False, allow_password_login=False,
        )
        task = restarted.coordinator._command_tasks[accepted.journal_id]
        result = await asyncio.wait_for(task, timeout=5)
        assert result["state"] == "completed"
        assert [request.operation for request in second_wire.calls] == [
            "acquire_vehicles", "get_remote_command_result", "get_remote_command_result",
        ]
        for request in second_wire.calls[1:]:
            assert "/api/v3.0/vehicle/remote-ctrl/result?" in request.url
            assert f"seqNo={BEAN_COMMAND_ID}" in request.url
            assert "securityToken" not in request.headers
        persisted = await restarted.state_store.async_get_command_journal(entry_data)
        assert len(persisted) == 1 and persisted[0].state == "completed"
    finally:
        await restarted.coordinator.async_cancel_command_tasks()
        await restarted.cloud.aclose()
