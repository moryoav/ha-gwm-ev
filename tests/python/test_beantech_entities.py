"""BeanTech entity registration, dispatch, and appointment lifecycle regressions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from zoneinfo import ZoneInfo

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from custom_components.gwm_ora.button import GwmBeanTechComfortButton, GwmClimatePresetButton
from custom_components.gwm_ora.button import async_setup_entry as setup_buttons
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.select import GwmCabinCleanAppointmentSelect, _clock_to_today_ms, _ms_to_clock
from custom_components.gwm_ora.select import async_setup_entry as setup_selects
from custom_components.gwm_ora.switch import GwmRemoteControlSwitch
from custom_components.gwm_ora.switch import async_setup_entry as setup_switches
from gwm_client import GwmApiError

VIN = "LGWTEST0000000003"
ACCEPTED = {"id": "accepted", "state": "in_progress"}


def _context(region="cn", platform="beantech", enabled=True):
    hass = HomeAssistant("synthetic-config")
    api = SimpleNamespace(**{name: AsyncMock(return_value=ACCEPTED) for name in (
        "async_vehicle_control", "async_set_comfort_mode", "async_set_climate",
    )}, async_get_cabin_clean_appointment=AsyncMock(return_value=None), async_set_cabin_clean_appointment=AsyncMock())
    coordinator = GwmDataUpdateCoordinator(hass, api, cloud_client=SimpleNamespace())
    vehicle = {"vin": VIN, "platform": platform, "values": {}, "capabilities": {
        "china_vehicle_commands": enabled, "climate_commands": enabled,
    }}
    coordinator.async_set_updated_data({"region": region, "vehicles": [vehicle]})
    coordinator.async_track_command = Mock()
    entry = SimpleNamespace(runtime_data=SimpleNamespace(api=api, coordinator=coordinator), async_on_unload=lambda callback: None)
    return hass, api, coordinator, vehicle, entry


@pytest.mark.asyncio
@pytest.mark.parametrize("region,platform", [("cn", "beantech"), ("cn", "navinfo"), ("cn", "unknown"), ("eu", "beantech"), ("aus", "beantech"), ("rus", "beantech")])
@pytest.mark.parametrize("enabled", [True, False])
async def test_beantech_entities_are_registered_only_on_the_intended_platform(region, platform, enabled):
    hass, api, coordinator, vehicle, entry = _context(region, platform, enabled)
    expected = region == "cn" and platform == "beantech"
    for setup, new_classes, count in (
        (setup_buttons, (GwmBeanTechComfortButton, GwmClimatePresetButton), 7),
        (setup_switches, (GwmRemoteControlSwitch,), 7),
        (setup_selects, (GwmCabinCleanAppointmentSelect,), 1),
    ):
        added = []
        await setup(hass, entry, added.extend)
        assert len({entity.unique_id for entity in added}) == len(added)
        new = [entity for entity in added if isinstance(entity, new_classes)]
        assert len(new) == (count if expected else 0)
        assert all(entity.available == enabled for entity in new)
        coordinator.last_update_success = False
        assert all(not entity.available for entity in new)
        coordinator.last_update_success = True
    api.async_vehicle_control.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("action,method,kwargs", [
    ("cabin_clean", "async_vehicle_control", {}), ("comfort_off", "async_vehicle_control", {}),
    ("comfort_warm", "async_set_comfort_mode", {"mode_type": "warm"}),
    ("comfort_cool", "async_set_comfort_mode", {"mode_type": "cool"}),
    ("comfort_last", "async_set_comfort_mode", {"mode_type": "common"}),
])
async def test_comfort_buttons_dispatch_and_track_exact_commands(action, method, kwargs):
    _, api, coordinator, _, _ = _context()
    button = GwmBeanTechComfortButton(api, coordinator, VIN, action, action)
    await button.async_press()
    getattr(api, method).assert_awaited_once_with(VIN, *([action] if method == "async_vehicle_control" else []), **kwargs)
    coordinator.async_track_command.assert_called_once_with(ACCEPTED)
    getattr(api, method).side_effect = GwmApiError(api_code="7")
    with pytest.raises(HomeAssistantError):
        await button.async_press()
    assert coordinator.async_track_command.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature,key", [(17, "fast_cool"), (31, "fast_heat")])
async def test_climate_presets_use_auto_at_the_captured_temperature_bounds(temperature, key):
    _, api, coordinator, _, _ = _context()
    await GwmClimatePresetButton(api, coordinator, VIN, temperature, key).async_press()
    api.async_set_climate.assert_awaited_once_with(VIN, mode="auto", temperature=temperature)
    coordinator.async_track_command.assert_called_once_with(ACCEPTED)


@pytest.mark.asyncio
async def test_every_comfort_switch_dispatches_both_actions_and_keeps_reported_state():
    hass, api, coordinator, vehicle, entry = _context()
    added = []
    await setup_switches(hass, entry, added.extend)
    for switch in [entity for entity in added if isinstance(entity, GwmRemoteControlSwitch)]:
        assert switch.is_on is None
        vehicle["values"][switch._state_key] = 0
        assert switch.is_on is False
        await switch.async_turn_on()
        api.async_vehicle_control.assert_awaited_with(VIN, switch._turn_on_action)
        assert switch.is_on is False
        vehicle["values"][switch._state_key] = 3
        assert switch.is_on is True
        await switch.async_turn_off()
        api.async_vehicle_control.assert_awaited_with(VIN, switch._turn_off_action)
        assert switch.is_on is True
        vehicle["values"][switch._state_key] = "0"
        assert switch.is_on is None
    assert coordinator.async_track_command.call_count == 14


@pytest.mark.parametrize("now,option,expected", [
    ("2026-09-10T07:00:00+08:00", "08:00", "2026-09-10T08:00:00+08:00"),
    ("2026-09-10T08:00:00+08:00", "08:00", "2026-09-11T08:00:00+08:00"),
    ("2026-09-10T23:59:59+08:00", "00:00", "2026-09-11T00:00:00+08:00"),
])
def test_appointment_uses_home_assistant_timezone_and_next_occurrence(monkeypatch, now, option, expected):
    monkeypatch.setattr(dt_util, "now", lambda: datetime.fromisoformat(now))
    assert _clock_to_today_ms(option) == int(datetime.fromisoformat(expected).timestamp() * 1000)


@pytest.mark.parametrize("now,expected", [
    ("2026-03-28T22:00:00+00:00", "2026-03-30T00:30:00+00:00"),
    ("2026-10-24T22:00:00+00:00", "2026-10-25T00:30:00+00:00"),
])
def test_appointment_dst_skips_nonexistent_times_and_handles_folds(monkeypatch, now, expected):
    local = datetime.fromisoformat(now).astimezone(ZoneInfo("Europe/Berlin"))
    monkeypatch.setattr(dt_util, "now", lambda: local)
    assert _clock_to_today_ms("02:30") == int(datetime.fromisoformat(expected).timestamp() * 1000)


@pytest.mark.parametrize("option", ["24:00", "08:01", "bad", "8:00", "00:60"])
def test_appointment_rejects_invalid_clock_options(option):
    with pytest.raises(HomeAssistantError):
        _clock_to_today_ms(option)


def test_appointment_readback_keeps_minutes_exact_and_bounds_dates(monkeypatch):
    local = datetime(2026, 9, 10, 8, 3, tzinfo=ZoneInfo("Asia/Shanghai"))
    monkeypatch.setattr(dt_util, "as_local", lambda value: value.astimezone(local.tzinfo))
    assert _ms_to_clock(int(local.timestamp() * 1000)) == "08:03"
    assert _ms_to_clock(10**30) is None


def _appointment(monkeypatch):
    hass, api, coordinator, _, _ = _context()
    entity = GwmCabinCleanAppointmentSelect(api, coordinator, VIN)
    entity.hass = hass
    entity.async_write_ha_state = Mock()
    monkeypatch.setattr(dt_util, "utcnow", lambda: datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(dt_util, "now", lambda: datetime(2026, 1, 1, tzinfo=UTC))
    return entity, api


@pytest.mark.asyncio
async def test_appointment_readback_clears_unset_and_retains_known_state_on_error(monkeypatch, caplog):
    entity, api = _appointment(monkeypatch)
    assert entity.current_option is None
    future = int(datetime(2026, 1, 2, 8, 3, tzinfo=UTC).timestamp() * 1000)
    api.async_get_cabin_clean_appointment.return_value = future
    await entity._async_read_state()
    assert entity.current_option == _ms_to_clock(future)
    assert entity.current_option in entity.options
    api.async_get_cabin_clean_appointment.side_effect = GwmApiError(api_code="7")
    await entity._async_read_state()
    assert entity._time_ms == future
    api.async_get_cabin_clean_appointment.side_effect = None
    api.async_get_cabin_clean_appointment.return_value = None
    await entity._async_read_state()
    assert entity.current_option is None
    entity._time_ms = 1
    assert entity.current_option is None


@pytest.mark.asyncio
async def test_appointment_only_changes_local_value_after_success(monkeypatch):
    entity, api = _appointment(monkeypatch)
    api.async_set_cabin_clean_appointment.side_effect = GwmApiError(api_code="7")
    with pytest.raises(HomeAssistantError):
        await entity.async_select_option("08:00")
    assert entity._time_ms is None
    api.async_set_cabin_clean_appointment.side_effect = None
    await entity.async_select_option("08:00")
    expected = int(datetime(2026, 1, 1, 8, tzinfo=UTC).timestamp() * 1000)
    assert entity._time_ms == expected
    api.async_set_cabin_clean_appointment.assert_awaited_with(VIN, time_ms=expected)


@pytest.mark.asyncio
async def test_appointment_stale_read_cannot_overwrite_new_selection(monkeypatch):
    entity, api = _appointment(monkeypatch)
    started, finish = asyncio.Event(), asyncio.Event()
    async def read(_vin):
        started.set()
        await finish.wait()
        return None
    api.async_get_cabin_clean_appointment.side_effect = read
    task = asyncio.create_task(entity._async_read_state())
    await started.wait()
    await entity.async_select_option("08:00")
    selected = entity._time_ms
    finish.set()
    await task
    assert entity._time_ms == selected


@pytest.mark.asyncio
async def test_appointment_background_reads_do_not_overlap_and_are_cancelled(monkeypatch):
    entity, api = _appointment(monkeypatch)
    started = asyncio.Event()
    async def read(_vin):
        started.set()
        await asyncio.Event().wait()
    api.async_get_cabin_clean_appointment.side_effect = read
    entity._handle_coordinator_update()
    await started.wait()
    first = entity._read_task
    entity._handle_coordinator_update()
    assert entity._read_task is first
    api.async_get_cabin_clean_appointment.assert_awaited_once_with(VIN)
    entity._cancel_read()
    with pytest.raises(asyncio.CancelledError):
        await first


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_appointment_initial_read_and_cleanup_follow_entity_lifecycle(monkeypatch, enabled):
    entity, api = _appointment(monkeypatch)
    entity.coordinator.data["vehicles"][0]["capabilities"]["china_vehicle_commands"] = enabled
    entity.async_on_remove = Mock()
    await entity.async_added_to_hass()
    assert api.async_get_cabin_clean_appointment.await_count == int(enabled)
    callbacks = [call.args[0] for call in entity.async_on_remove.call_args_list]
    assert entity._cancel_read in callbacks
    for callback in callbacks:
        callback()
