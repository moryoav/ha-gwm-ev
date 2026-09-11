"""BeanTech charging state, consent, and command lifecycle regressions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock

import pytest

pytest.importorskip("homeassistant")

from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util
from test_beantech_entities import ACCEPTED, VIN, _context

from custom_components.gwm_ora.beantech_charging import BeanTechChargingEntity
from custom_components.gwm_ora.entity import GwmEntity
from custom_components.gwm_ora.number import GwmChargeSocNumber
from custom_components.gwm_ora.number import async_setup_entry as setup_numbers
from custom_components.gwm_ora.select import GwmBatteryAppointmentTimeSelect, GwmChargeWindowSelect
from custom_components.gwm_ora.select import async_setup_entry as setup_selects
from custom_components.gwm_ora.switch import (
    GwmBatteryAppointmentHeatingSwitch,
    GwmBatteryHeatSwitch,
    GwmSmartChargeSwitch,
)
from custom_components.gwm_ora.switch import async_setup_entry as setup_switches
from gwm_client import GwmApiError


def _charging_context(region="cn", platform="beantech", remote=True, charging=True):
    hass, api, coordinator, vehicle, entry = _context(region, platform, remote)
    vehicle["capabilities"]["beantech_charging_commands"] = charging
    for name in ("async_set_charging_mode", "async_set_charge_window", "async_set_charge_soc", "async_set_battery_heating_appointment"):
        setattr(api, name, AsyncMock(return_value=ACCEPTED))
    api.async_get_charging_mode.return_value = {"enabled": False, "start_time": "23:03", "end_time": "07:07"}
    api.async_get_battery_heat_status.return_value = {"gun_warm": False, "active_warm": None}
    api.async_get_battery_heating_appointment.return_value = {"enabled": None}
    departures = {}
    api.battery_heating_departure_time = departures.get
    api.remember_battery_heating_departure_time = lambda vin, value: departures.update({vin: value})
    return hass, api, coordinator, vehicle, entry


def _entity(cls=GwmSmartChargeSwitch, **kwargs):
    hass, api, coordinator, vehicle, _ = _charging_context()
    entity = cls(api, coordinator, VIN, **kwargs)
    entity.hass = hass
    entity.async_write_ha_state = Mock()
    return entity, api, coordinator, vehicle


@pytest.mark.asyncio
@pytest.mark.parametrize("region,platform", [("cn", "beantech"), ("cn", "navinfo"), ("cn", "unknown"), ("eu", "beantech"), ("aus", "beantech"), ("rus", "beantech")])
@pytest.mark.parametrize("remote,charging", [(True, True), (False, True), (True, False), (False, False)])
async def test_charging_entities_isolate_platform_and_independent_consents(region, platform, remote, charging):
    hass, api, coordinator, _, entry = _charging_context(region, platform, remote, charging)
    for setup, expected_count in ((setup_switches, 4), (setup_selects, 3), (setup_numbers, 1)):
        entities = []
        await setup(hass, entry, entities.extend)
        assert len({entity.unique_id for entity in entities}) == len(entities)
        new = [entity for entity in entities if isinstance(entity, BeanTechChargingEntity)]
        assert len(new) == (expected_count if (region, platform) == ("cn", "beantech") else 0)
        for entity in new:
            assert entity.available == (charging if entity._requires_charging_control else remote)
            coordinator.last_update_success = False
            assert not entity.available
            coordinator.last_update_success = True
    api.async_set_charging_mode.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,kwargs,method,on,off,key", [
    (GwmSmartChargeSwitch, {}, "async_set_charging_mode", {"enable": True}, {"enable": False}, "enabled"),
    (GwmBatteryHeatSwitch, {"plugged_in": True}, "async_vehicle_control", "battery_gun_heat", "battery_gun_heat_stop", "gun_warm"),
    (GwmBatteryHeatSwitch, {"plugged_in": False}, "async_vehicle_control", "battery_initiative_heat", "battery_initiative_heat_stop", "active_warm"),
])
@pytest.mark.parametrize("state", ["completed", "failed", "timeout", None])
async def test_switches_read_back_after_every_outcome_without_optimistic_state(cls, kwargs, method, on, off, key, state):
    entity, api, coordinator, _ = _entity(cls, **kwargs)
    assert entity.is_on is None
    for action, command in ((entity.async_turn_on, on), (entity.async_turn_off, off)):
        await action()
        call = getattr(api, method)
        if isinstance(command, dict):
            call.assert_awaited_with(VIN, **command)
        else:
            call.assert_awaited_with(VIN, command)
        result = None if state is None else {"state": state}
        callback = coordinator.async_track_command.call_args.kwargs["on_terminal"]
        await callback(result)
        assert entity.is_on == entity._data.get(key)
    assert entity._read.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("start", [True, False])
async def test_charge_window_preserves_exact_reported_minutes_and_edits_only_one_bound(start):
    entity, api, coordinator, _ = _entity(GwmChargeWindowSelect, start=start)
    assert entity.current_option is None
    assert len(entity.options) == 288
    await entity._async_read_state()
    original = "23:03" if start else "07:07"
    assert entity.current_option == original
    assert original in entity.options
    await entity.async_select_option(original)
    api.async_set_charge_window.assert_not_awaited()
    with pytest.raises(HomeAssistantError):
        await entity.async_select_option("08:01")
    await entity.async_select_option("08:00")
    api.async_set_charge_window.assert_awaited_once_with(VIN, **{"start_time" if start else "end_time": "08:00"})
    assert entity.current_option == original
    field = "start_time" if start else "end_time"
    api.async_get_charging_mode.return_value[field] = "08:00"
    await coordinator.async_track_command.call_args.kwargs["on_terminal"]({"state": "completed"})
    assert entity.current_option == "08:00"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, None, "60", [], 40, 110, 65, 60.5, float("nan"), float("inf")])
async def test_charge_limit_rejects_invalid_values_without_sending(value):
    entity, api, _, _ = _entity(GwmChargeSocNumber)
    with pytest.raises(HomeAssistantError):
        await entity.async_set_native_value(value)
    api.async_set_charge_soc.assert_not_awaited()
    assert entity.native_value is None


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["completed", "failed", "timeout", None])
async def test_charge_limit_requires_terminal_success_and_invalidates_previous_value_on_acceptance(state):
    entity, api, coordinator, _ = _entity(GwmChargeSocNumber)
    assert entity.native_value is None
    entity._confirmed_percent = 90
    await entity.async_set_native_value(60.0)
    api.async_set_charge_soc.assert_awaited_once_with(VIN, percent=60)
    assert entity.native_value is None
    await coordinator.async_track_command.call_args.kwargs["on_terminal"](None if state is None else {"state": state})
    assert entity.native_value == (60 if state == "completed" else None)
    previous = entity.native_value
    api.async_set_charge_soc.side_effect = GwmApiError(api_code="7")
    with pytest.raises(HomeAssistantError):
        await entity.async_set_native_value(80)
    assert entity.native_value == previous
    assert coordinator.async_track_command.call_count == 1


@pytest.mark.asyncio
async def test_appointment_uses_explicit_confirmed_time_and_never_invents_departure(monkeypatch):
    now = datetime(2026, 9, 11, tzinfo=UTC)
    monkeypatch.setattr(dt_util, "utcnow", lambda: now)
    monkeypatch.setattr(dt_util, "now", lambda: now)
    monkeypatch.setattr(dt_util, "as_local", lambda value: value)
    select, api, coordinator, _ = _entity(GwmBatteryAppointmentTimeSelect)
    switch = GwmBatteryAppointmentHeatingSwitch(api, coordinator, VIN)
    switch.async_write_ha_state = Mock()
    assert select.current_option is None
    assert switch.is_on is None
    with pytest.raises(HomeAssistantError, match="battery heating time"):
        await select.async_select_option("08:01")
    for missing in (None, 1):
        api.remember_battery_heating_departure_time(VIN, missing)
        with pytest.raises(HomeAssistantError, match="Choose a future"):
            await switch.async_turn_on()
    api.async_set_battery_heating_appointment.assert_not_awaited()
    await select.async_select_option("08:00")
    expected = int(now.replace(hour=8).timestamp() * 1000)
    api.async_set_battery_heating_appointment.assert_awaited_once_with(VIN, enable=True, use_car_time_ms=expected)
    assert select.current_option is None
    await coordinator.async_track_command.call_args.kwargs["on_terminal"]({"state": "completed"})
    assert select.current_option == "08:00"
    await select.async_select_option("08:00")
    assert api.async_set_battery_heating_appointment.await_count == 1
    await switch.async_turn_off()
    api.async_set_battery_heating_appointment.assert_awaited_with(VIN, enable=False)
    await switch.async_turn_on()
    api.async_set_battery_heating_appointment.assert_awaited_with(VIN, enable=True, use_car_time_ms=expected)
    await switch._async_read_state()
    assert switch.is_on is None


@pytest.mark.asyncio
async def test_late_or_removed_callbacks_cannot_confirm_a_newer_command():
    entity, _, coordinator, _ = _entity(GwmChargeSocNumber)
    await entity.async_set_native_value(60)
    first = coordinator.async_track_command.call_args.kwargs["on_terminal"]
    await entity.async_set_native_value(80)
    second = coordinator.async_track_command.call_args.kwargs["on_terminal"]
    await first({"state": "completed"})
    assert entity.native_value is None
    entity._cancel_read()
    await second({"state": "completed"})
    assert entity.native_value is None


@pytest.mark.asyncio
async def test_initial_read_throttling_failure_and_unload(monkeypatch, caplog):
    entity, api, _, vehicle = _entity()
    remove = Mock()
    entity.async_on_remove = remove
    monkeypatch.setattr(GwmEntity, "async_added_to_hass", AsyncMock())
    await entity.async_added_to_hass()
    assert entity.is_on is False
    remove.assert_called_once_with(entity._cancel_read)
    entity._handle_coordinator_update()
    assert entity._read_task is None
    entity._last_read = float("-inf")
    entity._handle_coordinator_update()
    task = entity._read_task
    entity._handle_coordinator_update()
    assert entity._read_task is task
    await task
    api.async_get_charging_mode.side_effect = GwmApiError(api_code="7")
    await entity._async_read_state()
    assert entity.is_on is False
    vehicle["capabilities"]["beantech_charging_commands"] = False
    await entity._async_read_state()
    assert api.async_get_charging_mode.await_count == 3
    entity._cancel_read()
    entity._handle_coordinator_update()
    await entity._async_read_state()
    assert api.async_get_charging_mode.await_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("interruption", ["write", "remove", "locked"])
async def test_pending_read_does_not_overwrite_state_after_an_intervening_write_or_unload(interruption):
    entity, api, _, _ = _entity()
    started, release = asyncio.Event(), asyncio.Event()
    async def read(_vin):
        started.set()
        await release.wait()
        return {"enabled": True}
    api.async_get_charging_mode.side_effect = read
    task = asyncio.create_task(entity._async_read_state())
    await started.wait()
    if interruption == "write":
        await entity.async_turn_on()
    elif interruption == "remove":
        entity._cancel_read()
    else:
        await entity._write_lock.acquire()
        entity._handle_coordinator_update()
    release.set()
    await task
    assert entity.is_on is None
    if interruption == "locked":
        entity._write_lock.release()
