"""Existing entity-platform behavior on cloud normalized snapshots."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

pytest.importorskip("homeassistant")

from homeassistant.components.climate import HVACMode
from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.button import (
    GwmBeanTechComfortButton,
    GwmCabinCleanButton,
    GwmChinaRemoteButton,
    GwmClimatePresetButton,
    GwmCloseWindowsButton,
)
from custom_components.gwm_ora.climate import GwmClimate
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.entity import GwmEntity, setup_vehicle_entities
from custom_components.gwm_ora.lock import GwmDoorLock
from custom_components.gwm_ora.number import GwmClimateRunTimeNumber
from custom_components.gwm_ora.sensor import (
    SENSORS,
    GwmSensor,
    _sensor_descriptions_for_vehicle,
)
from custom_components.gwm_ora.switch import (
    GwmBatteryHeatSwitch,
    GwmChargingScheduleSwitch,
    GwmFrontDefrosterSwitch,
    GwmRemoteControlSwitch,
    GwmRemoteStartSwitch,
)


def _vehicle(
    vin: str,
    soc: float,
    *,
    platform: str | None = None,
    charge_soc: float | None = None,
    climate_commands: bool = False,
    lock_window_commands: bool = False,
    china_vehicle_commands: bool = False,
    charging_control: bool = False,
    front_defroster_commands: bool = False,
    cabin_clean_commands: bool = False,
    front_defroster: bool | None = None,
) -> dict[str, Any]:
    return {
        "vin": vin,
        "platform": platform,
        "name": f"Vehicle {vin[-1]}",
        "manufacturer": "GWM",
        "model": "Synthetic",
        "serial_number": f"SERIAL-{vin[-1]}",
        "capabilities": {
            "remote_commands": False,
            "climate_commands": climate_commands,
            "lock_window_commands": lock_window_commands,
            "china_vehicle_commands": china_vehicle_commands,
            "charging_control": charging_control,
            "front_defroster_commands": front_defroster_commands,
            "cabin_clean_commands": cabin_clean_commands,
        },
        "values": {
            "soc": soc,
            "charge_soc": charge_soc,
            "front_defroster": front_defroster,
        },
        "timestamps": {},
        "climate": {},
        "raw_items": {},
    }


@pytest.mark.asyncio
async def test_existing_platform_adds_new_cloud_vehicles_without_removing_old_entities() -> None:
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {"region": "eu", "vehicles": [_vehicle("SYNTHETIC-A", 80)]}
    )
    added: list[GwmSensor] = []
    soc_description = next(description for description in SENSORS if description.key == "soc")
    entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        async_on_unload=lambda callback: None,
    )

    setup_vehicle_entities(
        entry,  # type: ignore[arg-type]
        lambda entities: added.extend(entities),  # type: ignore[arg-type]
        lambda vehicle: (
            GwmSensor(coordinator, vehicle["vin"], soc_description),
        ),
    )

    assert len(added) == 1
    first = added[0]
    assert first.native_value == 80
    assert first.available
    assert not GwmClimate(
        SimpleNamespace(),
        coordinator,
        "SYNTHETIC-A",
    ).available

    coordinator.async_set_updated_data(
        {
            "region": "eu",
            "vehicles": [
                _vehicle("SYNTHETIC-A", 79),
                _vehicle("SYNTHETIC-B", 55),
            ],
        }
    )
    assert len(added) == 2
    assert first.native_value == 79
    assert added[1].native_value == 55

    coordinator.async_set_updated_data(
        {"region": "eu", "vehicles": [_vehicle("SYNTHETIC-B", 54)]}
    )
    assert len(added) == 2
    assert not first.available
    assert added[1].available

    coordinator.last_update_success = False
    assert not added[1].available


@pytest.mark.asyncio
async def test_cloud_coordinator_keeps_mixed_china_platform_entities_isolated() -> None:
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "remote_commands_enabled": False,
            "charging_control_enabled": False,
            "vehicles": [
                _vehicle("SYNTHETIC-NAVINFO", 78, platform="navinfo"),
                _vehicle(
                    "SYNTHETIC-BEANTECH",
                    71,
                    platform="beantech",
                    charge_soc=82.5,
                ),
            ],
        }
    )
    added: list[GwmSensor] = []
    entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        async_on_unload=lambda callback: None,
    )

    setup_vehicle_entities(
        entry,  # type: ignore[arg-type]
        lambda entities: added.extend(entities),  # type: ignore[arg-type]
        lambda vehicle: (
            GwmSensor(coordinator, vehicle["vin"], description)
            for description in _sensor_descriptions_for_vehicle(
                vehicle,
                coordinator.region,
            )
        ),
    )

    by_vehicle = {
        vin: {entity.entity_description.key: entity for entity in added if entity.vin == vin}
        for vin in ("SYNTHETIC-NAVINFO", "SYNTHETIC-BEANTECH")
    }
    assert by_vehicle["SYNTHETIC-NAVINFO"]["soc"].native_value == 78
    assert "charge_soc" not in by_vehicle["SYNTHETIC-NAVINFO"]
    assert by_vehicle["SYNTHETIC-BEANTECH"]["soc"].native_value == 71
    assert by_vehicle["SYNTHETIC-BEANTECH"]["charge_soc"].native_value == 82.5
    assert all(not entity.remote_commands_available for entity in added)
    assert all(not entity.charging_control_available for entity in added)


@pytest.mark.asyncio
async def test_task17_capability_exposes_climate_without_pin_gate_beantech() -> None:
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "eu",
            "vehicles": [_vehicle("SYNTHETIC-A", 80, climate_commands=True)],
        }
    )
    assert GwmClimate(SimpleNamespace(), coordinator, "SYNTHETIC-A").available
    assert GwmClimateRunTimeNumber(
        SimpleNamespace(), coordinator, "SYNTHETIC-A"
    ).available
    assert not GwmDoorLock(SimpleNamespace(), coordinator, "SYNTHETIC-A").available

    config_entry = SimpleNamespace(
        options={},
        async_on_unload=lambda callback: None,
    )
    pin_coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )
    pin_coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [
                _vehicle(
                    "SYNTHETIC-BEANTECH",
                    70,
                    platform="beantech",
                    climate_commands=True,
                )
            ],
        }
    )
    # BeanTech climate control is PIN-exempt, so it is exposed without a PIN.
    assert GwmClimate(
        SimpleNamespace(), pin_coordinator, "SYNTHETIC-BEANTECH"
    ).available
    assert GwmClimateRunTimeNumber(
        SimpleNamespace(), pin_coordinator, "SYNTHETIC-BEANTECH"
    ).available


@pytest.mark.asyncio
async def test_beantech_climate_entity_uses_auto_mode_and_17_to_31_range() -> None:
    config_entry = SimpleNamespace(
        options={"beantech_encrypted_security_pin": "X=="},
        async_on_unload=lambda callback: None,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [
                _vehicle(
                    "SYNTHETIC-BEANTECH",
                    70,
                    platform="beantech",
                    climate_commands=True,
                )
            ],
        }
    )

    climate = GwmClimate(SimpleNamespace(), coordinator, "SYNTHETIC-BEANTECH")
    assert climate.available
    assert climate.hvac_modes == [HVACMode.OFF, HVACMode.AUTO]
    assert climate.min_temp == 17
    assert climate.max_temp == 31
    assert climate.hvac_mode == HVACMode.AUTO


@pytest.mark.asyncio
async def test_saved_climate_runtime_is_visible_while_cloud_reads_are_stale() -> None:
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    vehicle = _vehicle("SYNTHETIC-A", 80, climate_commands=True)
    vehicle["climate"] = {"operation_time_minutes": 15}
    coordinator.async_set_updated_data({"region": "eu", "vehicles": [vehicle]})
    api = SimpleNamespace(climate_operation_time_minutes=lambda _vin: 5)

    entity = GwmClimateRunTimeNumber(api, coordinator, "SYNTHETIC-A")

    assert entity.native_value == 5


@pytest.mark.asyncio
async def test_task18_capability_exposes_lock_window_without_task19_buttons() -> None:
    api = SimpleNamespace()
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "eu",
            "vehicles": [
                _vehicle(
                    "SYNTHETIC-A",
                    80,
                    climate_commands=True,
                    lock_window_commands=True,
                )
            ],
        }
    )

    assert GwmDoorLock(api, coordinator, "SYNTHETIC-A").available
    assert GwmCloseWindowsButton(api, coordinator, "SYNTHETIC-A").available
    assert not GwmChinaRemoteButton(
        api,
        coordinator,
        "SYNTHETIC-A",
        "remote_start",
        "remote_start",
    ).available
    assert not GwmDoorLock(api, coordinator, "MISSING").available


@pytest.mark.asyncio
async def test_task19_china_buttons_are_capability_and_platform_filtered() -> None:
    api = SimpleNamespace()
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [
                _vehicle(
                    "SYNTHETIC-NAVINFO",
                    80,
                    platform="navinfo",
                    china_vehicle_commands=True,
                ),
                _vehicle(
                    "SYNTHETIC-BEANTECH",
                    70,
                    platform="beantech",
                    china_vehicle_commands=True,
                ),
                _vehicle(
                    "SYNTHETIC-UNKNOWN",
                    60,
                    platform="future-platform",
                    china_vehicle_commands=True,
                ),
            ],
        }
    )

    assert GwmChinaRemoteButton(
        api,
        coordinator,
        "SYNTHETIC-NAVINFO",
        "tailgate_open",
        "open_tailgate",
    ).available
    # ``remote_start`` moved to a switch, so BeanTech no longer exposes it as a
    # button (the NavInfo ``remote_start`` button above is unaffected).
    assert not GwmChinaRemoteButton(
        api,
        coordinator,
        "SYNTHETIC-BEANTECH",
        "remote_start",
        "remote_start",
    ).available
    assert not GwmChinaRemoteButton(
        api,
        coordinator,
        "SYNTHETIC-BEANTECH",
        "tailgate_open",
        "open_tailgate",
    ).available
    assert not GwmChinaRemoteButton(
        api,
        coordinator,
        "SYNTHETIC-UNKNOWN",
        "horn",
        "sound_horn",
    ).available
    navinfo_climate = GwmClimate(api, coordinator, "SYNTHETIC-NAVINFO")
    assert navinfo_climate.min_temp == 17
    assert navinfo_climate.max_temp == 31


@pytest.mark.asyncio
async def test_task20_capability_exposes_existing_charging_switch_only_when_enabled() -> None:
    api = SimpleNamespace()
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "eu",
            "charging_control_enabled": True,
            "vehicles": [
                _vehicle("SYNTHETIC-A", 80, charging_control=True),
                _vehicle("SYNTHETIC-B", 70),
            ],
        }
    )

    assert GwmChargingScheduleSwitch(api, coordinator, "SYNTHETIC-A").available
    assert not GwmChargingScheduleSwitch(api, coordinator, "SYNTHETIC-B").available


@pytest.mark.asyncio
async def test_overseas_front_defroster_switch_and_air_circulation_button_are_capability_gated() -> None:
    api = SimpleNamespace(
        async_set_front_defroster=AsyncMock(
            side_effect=(
                {"id": "front-on", "state": "in_progress"},
                {"id": "front-off", "state": "in_progress"},
            )
        ),
        async_start_cabin_clean=AsyncMock(
            return_value={"id": "cabin-clean", "state": "in_progress"}
        ),
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
    )
    coordinator.async_set_updated_data(
        {
            "region": "eu",
            "vehicles": [
                _vehicle(
                    "SYNTHETIC-A",
                    80,
                    front_defroster_commands=True,
                    cabin_clean_commands=True,
                    front_defroster=False,
                ),
                _vehicle("SYNTHETIC-B", 70),
            ],
        }
    )
    coordinator.async_track_command = Mock()  # type: ignore[method-assign]

    defroster = GwmFrontDefrosterSwitch(api, coordinator, "SYNTHETIC-A")
    circulation = GwmCabinCleanButton(api, coordinator, "SYNTHETIC-A")
    assert defroster.available
    assert defroster.is_on is False
    assert circulation.available
    assert not GwmFrontDefrosterSwitch(api, coordinator, "SYNTHETIC-B").available
    assert not GwmCabinCleanButton(api, coordinator, "SYNTHETIC-B").available

    await defroster.async_turn_on()
    await defroster.async_turn_off()
    await circulation.async_press()

    assert api.async_set_front_defroster.await_args_list[0].kwargs == {"enabled": True}
    assert api.async_set_front_defroster.await_args_list[1].kwargs == {"enabled": False}
    api.async_start_cabin_clean.assert_awaited_once_with("SYNTHETIC-A")
    assert coordinator.async_track_command.call_count == 3


def _beantech_entity(options: dict[str, Any] | None = None) -> GwmEntity:
    config_entry = SimpleNamespace(
        options=options or {},
        async_on_unload=lambda callback: None,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        SimpleNamespace(),
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )
    return GwmEntity(coordinator, "SYNTHETIC-BEANTECH")


@pytest.mark.asyncio
async def test_security_pin_configured_reflects_option() -> None:
    entity = _beantech_entity({})
    assert entity.security_pin_configured is False

    entity = _beantech_entity({"beantech_encrypted_security_pin": "X=="})
    assert entity.security_pin_configured is True

    entity = _beantech_entity({"beantech_encrypted_security_pin": "   "})
    assert entity.security_pin_configured is False


@pytest.mark.asyncio
async def test_beantech_remote_start_switch_replaces_remote_start_buttons() -> None:
    api = SimpleNamespace(
        async_vehicle_control=AsyncMock(
            side_effect=(
                {"id": "remote-start", "state": "in_progress"},
                {"id": "remote-stop", "state": "in_progress"},
            )
        )
    )
    config_entry = SimpleNamespace(
        options={"beantech_encrypted_security_pin": "X=="},
        async_on_unload=lambda callback: None,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )

    def china_vehicle(vin: str, platform: str, engine_state_code: int) -> dict[str, Any]:
        return {
            "vin": vin,
            "platform": platform,
            "name": f"Vehicle {vin[-1]}",
            "manufacturer": "GWM",
            "model": "Synthetic",
            "serial_number": f"SERIAL-{vin[-1]}",
            "capabilities": {"remote_commands": True},
            "values": {"engine_state_code": engine_state_code},
            "timestamps": {},
            "climate": {},
            "raw_items": {},
        }

    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [
                china_vehicle("SYNTHETIC-BEANTECH", "beantech", 0),
                china_vehicle("SYNTHETIC-NAVINFO", "navinfo", 0),
            ],
        }
    )

    switch = GwmRemoteStartSwitch(api, coordinator, "SYNTHETIC-BEANTECH")
    assert switch.available
    assert switch.is_on is False

    # NavInfo vehicles must not expose the BeanTech remote-start switch.
    assert not GwmRemoteStartSwitch(api, coordinator, "SYNTHETIC-NAVINFO").available

    with patch.object(switch, "async_write_ha_state"):
        await switch.async_turn_on()
        assert switch.is_on is True
        await switch.async_turn_off()
        assert switch.is_on is False

    assert api.async_vehicle_control.await_args_list == [
        call("SYNTHETIC-BEANTECH", "remote_start", run_time_minutes=15),
        call("SYNTHETIC-BEANTECH", "remote_stop"),
    ]


@pytest.mark.asyncio
async def test_beantech_comfort_switches_and_buttons_are_pin_exempt_and_dispatch() -> None:
    api = SimpleNamespace(
        async_vehicle_control=AsyncMock(
            return_value={"id": "comfort", "state": "in_progress"}
        ),
        async_set_climate=AsyncMock(
            return_value={"id": "climate", "state": "in_progress"}
        ),
    )
    config_entry = SimpleNamespace(
        options={},
        async_on_unload=lambda callback: None,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )

    def china_vehicle(vin: str, platform: str) -> dict[str, Any]:
        return {
            "vin": vin,
            "platform": platform,
            "name": f"Vehicle {vin[-1]}",
            "manufacturer": "GWM",
            "model": "Synthetic",
            "serial_number": f"SERIAL-{vin[-1]}",
            "capabilities": {
                "remote_commands": True,
                "climate_commands": True,
                "china_vehicle_commands": True,
            },
            "values": {
                "front_driver_seat_heater_level": 3,
                "front_driver_seat_vent_level": 0,
                "steering_wheel_heater_active": False,
                "front_defroster": False,
                "rear_defroster": False,
            },
            "timestamps": {},
            "climate": {"mode": "auto", "target_temperature_c": 17},
            "raw_items": {},
        }

    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [
                china_vehicle("SYNTHETIC-BEANTECH", "beantech"),
                china_vehicle("SYNTHETIC-NAVINFO", "navinfo"),
            ],
        }
    )
    coordinator.async_track_command = Mock()  # type: ignore[method-assign]

    seat = GwmRemoteControlSwitch(
        api,
        coordinator,
        "SYNTHETIC-BEANTECH",
        turn_on_action="seat_heating_start",
        turn_off_action="seat_heating_stop",
        state_key="front_driver_seat_heater_level",
        translation_key="seat_heating",
    )
    assert seat.available
    assert seat.is_on is True
    # NavInfo vehicles must not expose BeanTech comfort switches.
    assert not GwmRemoteControlSwitch(
        api,
        coordinator,
        "SYNTHETIC-NAVINFO",
        turn_on_action="seat_heating_start",
        turn_off_action="seat_heating_stop",
        state_key="front_driver_seat_heater_level",
        translation_key="seat_heating",
    ).available

    fast_cool = GwmClimatePresetButton(
        api, coordinator, "SYNTHETIC-BEANTECH", temperature=17, translation_key="fast_cool"
    )
    assert fast_cool.available

    # Cabin clean is PIN-exempt, so it is exposed without a PIN.
    cabin_clean = GwmBeanTechComfortButton(
        api, coordinator, "SYNTHETIC-BEANTECH", "cabin_clean", "cabin_clean"
    )
    assert cabin_clean.available

    # The one-touch comfort-off multi-command travels the PIN-gated timely path,
    # so it stays unavailable without a PIN.
    comfort_off = GwmBeanTechComfortButton(
        api, coordinator, "SYNTHETIC-BEANTECH", "comfort_off", "comfort_off"
    )
    assert not comfort_off.available

    with patch.object(seat, "async_write_ha_state"):
        await seat.async_turn_off()
        assert seat.is_on is False
    await fast_cool.async_press()
    await cabin_clean.async_press()

    assert api.async_vehicle_control.await_args_list == [
        call("SYNTHETIC-BEANTECH", "seat_heating_stop"),
        call("SYNTHETIC-BEANTECH", "cabin_clean"),
    ]
    api.async_set_climate.assert_awaited_once_with(
        "SYNTHETIC-BEANTECH", mode="auto", temperature=17
    )


@pytest.mark.asyncio
async def test_beantech_pin_required_switches_and_buttons_stay_gated() -> None:
    api = SimpleNamespace(
        async_vehicle_control=AsyncMock(
            return_value={"id": "cmd", "state": "in_progress"}
        ),
    )
    config_entry = SimpleNamespace(
        options={},
        async_on_unload=lambda callback: None,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=SimpleNamespace(),  # type: ignore[arg-type]
        config_entry=config_entry,  # type: ignore[arg-type]
    )

    def china_vehicle(vin: str, platform: str) -> dict[str, Any]:
        return {
            "vin": vin,
            "platform": platform,
            "name": f"Vehicle {vin[-1]}",
            "manufacturer": "GWM",
            "model": "Synthetic",
            "serial_number": f"SERIAL-{vin[-1]}",
            "capabilities": {
                "remote_commands": True,
                "climate_commands": True,
                "china_vehicle_commands": True,
            },
            "values": {
                "engine_state_code": 0,
                "front_driver_seat_heater_level": 3,
                "front_driver_seat_vent_level": 0,
                "steering_wheel_heater_active": False,
                "front_defroster": False,
                "rear_defroster": False,
            },
            "timestamps": {},
            "climate": {"mode": "auto", "target_temperature_c": 17},
            "raw_items": {},
        }

    coordinator.async_set_updated_data(
        {
            "region": "cn",
            "vehicles": [china_vehicle("SYNTHETIC-BEANTECH", "beantech")],
        }
    )

    battery_heat = GwmBatteryHeatSwitch(
        api,
        coordinator,
        "SYNTHETIC-BEANTECH",
        turn_on_action="battery_gun_heat",
        turn_off_action="battery_gun_heat_stop",
        translation_key="battery_gun_heat",
    )
    remote_start = GwmRemoteStartSwitch(api, coordinator, "SYNTHETIC-BEANTECH")
    comfort_off = GwmBeanTechComfortButton(
        api, coordinator, "SYNTHETIC-BEANTECH", "comfort_off", "comfort_off"
    )

    # Remote start and the multi-command comfort-off need a configured PIN
    # before they are exposed; battery heating is PIN-exempt like the other
    # comfort controls, so it is available without one.
    assert not remote_start.available
    assert battery_heat.available
    assert not comfort_off.available

    config_entry.options = {"beantech_encrypted_security_pin": "X=="}

    assert remote_start.available
    assert battery_heat.available
    assert comfort_off.available
