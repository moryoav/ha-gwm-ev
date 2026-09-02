"""Existing entity-platform behavior on cloud normalized snapshots."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.button import (
    GwmCabinCleanButton,
    GwmChinaRemoteButton,
    GwmCloseWindowsButton,
)
from custom_components.gwm_ora.climate import GwmClimate
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.entity import setup_vehicle_entities
from custom_components.gwm_ora.lock import GwmDoorLock
from custom_components.gwm_ora.number import GwmClimateRunTimeNumber
from custom_components.gwm_ora.sensor import (
    SENSORS,
    GwmSensor,
    _sensor_descriptions_for_vehicle,
)
from custom_components.gwm_ora.switch import (
    GwmChargingScheduleSwitch,
    GwmFrontDefrosterSwitch,
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
async def test_task17_capability_exposes_only_climate_and_keeps_beantech_hidden() -> None:
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
    assert not GwmClimate(
        SimpleNamespace(), coordinator, "SYNTHETIC-BEANTECH"
    ).available
    assert not GwmClimateRunTimeNumber(
        SimpleNamespace(), coordinator, "SYNTHETIC-BEANTECH"
    ).available


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
    assert GwmChinaRemoteButton(
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
