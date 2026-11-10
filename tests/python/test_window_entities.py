"""Window wire values, physical names, and existing entity identities."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("homeassistant")

from support.entities import VIN, _context

from custom_components.gwm_ora.binary_sensor import async_setup_entry as setup_binary_sensors
from custom_components.gwm_ora.button import GwmCloseWindowsButton
from custom_components.gwm_ora.button import async_setup_entry as setup_buttons
from custom_components.gwm_ora.gwm_client import (
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    VehicleIdentifier,
    map_vehicle_snapshot,
)
from custom_components.gwm_ora.gwm_client.china_gtsp import map_gtsp_status
from custom_components.gwm_ora.gwm_client.china_status import map_bean_tech_status, map_china_status

POSITIONS = ("front_left", "front_right", "rear_left", "rear_right")


@pytest.mark.parametrize(
    "language,left,right",
    [
        ("en", "Rear-left window", "Rear-right window"),
        ("zh-Hans", "左后车窗", "右后车窗"),
    ],
)
def test_rear_window_translations_use_physical_sides(language, left, right):
    """Give both supported languages the same physical meaning."""
    translations = json.loads(
        (Path(__file__).resolve().parents[2] / f"custom_components/gwm_ora/translations/{language}.json").read_text(
            encoding="utf-8"
        )
    )
    names = translations["entity"]["binary_sensor"]
    assert names["window_rear_left"]["name"] == left
    assert names["window_rear_right"]["name"] == right


def _window_snapshot(region, platform, raw_values):
    """Pass physical positions through the real backend and snapshot mappers."""
    identifier = VehicleIdentifier(VIN)
    backend = str(platform or "").strip().lower() if region == "cn" else None
    if backend in {"beantech", "gtsp"}:
        payload = {
            "vehicleStatusInfo": {
                "windows": dict(
                    zip(
                        ("lfWinPosnSts", "rfWinPosnSts", "lbWinPosnSts", "rbWinPosnSts"),
                        raw_values,
                        strict=True,
                    )
                )
            }
        }
        mapper = map_bean_tech_status if backend == "beantech" else map_gtsp_status
        status = mapper(payload, identifier=identifier, vehicle_id=None)
    elif backend == "navinfo":
        status = map_china_status(
            {
                "vehicleSts": {
                    "carStatus": dict(
                        zip(
                            ("drvWinPosnSts", "passWinPosnSts", "rlWinPosnSts", "rrWinPosnSts"),
                            raw_values,
                            strict=True,
                        )
                    )
                }
            },
            identifier=identifier,
            vehicle_id=None,
            network_type=2,
            tank_capacity=None,
        )
    else:
        status = CloudVehicleStatus(
            items=tuple(
                CloudStatusItem(code=code, value=value)
                for code, value in zip(
                    ("2210001", "2210002", "2210003", "2210004"),
                    raw_values,
                    strict=True,
                )
            ),
        )
    return map_vehicle_snapshot(
        CloudVehicle(identifier=identifier, platform=backend),
        status,
        CloudVehicleBasics(),
        refreshed_at=datetime(2026, 11, 5, tzinfo=UTC),
        remote_commands_available=False,
    ).as_dict()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "region,platform,closed,opened,rear_keys",
    [
        ("eu", None, 1, 2, ("window_rear_left_open", "window_rear_right_open")),
        ("aus", None, 1, 3, ("window_rear_left_open", "window_rear_right_open")),
        ("rus", None, 1, 2, ("window_rear_left_open", "window_rear_right_open")),
        ("apac", None, 1, 3, ("window_rear_left_open", "window_rear_right_open")),
        ("eu", "beantech", 1, 2, ("window_rear_left_open", "window_rear_right_open")),
        ("cn", "navinfo", 0, 1, ("window_rear_left_open", "window_rear_right_open")),
        ("cn", "beantech", 1, 2, ("window_rear_right_open", "window_rear_left_open")),
        ("cn", " BeanTech ", 1, 16, ("window_rear_right_open", "window_rear_left_open")),
        ("cn", "gtsp", 5, 2, ("window_rear_right_open", "window_rear_left_open")),
        ("cn", " GTSP ", 5, 0, ("window_rear_right_open", "window_rear_left_open")),
    ],
)
async def test_window_states_and_names_keep_physical_entity_identity_on_reload(
    region,
    platform,
    closed,
    opened,
    rear_keys,
):
    """Opening each physical window updates its existing sensor and correct name."""
    hass, api, coordinator, _, entry = _context(region, platform)

    def refresh(raw_values):
        """Publish new wire values to the existing sensor instances."""
        coordinator.async_set_updated_data(
            {
                "region": region,
                "vehicles": [_window_snapshot(region, platform, raw_values)],
            }
        )

    refresh([closed] * 4)
    added = []
    await setup_binary_sensors(hass, entry, added.extend)
    windows = {
        entity.entity_description.key: entity for entity in added if entity.entity_description.key.startswith("window_")
    }
    assert set(windows) == {
        "window_front_left_open",
        "window_front_right_open",
        "window_rear_left_open",
        "window_rear_right_open",
    }
    physical_entities = dict(
        zip(
            POSITIONS,
            (
                windows["window_front_left_open"],
                windows["window_front_right_open"],
                windows[rear_keys[0]],
                windows[rear_keys[1]],
            ),
            strict=True,
        )
    )
    expected_translations = dict(
        zip(
            POSITIONS,
            (
                "window_front_driver",
                "window_front_passenger",
                "window_rear_left",
                "window_rear_right",
            ),
            strict=True,
        )
    )
    identities = {position: entity.unique_id for position, entity in physical_entities.items()}
    for position, entity in physical_entities.items():
        assert entity.entity_description.translation_key == expected_translations[position]
        assert entity.unique_id == f"{VIN}_{entity.entity_description.key}"
        assert entity.is_on is False

    for index, position in enumerate(POSITIONS):
        values = [closed] * 4
        values[index] = opened
        refresh(values)
        assert {key: entity.is_on for key, entity in physical_entities.items()} == {
            key: key == position for key in POSITIONS
        }
        assert {key: entity.unique_id for key, entity in physical_entities.items()} == identities

    # An absent field must clear a previously open reading, not retain its last state.
    values = [closed] * 4
    values[3] = 4 if region == "cn" and str(platform).strip().lower() == "beantech" else None
    refresh(values)
    assert physical_entities["rear_right"].is_on is None
    assert physical_entities["rear_right"].available
    assert all(physical_entities[position].is_on is False for position in POSITIONS[:3])
    refresh([closed] * 4)
    assert all(entity.is_on is False for entity in windows.values())
    assert len(added) == len({entity.unique_id for entity in added})

    reloaded_hass, _, reloaded_coordinator, _, reloaded_entry = _context(region, platform)
    reloaded_coordinator.async_set_updated_data(coordinator.data)
    reloaded = []
    await setup_binary_sensors(reloaded_hass, reloaded_entry, reloaded.extend)
    reloaded_windows = {
        entity.unique_id: entity for entity in reloaded if entity.entity_description.key.startswith("window_")
    }
    assert set(reloaded_windows) == set(identities.values())
    for entity in windows.values():
        assert (
            reloaded_windows[entity.unique_id].entity_description.translation_key
            == entity.entity_description.translation_key
        )
        assert reloaded_windows[entity.unique_id].is_on is False

    buttons = []
    await setup_buttons(hass, entry, buttons.extend)
    close_buttons = [entity for entity in buttons if isinstance(entity, GwmCloseWindowsButton)]
    assert len(close_buttons) == 1
    assert close_buttons[0].unique_id == f"{VIN}_close_windows"
    api.async_vehicle_control.assert_not_awaited()
