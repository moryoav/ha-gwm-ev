"""Offline parity tests for the four-region normalized snapshot boundary."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from gwm_client import (
    ChinaVehicle,
    CloudClimateConfiguration,
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    VehicleIdentifier,
    VehicleSnapshot,
    VehicleValues,
    is_valid_operation_time,
    map_vehicle_snapshot,
    normalize_operation_time,
    normalize_temperature,
    valid_temperature,
)
from gwm_client.china_status import map_bean_tech_status, map_china_status
from gwm_client.models import (
    FrozenJsonValue,
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)

_FIXTURES = Path(__file__).with_name("fixtures")
_REFRESHED_AT = datetime(2026, 8, 28, 12, 34, 56, 789000, tzinfo=UTC)


def _item(code: str, value: object, unit: str | None = None) -> CloudStatusItem:
    return CloudStatusItem(code=code, value=cast("FrozenJsonValue", value), unit=unit)


def _map(
    *,
    items: tuple[CloudStatusItem, ...] = (),
    basics: CloudVehicleBasics | None = None,
    acquisition_time_ms: int | None = 1_700_000_000_000,
    update_time_ms: int | None = 1_700_000_100_000,
    latitude: float | None = 32.1,
    longitude: float | None = 34.8,
) -> VehicleSnapshot:
    return map_vehicle_snapshot(
        CloudVehicle(
            identifier=VehicleIdentifier("SYNTHETIC+OPAQUE/ID="),
            app_show_series_name="Synthetic series",
            brand_name="GWM",
            vehicle_type="BEV",
        ),
        CloudVehicleStatus(
            device_id="SYNTHETIC-DEVICE",
            acquisition_time_ms=acquisition_time_ms,
            update_time_ms=update_time_ms,
            latitude=latitude,
            longitude=longitude,
            items=items,
        ),
        basics or CloudVehicleBasics(),
        refreshed_at=_REFRESHED_AT,
        remote_commands_available=True,
        command_status="idle",
    )


def test_complete_known_signal_contract_matches_addon_mapper() -> None:
    snapshot = _map(
        items=(
            _item("2013021", 80, "%"),
            _item("2011501", 210, "km"),
            _item("2017002", 45, "L"),
            _item("2011007", 418, "km"),
            _item("2013022", 32, "min"),
            _item("2041301", 94, "%"),
            _item("2101001", 231, "kPa"),
            _item("2101002", 232, "kPa"),
            _item("2101003", 233, "kPa"),
            _item("2101004", 234, "kPa"),
            _item("2101005", 31, "C"),
            _item("2101006", 32, "C"),
            _item("2101007", 33, "C"),
            _item("2101008", 34, "C"),
            _item("2103010", 12345, "km"),
            _item("2201001", 234, "C"),
            _item("2041142", 1),
            _item("2042082", 1),
            _item("2202001", 1),
            _item("2208001", 0),
            _item("2210001", 1),
            _item("2210002", 0),
            _item("2210003", 2),
            _item("2210004", 1),
            _item("2206002", 1),
            _item("2206004", 0),
            _item("2206003", 0),
            _item("2206005", 1),
            _item("2206001", 0),
            _item("2210005", 3),
            _item("2078020", 1),
            _item("2222001", 0),
            _item("2210032", 1),
            _item("2310001", 1),
            _item("2102001", 1),
            _item("2102002", 0),
            _item("2102003", 2),
            _item("2102004", 3),
            _item("2102007", 4),
            _item("2102008", 5),
            _item("2102009", 6),
            _item("2102010", 7),
            _item("2210011", 0),
            _item("2210010", 1),
            _item("2210013", 2),
            _item("2210012", 3),
            _item("2060016", 1),
            _item("2424001", 2),
            _item("2424002", 3),
            _item("2202111", 1),
            _item("2016001", 2),
            _item("2220001", 3),
            _item("2220002", 2),
            _item("2220003", 3),
            _item("2220004", 1),
        ),
        basics=CloudVehicleBasics(
            climate=CloudClimateConfiguration(temperature="23", operation_time="900")
        ),
    )

    assert snapshot.values == VehicleValues(
        soc=80,
        range_km=210,
        fuel_level_l=45,
        fuel_range_km=418,
        remaining_charging_time_min=32,
        soce=94,
        tire_pressure_front_left_kpa=231,
        tire_pressure_front_right_kpa=232,
        tire_pressure_rear_left_kpa=233,
        tire_pressure_rear_right_kpa=234,
        tire_temperature_front_left_c=31,
        tire_temperature_front_right_c=32,
        tire_temperature_rear_left_c=33,
        tire_temperature_rear_right_c=34,
        odometer_km=12345,
        interior_temperature_c=23.4,
        charging_status="charging",
        charging_active=True,
        charge_plug_connected=True,
        ac_active=True,
        locked=True,
        window_front_left_open=False,
        window_front_right_open=True,
        window_rear_left_open=True,
        window_rear_right_open=False,
        window_front_driver_open=False,
        window_front_passenger_open=True,
        window_rear_driver_side_open=False,
        window_rear_passenger_side_open=True,
        door_front_driver_open=True,
        door_front_passenger_open=False,
        door_rear_driver_side_open=False,
        door_rear_passenger_side_open=True,
        trunk_open=False,
        sunroof_position_code=3,
        air_circulation=True,
        front_defroster=False,
        rear_defroster=True,
        gps_authorized=True,
        tire_pressure_state_front_left=1,
        tire_pressure_state_front_right=0,
        tire_pressure_state_rear_left=2,
        tire_pressure_state_rear_right=3,
        tire_temperature_state_front_left=4,
        tire_temperature_state_front_right=5,
        tire_temperature_state_rear_left=6,
        tire_temperature_state_rear_right=7,
        window_learn_front_left=0,
        window_learn_front_right=1,
        window_learn_rear_left=2,
        window_learn_rear_right=3,
        steering_wheel_heater_active=True,
        rear_left_seat_heater_level=2,
        rear_right_seat_heater_level=3,
        front_windscreen_heater_active=True,
        engine_state_code=2,
        front_driver_seat_heater_level=3,
        front_passenger_seat_heater_level=2,
        front_driver_seat_vent_level=3,
        front_passenger_seat_vent_level=1,
    )
    assert snapshot.climate.mode == "auto"
    assert snapshot.climate.action is None
    assert snapshot.climate.target_temperature_c == 23
    assert snapshot.climate.operation_time_minutes == 15
    assert snapshot.climate.current_temperature_c == 23.4
    assert snapshot.raw_items["2013021"].value == "80"
    assert snapshot.raw_items["2013021"].unit == "%"
    json.dumps(snapshot.as_dict(), allow_nan=False)


@pytest.mark.parametrize(
    ("filename", "allow_stringified_numbers", "allow_numbers_for_strings", "expected_soc"),
    [
        ("eu_read_responses_v1.json", False, False, None),
        ("anz_read_responses_v1.json", True, False, None),
        ("russia_read_responses_v1.json", True, True, 61),
    ],
)
def test_overseas_region_fixtures_reach_the_normalized_snapshot_boundary(
    filename: str,
    allow_stringified_numbers: bool,
    allow_numbers_for_strings: bool,
    expected_soc: float | None,
) -> None:
    fixture = cast(
        "dict[str, object]",
        json.loads((_FIXTURES / filename).read_text(encoding="utf-8")),
    )
    responses = cast("dict[str, object]", fixture["responses"])
    vehicles = parse_cloud_vehicles(
        responses["acquire_vehicles"],
        allow_numbers_for_strings=allow_numbers_for_strings,
    )
    status = parse_cloud_vehicle_status(
        responses["get_last_status"],
        allow_stringified_numbers=allow_stringified_numbers,
        allow_numbers_for_strings=allow_numbers_for_strings,
    )
    basics = parse_cloud_vehicle_basics(
        responses["get_vehicle_basics"],
        allow_numbers_for_strings=allow_numbers_for_strings,
    )

    snapshot = map_vehicle_snapshot(
        vehicles[0],
        status,
        basics,
        refreshed_at=_REFRESHED_AT,
        remote_commands_available=False,
    )
    serialized = snapshot.as_dict()

    assert snapshot.vin == fixture["identifier"]
    assert snapshot.name.startswith("Synthetic ")
    assert snapshot.values.soc == expected_soc
    assert snapshot.timestamps.last_refresh == _REFRESHED_AT
    assert serialized["command_status"] == "No remote command has run yet"
    assert serialized["raw_items"]
    assert "SYNTHETIC-owner@example.invalid" not in json.dumps(serialized)


def test_china_fixture_translation_reaches_the_same_normalized_snapshot_boundary() -> None:
    fixture = cast(
        "dict[str, object]",
        json.loads((_FIXTURES / "china_poc_contracts_v1.json").read_text(encoding="utf-8")),
    )
    discovery_response = cast("dict[str, object]", fixture["discovery_response"])
    discovery_data = cast("dict[str, object]", discovery_response["data"])
    raw_vehicle = cast("list[dict[str, object]]", discovery_data["acquireVehiclesList"])[0]
    identifier = VehicleIdentifier(cast("str", raw_vehicle["vin"]))
    vehicle = ChinaVehicle(
        identifier=identifier,
        app_show_series_name=cast("str", raw_vehicle["appShowSeriesName"]),
        brand_name=cast("str", raw_vehicle["brandName"]),
        vehicle_type=cast("str", raw_vehicle["vtype"]),
        vehicle_id=cast("str", raw_vehicle["vehicleId"]),
        platform=cast("str", raw_vehicle["belongPlatform"]),
        network_type=int(cast("str", raw_vehicle["vehicleNetworkType"])),
    )
    response = cast("dict[str, object]", fixture["status_response"])
    status = map_china_status(
        cast("dict[str, object]", response["body"]),
        identifier=identifier,
        vehicle_id=vehicle.vehicle_id,
        network_type=vehicle.network_type,
        tank_capacity=vehicle.tank_capacity,
    )

    snapshot = map_vehicle_snapshot(
        vehicle,
        status,
        CloudVehicleBasics(),
        refreshed_at=_REFRESHED_AT,
        remote_commands_available=False,
    )

    assert snapshot.name == "Synthetic Series"
    assert snapshot.manufacturer == "Synthetic Brand"
    assert snapshot.model == "SYNTHETIC"
    assert snapshot.values.soc == 78
    assert snapshot.values.soce == 95
    assert snapshot.values.odometer_km is None
    assert snapshot.values.locked is True
    assert snapshot.timestamps.acquisition_time == datetime(2024, 8, 12, 9, 59, 49, tzinfo=UTC)
    assert snapshot.raw_items["2013021"].value == "78"
    json.dumps(snapshot.as_dict(), allow_nan=False)


def test_bean_tech_fixture_reaches_platform_aware_snapshot_without_commands() -> None:
    fixture = cast(
        "dict[str, object]",
        json.loads((_FIXTURES / "china_beantech_status_v1.json").read_text(encoding="utf-8")),
    )
    identifier = VehicleIdentifier(cast("str", fixture["vin"]))
    vehicle = ChinaVehicle(
        identifier=identifier,
        app_show_series_name="Synthetic BeanTech Series",
        brand_name="Synthetic Brand",
        vehicle_type="SYNTHETIC-BEAN",
        vehicle_id="SYNTHETIC-VEHICLE-3",
        platform=" BeanTech ",
        network_type=4,
    )
    response = cast("dict[str, object]", fixture["response"])
    status = map_bean_tech_status(
        response,
        identifier=identifier,
        vehicle_id=vehicle.vehicle_id,
    )

    snapshot = map_vehicle_snapshot(
        vehicle,
        status,
        CloudVehicleBasics(),
        refreshed_at=_REFRESHED_AT,
        remote_commands_available=False,
        charging_control_available=True,
    )
    serialized = snapshot.as_dict()

    assert snapshot.platform == "beantech"
    assert snapshot.capabilities.remote_commands is False
    assert snapshot.capabilities.charging_control is False
    assert snapshot.values.soc == 71
    assert snapshot.values.range_km == 75
    assert snapshot.values.fuel_range_km == 306
    assert snapshot.values.fuel_level_l == 29
    assert snapshot.values.remaining_charging_time_min == 12
    assert snapshot.values.charging_status == "charging_complete"
    assert snapshot.values.charging_active is False
    assert snapshot.values.near_beam_active is True
    assert snapshot.values.far_beam_active is False
    assert snapshot.values.charge_soc == 82.5
    assert snapshot.values.acc_clean_off == 0
    assert snapshot.values.tire_pressure_indicator_front_left is False
    assert snapshot.values.tire_pressure_indicator_front_right is True
    assert snapshot.values.tire_pressure_indicator_rear_left is None
    assert snapshot.values.tire_pressure_indicator_rear_right is None
    assert snapshot.values.aux_battery_level == 90
    assert snapshot.values.remaining_usable_charge_percent == 68
    assert snapshot.values.battery_pack_current == 23.4
    assert snapshot.values.battery_pack_voltage == 398.7
    assert serialized["platform"] == "beantech"
    assert serialized["capabilities"] == {
        "remote_commands": False,
        "charging_control": False,
    }
    json.dumps(serialized, allow_nan=False)


def test_missing_optional_signals_stay_unknown_and_identity_fallbacks_match() -> None:
    snapshot = map_vehicle_snapshot(
        CloudVehicle(
            identifier=VehicleIdentifier("SYNTHETIC-ID"),
            app_show_series_name="  ",
            vehicle_nickname="Nickname",
            brand_name=" ",
            other_brand_name=None,
        ),
        CloudVehicleStatus(),
        CloudVehicleBasics(),
        refreshed_at=_REFRESHED_AT,
        remote_commands_available=False,
        command_status="idle",
    )

    assert snapshot.name == "Nickname"
    assert snapshot.manufacturer == "GWM"
    assert snapshot.model == ""
    assert snapshot.location is None
    assert snapshot.timestamps.acquisition_time is None
    assert snapshot.timestamps.update_time is None
    assert all(value is None for value in snapshot.values.as_dict().values())
    assert snapshot.climate.mode == "off"
    assert snapshot.climate.action == "off"
    assert snapshot.raw_items == {}
    serialized_values = cast("dict[str, object]", snapshot.as_dict()["values"])
    assert "front_driver_seat_vent_level" in serialized_values


def test_malformed_values_fail_closed_and_latest_non_null_duplicate_wins() -> None:
    snapshot = _map(
        items=(
            _item(" ", 1),
            _item("2013021", math.nan, "%"),
            _item("2011501", "Infinity", "km"),
            _item("2017002", -1, "L"),
            _item(" 2011007 ", 100, "km"),
            _item("2011007", 200, "km"),
            _item("2011007", None, "km"),
            _item("2206002", 1.0),
            _item("2206004", "unknown"),
            _item("2210001", "unknown"),
            _item("2102001", 1.5),
            _item("2220001", 4),
            _item("2220002", "3.0"),
            _item("2220003", -1),
            _item("NESTED", {"flag": True, "levels": (1, None, "synthetic")}),
        ),
        acquisition_time_ms=(1 << 63) - 1,
        update_time_ms=(1 << 63) - 1,
        latitude=math.nan,
        longitude=181.0,
    )

    assert snapshot.values.soc is None
    assert snapshot.values.range_km is None
    assert snapshot.values.fuel_level_l is None
    assert snapshot.values.fuel_range_km == 200
    assert snapshot.values.door_front_driver_open is True
    assert snapshot.values.door_front_passenger_open is None
    assert snapshot.values.window_front_driver_open is None
    assert snapshot.values.tire_pressure_state_front_left is None
    assert snapshot.values.front_driver_seat_heater_level is None
    assert snapshot.values.front_passenger_seat_heater_level == 3
    assert snapshot.values.front_driver_seat_vent_level is None
    assert snapshot.timestamps.acquisition_time is None
    assert snapshot.timestamps.update_time is None
    assert snapshot.location is None
    assert snapshot.raw_items["2011007"].value == "200"
    assert snapshot.raw_items["2013021"].value == "NaN"
    assert snapshot.raw_items["NESTED"].value == '{"flag":true,"levels":[1,null,"synthetic"]}'
    json.dumps(snapshot.as_dict(), allow_nan=False)


@pytest.mark.parametrize(
    ("charge_status", "plug_status", "expected_status", "expected_active"),
    [
        (0, 0, "disconnected", False),
        (0, 1, "connected", False),
        (1, 1, "charging", True),
        (2, 1, "awaiting_charging", False),
        (3, 1, "charging_complete", False),
        (5, 1, "waiting_for_power", False),
        (6, 1, "error", False),
        (7, 1, None, None),
    ],
)
def test_charge_status_matrix(
    charge_status: int,
    plug_status: int,
    expected_status: str | None,
    expected_active: bool | None,
) -> None:
    values = _map(
        items=(
            _item("2041142", charge_status),
            _item("2042082", plug_status),
        )
    ).values

    assert values.charging_status == expected_status
    assert values.charging_active == expected_active


@pytest.mark.parametrize(
    ("value", "expected"),
    [("300", 5), ("900", 15), ("1800", 30), ("30", 30), ("25", 25)],
)
def test_operation_time_normalization(value: str, expected: int) -> None:
    assert normalize_operation_time(value, 17) == expected


@pytest.mark.parametrize("value", ["200", "301", "invalid", "1_800", None])
def test_invalid_operation_time_uses_fallback(value: str | None) -> None:
    assert normalize_operation_time(value, 17) == 17


@pytest.mark.parametrize(
    ("value", "expected"),
    [(5, True), (15, True), (30, True), (4, False), (16, True), (31, False)],
)
def test_operation_time_validation(value: int, expected: bool) -> None:
    assert is_valid_operation_time(value) is expected


def test_temperature_normalization_and_validation() -> None:
    assert normalize_temperature("15", 22) == 16
    assert normalize_temperature("33", 22) == 32
    assert normalize_temperature("invalid", 21) == 21
    assert normalize_temperature("2_2", 21) == 21
    assert valid_temperature("16") == 16
    assert valid_temperature("32") == 32
    assert valid_temperature("15") is None
    assert valid_temperature("33") is None
    assert valid_temperature(None) is None


def test_mapping_requires_an_aware_refresh_time() -> None:
    with pytest.raises(ValueError, match="last_refresh_invalid"):
        map_vehicle_snapshot(
            CloudVehicle(identifier=VehicleIdentifier("SYNTHETIC-ID")),
            CloudVehicleStatus(),
            CloudVehicleBasics(),
            refreshed_at=datetime(2026, 8, 28),
            remote_commands_available=False,
        )


def test_normalized_model_reprs_do_not_expose_identifiers_or_telemetry() -> None:
    snapshot = _map(items=(_item("2013021", 80, "%"),))

    representations = (
        repr(snapshot),
        repr(snapshot.location),
        repr(snapshot.timestamps),
        repr(snapshot.values),
        repr(snapshot.climate),
        repr(snapshot.raw_items["2013021"]),
    )
    assert all("SYNTHETIC" not in value for value in representations)
    assert all("soc=80" not in value for value in representations)
    assert all("value='80'" not in value for value in representations)
