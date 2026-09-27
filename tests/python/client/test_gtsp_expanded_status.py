"""GTSP-only unit checks, provisional enums, and schema diagnostics."""

import logging
from datetime import UTC, datetime

import pytest
from test_china_gtsp import IDENTIFIER, LOGGER, SECRET, mapped

from gwm_client import CloudVehicle, CloudVehicleBasics, map_vehicle_snapshot
from gwm_client.china_gtsp import _BINARY_FIELDS, _WINDOW_FIELDS


def snapshot(status):
    return map_vehicle_snapshot(
        CloudVehicle(identifier=IDENTIFIER, platform="gtsp"), mapped(status), CloudVehicleBasics(),
        refreshed_at=datetime(2026, 9, 27, tzinfo=UTC), remote_commands_available=False,
    )


def test_all_tires_preserve_wheel_order_units_and_negative_temperatures():
    status = {
        "tirePress": {f"{prefix}TirePressVal": f"{230 + i},kPa" for i, prefix in enumerate(("lf", "rf", "lb", "rb"))},
        "tireTemp": {f"{prefix}TireTempVal": f"{-5 + i},℃" for i, prefix in enumerate(("lf", "rf", "lb", "rb"))},
    }
    values = snapshot(status).values.as_dict()
    for i, position in enumerate(("front_left", "front_right", "rear_left", "rear_right")):
        assert values[f"tire_pressure_{position}_kpa"] == 230 + i
        assert values[f"tire_temperature_{position}_c"] == -5 + i
    items = mapped(status).items
    assert {item.unit for item in items} == {"kPa", "°C"}


@pytest.mark.parametrize("field,value,expected", [
    ("remainOil", "7,L", 7), ("remainOil", "0,l", 0),
    ("remainOil", "7", None), ("remainOil", "7,%", None),
    ("remainOil", "-1,L", None), ("remainOil", "301,L", None),
    ("preMileage", "50,km", 50), ("preMileage", "0,KM", 0),
    ("preMileage", "50", None), ("preMileage", "50,miles", None),
    ("preMileage", "10001,km", None), ("preMileage", "65535,km", None),
])
def test_fuel_requires_explicit_units_and_never_uses_gauge_bars(field, value, expected):
    result = snapshot({field: value, "oilQty": 7})
    assert getattr(result.values, "fuel_level_l" if field == "remainOil" else "fuel_range_km") == expected
    assert result.values.range_km is None


def test_fuel_range_falls_back_only_when_top_level_is_absent():
    assert snapshot({"charge": {"preMileage": "70,km"}}).values.fuel_range_km == 70
    assert snapshot({"preMileage": "50,km", "charge": {"preMileage": "70,km"}}).values.fuel_range_km == 50
    assert snapshot({"preMileage": "bad", "charge": {"preMileage": "70,km"}}).values.fuel_range_km is None


@pytest.mark.parametrize("value,expected", [
    ("-40,C", -40), ("125,°C", 125), ("23,℃", 23),
    ("-50,℃", None), ("128,C", None), ("20,F", None), ("20", None),
    ("NaN,C", None), ("inf,C", None), (True, None), ({}, None),
])
def test_tire_temperature_rejects_unsupported_units_and_invalid_values(value, expected):
    assert snapshot({"tireTemp": {"lfTireTempVal": value}}).values.tire_temperature_front_left_c == expected


@pytest.mark.parametrize("value,expected", [("0,kPa", 0), ("600,kpa", 600),
    ("601,kPa", None), ("-1,kPa", None), ("2.4,bar", None), ("240", None), ("65535,kPa", None)])
def test_tire_pressure_bounds_and_explicit_units(value, expected):
    assert snapshot({"tirePress": {"rfTirePressVal": value}}).values.tire_pressure_front_right_kpa == expected


@pytest.mark.parametrize("raw,expected", [(0, "0"), (1, "1"), ("1", "1"), (2, None), (-1, None),
    (255, None), (True, None), ("1,%", None), ("bad", None), (1.5, None)])
@pytest.mark.parametrize("field,code", list(_BINARY_FIELDS.items()))
def test_only_binary_door_codes_reach_the_shared_mapper(field, code, raw, expected):
    items = {item.code: item.value for item in mapped({"door": {field: raw}}).items}
    assert items.get(code) == expected


@pytest.mark.parametrize("raw,expected", [(0, True), (1, True), (2, True), (3, True), (4, True),
    (5, False), (6, None), (255, None), (-1, None), (True, None), ("5,%", None), ("bad", None)])
@pytest.mark.parametrize("field,key", [
    ("lfwinposnsts", "window_front_driver_open"), ("rfwinposnsts", "window_front_passenger_open"),
    ("lbwinposnsts", "window_rear_driver_side_open"), ("rbwinposnsts", "window_rear_passenger_side_open"),
])
def test_provisional_window_enum_and_rear_sides(field, key, raw, expected):
    assert getattr(snapshot({"windows": {field: raw}}).values, key) is expected


def test_lock_is_provisional_read_only_and_not_navinfo_network_conversion():
    locked = snapshot({"door": {"mainDrveDoorLockSts": 0, "mainDrveDoorSts": 1, "viceDoorSts": 0}})
    assert locked.values.locked is True
    assert locked.values.door_front_driver_open is True
    assert locked.values.door_front_passenger_open is False
    assert snapshot({"door": {"mainDrveDoorLockSts": 1}}).values.locked is False
    assert snapshot({"door": {"mainDrveDoorLockSts": 2}}).values.locked is None
    assert not any(locked.capabilities.as_dict().values())


@pytest.mark.parametrize("group", ["door", "windows", "tirePress", "tireTemp"])
@pytest.mark.parametrize("bad", [None, [], "bad", {"x": 0, "X": 1}, {str(i): 0 for i in range(513)}])
def test_bad_optional_groups_do_not_discard_valid_battery_status(group, bad):
    result = snapshot({"powerBatteryPercent": "60,%", group: bad})
    assert result.values.soc == 60
    assert result.values.locked is None
    assert result.values.tire_pressure_front_left_kpa is None


def test_new_model_fields_stay_raw_and_shape_logging_does_not_expose_values(caplog):
    status = {"cbnTemp": "23,C", "bmsPackVolt": "350,V", "bmsPackCurr": "-4,A", "vcuChrgPowerDisp": "1.4,kW",
        "powertrainSts": "2", "hcuGearSts": "3", "engineSts": "1", "airConditionSts": "1",
        "door": {"backDoorSts": "1", SECRET: SECRET}, "windows": {"skyLightSts": "5", "lfWinLearnSts": "1"}}
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = snapshot(status)
    for field in ("cbntemp", "bmspackvolt", "bmspackcurr", "vcuchrgpowerdisp", "powertrainsts", "hcugearsts"):
        assert f"data.vehiclestatusinfo.{field}:string" in caplog.text
    assert "unit=kw" in caplog.text and "unlisted_fields=1" in caplog.text
    assert SECRET not in caplog.text and "350" not in caplog.text
    assert result.raw_items["gtsp_battery_current_raw"].value == "-4"
    assert result.values.interior_temperature_c is None
    assert result.values.battery_pack_voltage is None
    assert result.values.power is None
    assert result.values.ac_active is None
    assert result.values.sunroof_position_code is None
    assert result.values.charging_active is None
    assert set(_WINDOW_FIELDS.values()).isdisjoint(result.raw_items)
