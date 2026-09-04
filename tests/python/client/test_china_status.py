from __future__ import annotations

import json
import math
from pathlib import Path
from typing import cast

import pytest

from gwm_client.china_status import map_bean_tech_status, map_china_status
from gwm_client.models import CloudVehicleStatus, VehicleIdentifier

_VIN = "LGWTEST0000000001"
_BEAN_FIXTURE = json.loads(
    (Path(__file__).with_name("fixtures") / "china_beantech_status_v1.json").read_text(
        encoding="utf-8"
    )
)


def _map(
    data: object,
    *,
    vehicle_id: str | None = "SYNTHETIC-VEHICLE-1",
    network_type: int | None = 2,
    tank_capacity: object = 56,
) -> CloudVehicleStatus:
    return map_china_status(
        data,
        identifier=VehicleIdentifier(_VIN),
        vehicle_id=vehicle_id,
        network_type=network_type,
        tank_capacity=tank_capacity,
    )


def _items(status: CloudVehicleStatus) -> dict[str, tuple[object, str | None]]:
    return {item.code: (item.value, item.unit) for item in status.items}


def _map_bean(data: object) -> CloudVehicleStatus:
    return map_bean_tech_status(
        data,
        identifier=VehicleIdentifier(_BEAN_FIXTURE["vin"]),
        vehicle_id="SYNTHETIC-VEHICLE-3",
    )


def test_bean_tech_fixture_maps_released_and_platform_specific_signals() -> None:
    status = _map_bean(_BEAN_FIXTURE["response"])
    items = _items(status)

    assert status.device_id == "SYNTHETIC-BEAN-DEVICE"
    assert status.acquisition_time_ms == 1723456789000
    assert status.update_time_ms == 1723456790000
    assert status.latitude == 1.25
    assert status.longitude == -2.5
    assert items["2103010"] == ("22883", "km")
    assert items["2011501"] == ("75", "km")
    assert items["2011007"] == ("306", "km")
    assert items["2017002"] == ("29", "L")
    assert items["2013021"] == ("71", "%")
    assert items["9000025"] == ("68", "%")
    assert items["9000024"] == ("90", "%")
    assert items["2101001"] == ("248", "kPa")
    assert items["2101008"] == ("38", "°C")
    assert items["2208001"] == ("0", None)
    assert items["2206002"] == ("1", None)
    assert items["2210001"] == ("1", None)
    assert items["2210002"] == ("0", None)
    assert items["2210004"] == ("0", None)
    assert items["2210003"] == ("1", None)
    assert items["2041142"] == ("3", None)
    assert items["2013022"] == ("12", "min")
    assert items["2201001"] == ("235", None)
    assert items["9000001"] == ("1", None)
    assert items["9000011"] == ("82.5", "%")
    assert items["9000026"] == ("23.4", None)
    assert items["9000027"] == ("398.7", None)
    assert items["9000014"] == ("5.916", "kW")
    assert items["9000023"] == ("3", None)
    assert items["2310001"] == ("1", None)
    assert _BEAN_FIXTURE["vin"] not in repr(status)


def test_bean_tech_sparse_v3_pack_fields_map() -> None:
    status = _map_bean(
        {
            "data": {
                "vehicleStatusInfo": {
                    "efficiency": 5916.0,
                    "battPackCurr": 17,
                    "battPackVolt": 348,
                }
            }
        }
    )
    items = _items(status)
    assert items["9000014"] == ("5.916", "kW")
    assert items["9000026"] == ("17", None)
    assert items["9000027"] == ("348", None)


def test_bean_tech_power_falls_back_when_efficiency_absent() -> None:
    status = _map_bean(
        {
            "data": {
                "vehicleStatusInfo": {
                    "mileage": "1, km",
                    "power": 12.5,
                }
            }
        }
    )
    assert _items(status)["9000014"] == ("12.5", None)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": {"vehicleStatusInfo": {}}},
        {"data": {"vehicleStatusInfo": {"door": []}}},
        {"data": {"vehicleStatusInfo": {"door": {}, "DOOR": {}}}},
        {"data": {"vehicleStatusInfo": {"mileage": {"value": 1}}}},
        {"data": {"vehicleStatusInfo": {"mileage": math.inf}}},
    ],
)
def test_bean_tech_malformed_or_unrecognized_shapes_fail_closed(payload: object) -> None:
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map_bean(payload)


def test_verified_vv6_status_maps_to_existing_signal_contract() -> None:
    source = {
        "vehicleSts": {
            "lastUpdate": 1723456789000,
            "battSts": {
                "battSoc": "78",
                "battSoh": "95",
                "hcuEVContnsDistance": "123",
                "bmsDCChrgConnect": "1",
                "bmsChrgsts": "1",
                "chgSts": 1,
                "chgTime": 45,
            },
            "carStatus": {
                "drvDoorLockSts": 2,
                "drvDoorSts": 1,
                "passDoorSts": 0,
                "rlDoorSts": 0,
                "rrDoorSts": 1,
                "trunkSts": 0,
                "drvWinPosnSts": 1,
                "passWinPosnSts": 0,
                "rlWinPosnSts": 0,
                "rrWinPosnSts": 1,
                "vehTotDistance": "45678",
                "remainFuelSts": 1,
                "remainFuel": "320",
                "oilQty": 4,
                "lat": "31.2",
                "lon": "121.5",
                "cdngoffValid": "1",
                "cdngoff": "0",
                "drvTirePress": "240",
                "passTirePress": "241",
                "rlTirePress": "242",
                "rrTirePress": "243",
            },
        }
    }

    status = _map(source)
    items = _items(status)

    assert status.device_id == "SYNTHETIC-VEHICLE-1"
    assert status.acquisition_time_ms == 1723456789000
    assert status.update_time_ms == 1723456789000
    assert status.latitude == 31.2
    assert status.longitude == 121.5
    assert items["2013021"] == ("78", "%")
    assert items["2011501"] == ("123", "km")
    assert items["2013022"] == ("45", "min")
    assert items["2041301"] == ("95", "%")
    assert items["2017002"] == ("28", "L")
    assert items["2011007"] == ("123", "km")
    assert items["2103010"] == ("45678", "km")
    assert items["2041142"] == ("1", None)
    assert items["2042082"] == ("1", None)
    assert items["2202001"] == ("1", None)
    assert items["2208001"] == ("0", None)
    assert items["2206002"] == ("1", None)
    assert items["2206005"] == ("1", None)
    assert items["2210001"] == ("0", None)
    assert items["2210003"] == ("1", None)
    assert items["2101001"] == ("240", "kPa")
    assert items["2101004"] == ("243", "kPa")
    assert items["2310001"] == ("1", None)


def test_vv6_fallbacks_match_live_corrected_values() -> None:
    status = _map(
        {
            "vehicleSts": {
                "battSts": {},
                "carStatus": {
                    "drvDoorLockSts": 0,
                    "drvTirePress": "266",
                    "drvTireTemp": "41",
                    "passTirePress": "266",
                    "passTireTemp": "36",
                    "rlTirePress": "279",
                    "rlTireTemp": "36",
                    "rrTirePress": "248",
                    "rrTireTemp": "35",
                    "hcuEvcontnsdistance": "204",
                    "remainFuel": "24",
                    "remainFuelSts": 1,
                    "soc": "46",
                    "vehTotDistance": "56040",
                },
            }
        }
    )
    items = _items(status)

    assert items["2013021"] == ("46", "%")
    assert items["2011501"] == ("204", "km")
    assert items["2017002"] == ("24", "L")
    assert items["2011007"] == ("204", "km")
    assert items["2103010"] == ("56040", "km")
    assert items["2208001"] == ("0", None)
    assert [items[f"210100{index}"][0] for index in range(1, 5)] == ["266", "266", "279", "248"]
    assert [items[f"210100{index}"][0] for index in range(5, 9)] == ["41", "36", "36", "35"]


def test_dedicated_battery_soc_wins_over_car_status_fallback() -> None:
    items = _items(
        _map(
            {
                "vehicleSts": {
                    "battSts": {"battSoc": "78"},
                    "carStatus": {"soc": "46"},
                }
            }
        )
    )

    assert items["2013021"] == ("78", "%")


def test_status_body_fallback_upload_time_and_identifier_fallback() -> None:
    status = _map(
        {"carStatus": {"uploadTime": "1723456789001", "vehTotDistance": 123}},
        vehicle_id="  ",
    )

    assert status.device_id == _VIN
    assert status.acquisition_time_ms == 1723456789001
    assert status.update_time_ms == 1723456789001
    assert _items(status)["2103010"] == ("123", "km")


def test_full_body_and_comfort_signal_matrix() -> None:
    status = _map(
        {
            "vehicleSts": {
                "battSts": {"bmsDCChrgConnect": 1, "bmsChrgsts": 2},
                "carStatus": {
                    "drvTirePressState": 1,
                    "passTirePressState": "2",
                    "rlTirePressState": 3,
                    "rrTirePressState": 4,
                    "drvTireTempState": 5,
                    "passTireTempState": 6,
                    "rlTireTempState": 7,
                    "rrTireTempState": 8,
                    "srPosnSts": 3,
                    "drvWinLrnSts": 1,
                    "passWinLrnSts": 0,
                    "rlWinLrnSts": 1,
                    "rrWinLrnSts": 0,
                    "achtdrrwndValid": 1,
                    "rearDefrostState": 1,
                    "steerwheelheatdsts": 0,
                    "engstsValid": 1,
                    "engSts": 1,
                    "driverseatheatstsValid": 1,
                    "passseatheatstsValid": 1,
                    "driverseatventstsValid": 1,
                    "passseatventstsValid": 1,
                    "seatHeatingMainState": 2,
                    "seatHeatingDeputyState": 1,
                },
            }
        }
    )
    items = _items(status)

    assert items["2041142"] == ("3", None)
    assert items["2102001"] == ("1", None)
    assert items["2102004"] == ("4", None)
    assert items["2102007"] == ("5", None)
    assert items["2102010"] == ("8", None)
    assert items["2210005"] == ("3", None)
    assert items["2210011"] == ("1", None)
    assert items["2210010"] == ("0", None)
    assert items["2210013"] == ("1", None)
    assert items["2210012"] == ("0", None)
    assert items["2210032"] == ("1", None)
    assert items["2060016"] == ("0", None)
    assert items["2016001"] == ("1", None)
    assert items["2220001"] == ("0", None)
    assert items["2220002"] == ("1", None)
    assert items["2220003"] == ("1", None)
    assert items["2220004"] == ("0", None)


@pytest.mark.parametrize(("raw", "expected"), [(2, "3"), (3, "6"), (4, "4")])
def test_dc_charge_status_normalization(raw: int, expected: str) -> None:
    items = _items(
        _map({"vehicleSts": {"battSts": {"bmsDCChrgConnect": 2, "bmsChrgsts": raw}}})
    )

    assert items["2041142"] == (expected, None)
    assert items["2042082"] == ("1", None)


def test_obc_and_fallback_charge_status_are_supported() -> None:
    items = _items(_map({"vehicleSts": {"battSts": {"obcSts": "1", "chgSts": 6}}}))

    assert items["2041142"] == ("6", None)
    assert items["2042082"] == ("1", None)


def test_tire_sentinels_and_negative_charge_time_are_omitted() -> None:
    items = _items(
        _map(
            {
                "vehicleSts": {
                    "battSts": {"chgTime": -1},
                    "carStatus": {
                        "drvTirePress": 349,
                        "passTirePress": "350",
                        "rlTireTemp": -50,
                    },
                }
            }
        )
    )

    assert "2013022" not in items
    assert "2101001" not in items
    assert "2101002" not in items
    assert "2101007" not in items


def test_fuel_validation_uses_safe_tank_and_segment_fallbacks() -> None:
    over_capacity = _items(
        _map(
            {
                "vehicleSts": {
                    "carStatus": {"remainFuelSts": "1", "remainFuel": "80", "oilQty": "2.5"}
                }
            },
            tank_capacity="40",
        )
    )
    no_capacity = _items(
        _map(
            {"vehicleSts": {"carStatus": {"remainFuelSts": 0, "oilQty": 4}}},
            tank_capacity="not-a-number",
        )
    )

    assert over_capacity["2017002"] == ("12.5", "L")
    assert "2017002" not in no_capacity


@pytest.mark.parametrize(
    ("network_type", "raw", "expected"),
    [
        (2, 0, "0"),
        (2, 2, "0"),
        (2, 3, "0"),
        (2, 1, "1"),
        (None, 1, "0"),
        (1, 0, "1"),
    ],
)
def test_lock_semantics_depend_on_vehicle_network_type(
    network_type: int | None,
    raw: int,
    expected: str,
) -> None:
    items = _items(
        _map(
            {"vehicleSts": {"carStatus": {"drvDoorLockSts": raw}}},
            network_type=network_type,
        )
    )

    assert items["2208001"] == (expected, None)


def test_coordinates_are_finite_and_gps_signal_requires_both() -> None:
    latitude_only = _map({"vehicleSts": {"carStatus": {"lat": "31.2", "lon": "not-known"}}})
    nonfinite = _map({"vehicleSts": {"carStatus": {"lat": "NaN", "lon": "Infinity"}}})

    assert latitude_only.latitude == 31.2
    assert latitude_only.longitude is None
    assert "2310001" not in _items(latitude_only)
    assert nonfinite.latitude is None
    assert nonfinite.longitude is None
    assert "2310001" not in _items(nonfinite)


def test_case_insensitive_fields_are_accepted_without_retaining_source() -> None:
    source = {"VEHICLESTS": {"CARSTATUS": {"SOc": 46, "VEHTOTDISTANCE": 56040}}}
    status = _map(source)
    source["VEHICLESTS"]["CARSTATUS"]["SOc"] = 99

    assert _items(status)["2013021"] == ("46", "%")
    assert _items(status)["2103010"] == ("56040", "km")
    assert _VIN not in repr(status)
    assert "46" not in repr(status)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {1: "invalid-key"},
        {"vehicleSts": []},
        {"vehicleSts": {"carStatus": []}},
        {"vehicleSts": {}, "VEHICLESTS": {}},
        {"vehicleSts": {"carStatus": {}, "CARSTATUS": {}}},
        {"vehicleSts": {"carStatus": {"lat": math.nan}}},
        {"vehicleSts": {"carStatus": {"soc": {"nested": "invalid"}}}},
    ],
)
def test_malformed_relevant_shapes_fail_closed(payload: object) -> None:
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map(payload)


def test_mapping_bounds_and_metadata_types_fail_closed() -> None:
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map({f"field-{index}": index for index in range(513)})
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        map_china_status(
            {},
            identifier=cast(VehicleIdentifier, object()),
            vehicle_id=None,
            network_type=2,
            tank_capacity=56,
        )
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map({}, network_type=cast(int, True))
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map({}, vehicle_id=cast(str, 123))


@pytest.mark.parametrize("payload", [{}, {"vehicleSts": {}}, {"unrelated": "value"}])
def test_status_without_a_recognized_marker_fails_closed(payload: object) -> None:
    with pytest.raises(ValueError, match="^status_schema_invalid$"):
        _map(payload)
