"""Privacy-minimizing China platform status translation.

The mainland-China services return field-oriented AutoAI ``vehicleSts`` and
BeanTech ``vehicleStatusInfo`` objects instead of the signal-code list used by
the overseas gateways. This module translates only released fields needed by
the typed cloud model and never retains the source mapping.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping

from .models import CloudStatusItem, CloudVehicleStatus, VehicleIdentifier

_INTEGER = re.compile(r"[+-]?[0-9]+")
_MIN_INT32 = -(1 << 31)
_MAX_INT32 = (1 << 31) - 1
_MIN_INT64 = -(1 << 63)
_MAX_INT64 = (1 << 63) - 1
_MAX_OBJECT_MEMBERS = 512
_MAX_SCALAR_LENGTH = 4096
_MAX_DEVICE_ID_LENGTH = 512

type _Object = dict[str, object]


def map_china_status(
    data: object,
    *,
    identifier: VehicleIdentifier,
    vehicle_id: str | None,
    network_type: int | None,
    tank_capacity: object,
) -> CloudVehicleStatus:
    """Translate one AutoAI status body into immutable cloud status items.

    Property lookup follows the case-insensitive C# protocol boundary, while
    case-colliding keys and malformed relevant object shapes are rejected.
    Unknown response sections are ignored and no source object is retained.
    """

    if type(identifier) is not VehicleIdentifier:
        raise ValueError("status_schema_invalid")
    device_id = _validated_device_id(vehicle_id, identifier)
    network = _validated_network_type(network_type)

    root = _copy_object(data)
    status_value = root.get("vehiclests")
    status = root if status_value is None else _copy_object(status_value)
    if all(status.get(name) is None for name in ("lastupdate", "carstatus", "battsts")):
        raise ValueError("status_schema_invalid")
    car = _child_object(status, "carstatus")
    battery = _child_object(status, "battsts")

    last_update = _long(status.get("lastupdate"))
    if last_update is None:
        last_update = _long(_get(car, "uploadtime"))
    if last_update is None:
        last_update = 0

    items: list[CloudStatusItem] = []
    _add(items, "2013021", _first_value(battery, "battsoc", car, "soc"), "%")
    remaining_range = _first_value(
        battery,
        "hcuevcontnsdistance",
        car,
        "hcuevcontnsdistance",
    )
    _add(items, "2011501", remaining_range, "km")
    _add(items, "2013022", _non_negative_value(battery, "chgtime"), "min")
    _add(items, "2041301", _value(battery, "battsoh"), "%")
    if _add_fuel_level(items, car, tank_capacity):
        _add(items, "2011007", remaining_range, "km")

    _add_tire(items, car, "drv", "2101001", "2101005", "2102001", "2102007")
    _add_tire(items, car, "pass", "2101002", "2101006", "2102002", "2102008")
    _add_tire(items, car, "rl", "2101003", "2101007", "2102003", "2102009")
    _add_tire(items, car, "rr", "2101004", "2101008", "2102004", "2102010")

    _add(items, "2103010", _value(car, "vehtotdistance"), "km")
    _add(items, "2041142", _charge_status_value(battery))
    _add(items, "2042082", _charge_plug_code(battery))
    _add(items, "2202001", _air_conditioning_code(car))
    _add(items, "2208001", _lock_code(network, car))

    _add(items, "2210001", _window_code(car, "drvwinposnsts"))
    _add(items, "2210002", _window_code(car, "passwinposnsts"))
    _add(items, "2210003", _window_code(car, "rlwinposnsts"))
    _add(items, "2210004", _window_code(car, "rrwinposnsts"))
    _add(items, "2210005", _value(car, "srposnsts"))
    _add(items, "2210011", _value(car, "drvwinlrnsts"))
    _add(items, "2210010", _value(car, "passwinlrnsts"))
    _add(items, "2210013", _value(car, "rlwinlrnsts"))
    _add(items, "2210012", _value(car, "rrwinlrnsts"))

    _add(items, "2206002", _open_code(car, "drvdoorsts"))
    _add(items, "2206004", _open_code(car, "passdoorsts"))
    _add(items, "2206003", _open_code(car, "rldoorsts"))
    _add(items, "2206005", _open_code(car, "rrdoorsts"))
    _add(items, "2206001", _open_code(car, "trunksts"))
    _add(items, "2210032", _enabled_when_valid(car, "achtdrrwndvalid", "reardefroststate"))
    _add(items, "2060016", _binary_value(car, "steerwheelheatdsts"))
    _add(items, "2016001", _engine_code(car))
    _add(
        items,
        "2220001",
        _comfort_level(car, "driverseatheatstsvalid", "seatheatingmainstate", "1"),
    )
    _add(
        items,
        "2220002",
        _comfort_level(car, "passseatheatstsvalid", "seatheatingdeputystate", "1"),
    )
    _add(
        items,
        "2220003",
        _comfort_level(car, "driverseatventstsvalid", "seatheatingmainstate", "2"),
    )
    _add(
        items,
        "2220004",
        _comfort_level(car, "passseatventstsvalid", "seatheatingdeputystate", "2"),
    )

    latitude = _double(_get(car, "lat"))
    longitude = _double(_get(car, "lon"))
    if latitude is not None and longitude is not None:
        _add(items, "2310001", "1")

    return CloudVehicleStatus(
        device_id=device_id,
        acquisition_time_ms=last_update,
        update_time_ms=last_update,
        latitude=latitude,
        longitude=longitude,
        items=tuple(items),
    )


def map_bean_tech_status(
    data: object,
    *,
    identifier: VehicleIdentifier,
    vehicle_id: str | None,
) -> CloudVehicleStatus:
    """Translate one BeanTech response into immutable cloud status items.

    The released app returns comma-delimited value/unit scalars and several
    nested status groups. Case-colliding keys and malformed relevant objects
    are rejected, while unknown fields are ignored and never retained.
    """

    if type(identifier) is not VehicleIdentifier:
        raise ValueError("status_schema_invalid")

    root = _copy_object(data)
    data_value = root.get("data")
    body = root if data_value is None else _copy_object(data_value)
    status_value = body.get("vehiclestatusinfo")
    status = body if status_value is None else _copy_object(status_value)
    recognizable = {
        "mileage",
        "batterypremileage",
        "powerbatterydisplayval",
        "enginests",
        "door",
        "tirepress",
        "tiretemp",
        "seat",
        "windows",
        "charge",
        "lighting",
    }
    if not any(status.get(name) is not None for name in recognizable):
        raise ValueError("status_schema_invalid")

    door = _child_object(status, "door")
    tire_press = _child_object(status, "tirepress")
    tire_temp = _child_object(status, "tiretemp")
    seat = _child_object(status, "seat")
    windows = _child_object(status, "windows")
    charge = _child_object(status, "charge")
    lighting = _child_object(status, "lighting")
    items: list[CloudStatusItem] = []

    _add_split_non_negative(items, "2103010", status, "mileage")
    _add_split_non_negative(items, "2011501", status, "batterypremileage")
    _add_split_non_negative(items, "2011007", status, "premileage")
    _add_split_non_negative(items, "2017002", status, "remainoil")
    _add_split_percentage(items, "2013021", status, "powerbatterydisplayval")
    _add_split_percentage(items, "9000025", status, "powerbatterypercent")
    _add_split_percentage(items, "9000024", status, "remainelectricpercent")

    for node, property_name, code in (
        (tire_press, "lftirepressval", "2101001"),
        (tire_press, "rftirepressval", "2101002"),
        (tire_press, "lbtirepressval", "2101003"),
        (tire_press, "rbtirepressval", "2101004"),
        (tire_temp, "lftiretempval", "2101005"),
        (tire_temp, "rftiretempval", "2101006"),
        (tire_temp, "lbtiretempval", "2101007"),
        (tire_temp, "rbtiretempval", "2101008"),
    ):
        value, unit = _split_number_unit(node, property_name)
        _add(items, code, value, unit)

    for node, property_name, code in (
        (tire_press, "lftirepresssts", "2102001"),
        (tire_press, "rftirepresssts", "2102002"),
        (tire_press, "lbtirepresssts", "2102003"),
        (tire_press, "rbtirepresssts", "2102004"),
        (tire_temp, "lftiretempsts", "2102007"),
        (tire_temp, "rftiretempsts", "2102008"),
        (tire_temp, "lbtiretempsts", "2102009"),
        (tire_temp, "rbtiretempsts", "2102010"),
        (door, "maindrvedoorlocksts", "2208001"),
        (door, "maindrvedoorsts", "2206002"),
        (door, "vicedoorsts", "2206004"),
        (door, "lbdoorsts", "2206003"),
        (door, "rbdoorsts", "2206005"),
        (door, "tailgateopenupsts", "2206001"),
        (seat, "maindriverseatheatsts", "2220001"),
        (seat, "viceseatheatsts", "2220002"),
        (seat, "maindriverseatventsts", "2220003"),
        (seat, "viceseatventsts", "2220004"),
    ):
        _add(items, code, _value(node, property_name))

    for property_name, code in (
        ("lfwinposnsts", "2210001"),
        ("rfwinposnsts", "2210002"),
        ("lbwinposnsts", "2210004"),
        ("rbwinposnsts", "2210003"),
    ):
        _add(items, code, _window_closed_code(windows, property_name))
    _add(items, "2210005", _value(windows, "skylightsts"))

    for property_name, code in (
        ("lfwinlearnsts", "2210011"),
        ("rfwinlearnsts", "2210010"),
        ("lbwinlearnsts", "2210013"),
        ("rbwinlearnsts", "2210012"),
    ):
        _add(items, code, _value(windows, property_name))

    for property_name, code in (
        ("enginests", "2016001"),
        ("airconditionsts", "2202001"),
        ("backfrost", "2210032"),
        ("frontfrost", "2222001"),
        ("steerwheelheatdsts", "2060016"),
    ):
        _add(items, code, _value(status, property_name))
    _add(items, "2041142", _value(charge, "chargestatus"))
    _add(items, "2042082", _value(charge, "charginggunstatus"))
    charging_time, charging_time_unit = _split_number_unit(charge, "chargingtime")
    _add_non_negative_number(
        items,
        "2013022",
        charging_time,
        charging_time_unit or "min",
    )

    in_car_temperature, _ = _split_number_unit(status, "incartemperature")
    temperature = _double(in_car_temperature)
    if temperature is not None:
        _add(items, "2201001", f"{temperature * 10:.0f}")

    for node, property_name, code in (
        (lighting, "nearbeamsts", "9000001"),
        (lighting, "farbeamsts", "9000002"),
        (lighting, "leftturnlampsts", "9000003"),
        (lighting, "rightturnlampsts", "9000004"),
        (status, "oilalarmsts", "9000005"),
        (status, "enginedoorsts", "9000006"),
        (status, "acautomodests", "9000007"),
        (status, "aircleansts", "9000008"),
        (status, "cabinclean", "9000009"),
        (door, "backdoorsts", "9000010"),
        (charge, "charginggunmodel", "9000012"),
        (status, "hcupowertrainsts", "9000013"),
        (status, "batterypacksts", "9000015"),
        (status, "accbnclnoff", "9000016"),
        (status, "tboxstate", "9000017"),
        (status, "wirelesslevel", "9000018"),
        (status, "oilqty", "9000019"),
        (status, "battpackcurr", "9000026"),
        (status, "battpackvolt", "9000027"),
        (tire_press, "lftirepressindcrsts", "9000020"),
        (tire_press, "rftirepressindcrsts", "9000021"),
        (tire_press, "lbtirepressindcrsts", "9000022"),
        (tire_press, "rbtirepressindcrsts", "9000023"),
    ):
        _add(items, code, _value(node, property_name))
    charge_soc, charge_soc_unit = _split_number_unit(charge, "chargesoc")
    _add_percentage(items, "9000011", charge_soc, charge_soc_unit or "%")

    # ``efficiency`` is the live charging power in watts (== pack current *
    # voltage); the raw ``power`` field stays 0 while parked. Convert to kW.
    efficiency = _object_number(_get(status, "efficiency"))
    if efficiency is not None:
        _add(items, "9000014", _format_three_decimals(efficiency / 1000.0), "kW")

    latitude = _double(body.get("latitude"))
    longitude = _double(body.get("longitude"))
    if latitude is not None and longitude is not None:
        _add(items, "2310001", "1")

    device_id = _validated_device_id(
        _first_non_empty(_value(body, "deviceid"), vehicle_id, identifier.value),
        identifier,
    )
    return CloudVehicleStatus(
        device_id=device_id,
        acquisition_time_ms=_long(body.get("acquisitiontime")) or 0,
        update_time_ms=_long(body.get("updatetime")) or 0,
        latitude=latitude,
        longitude=longitude,
        items=tuple(items),
    )


def _copy_object(value: object) -> _Object:
    if not isinstance(value, Mapping):
        raise ValueError("status_schema_invalid")
    if len(value) > _MAX_OBJECT_MEMBERS:
        raise ValueError("status_schema_invalid")

    result: _Object = {}
    for key, child in value.items():
        if not isinstance(key, str):
            raise ValueError("status_schema_invalid")
        folded = key.casefold()
        if folded in result:
            raise ValueError("status_schema_invalid")
        result[folded] = child
    return result


def _child_object(parent: _Object, name: str) -> _Object | None:
    value = parent.get(name)
    return None if value is None else _copy_object(value)


def _get(node: _Object | None, name: str) -> object:
    return None if node is None else node.get(name)


def _validated_device_id(value: str | None, identifier: VehicleIdentifier) -> str:
    if value is None:
        return identifier.value
    if (
        not isinstance(value, str)
        or len(value) > _MAX_DEVICE_ID_LENGTH
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("status_schema_invalid")
    if not value.strip():
        return identifier.value
    return value


def _validated_network_type(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not _MIN_INT32 <= value <= _MAX_INT32:
        raise ValueError("status_schema_invalid")
    return value


def _scalar_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        result = value
    elif isinstance(value, bool):
        result = "1" if value else "0"
    elif isinstance(value, int):
        if not _MIN_INT64 <= value <= _MAX_INT64:
            raise ValueError("status_schema_invalid")
        result = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("status_schema_invalid")
        result = _format_number(value)
    else:
        raise ValueError("status_schema_invalid")
    if len(result) > _MAX_SCALAR_LENGTH:
        raise ValueError("status_schema_invalid")
    return result


def _value(node: _Object | None, name: str) -> str | None:
    return _scalar_text(_get(node, name))


def _integer(value: object) -> int | None:
    text = _scalar_text(value)
    if text is None:
        return None
    stripped = text.strip()
    if _INTEGER.fullmatch(stripped) is None:
        return None
    parsed = int(stripped)
    return parsed if _MIN_INT32 <= parsed <= _MAX_INT32 else None


def _long(value: object) -> int | None:
    text = _scalar_text(value)
    if text is None:
        return None
    stripped = text.strip()
    if _INTEGER.fullmatch(stripped) is None:
        return None
    parsed = int(stripped)
    return parsed if _MIN_INT64 <= parsed <= _MAX_INT64 else None


def _double(value: object) -> float | None:
    text = _scalar_text(value)
    if text is None:
        return None
    try:
        parsed = float(text.strip())
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def _format_number(value: float) -> str:
    return format(value, ".15g")


def _format_three_decimals(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _first_non_empty(*values: str | None) -> str:
    return next((value for value in values if value is not None and value.strip()), "")


def _first_value(
    first: _Object | None,
    first_property: str,
    second: _Object | None,
    second_property: str,
) -> str:
    return _first_non_empty(_value(first, first_property), _value(second, second_property))


def _add(items: list[CloudStatusItem], code: str, value: str | None, unit: str | None = None) -> None:
    if value is None or not value.strip():
        return
    items.append(CloudStatusItem(code=code, value=value, unit=unit))


def _object_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        parsed = float(value)
    except (OverflowError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _valid_fuel_level(car: _Object | None, tank_capacity: object) -> str | None:
    validity = _integer(_get(car, "remainfuelsts"))
    value = _double(_get(car, "remainfuel"))
    if validity != 1 or value is None or value < 0:
        return None
    capacity = _object_number(tank_capacity)
    if capacity is not None and capacity > 0 and value > capacity:
        return None
    return _format_three_decimals(value)


def _add_fuel_level(
    items: list[CloudStatusItem],
    car: _Object | None,
    tank_capacity: object,
) -> bool:
    direct = _valid_fuel_level(car, tank_capacity)
    if direct is not None:
        _add(items, "2017002", direct, "L")
        return True

    segments = _double(_get(car, "oilqty"))
    capacity = _object_number(tank_capacity)
    if segments is not None and 0 <= segments <= 8 and capacity is not None and capacity > 0:
        _add(items, "2017002", _format_three_decimals(segments * capacity / 8), "L")
        return True
    return False


def _add_tire(
    items: list[CloudStatusItem],
    car: _Object | None,
    prefix: str,
    pressure_code: str,
    temperature_code: str,
    pressure_state_code: str,
    temperature_state_code: str,
) -> None:
    pressure = _value(car, prefix + "tirepress")
    if pressure not in {"349", "350"}:
        _add(items, pressure_code, pressure, "kPa")
    temperature = _value(car, prefix + "tiretemp")
    if temperature != "-50":
        _add(items, temperature_code, temperature, "°C")
    _add(items, pressure_state_code, _value(car, prefix + "tirepressstate"))
    _add(items, temperature_state_code, _value(car, prefix + "tiretempstate"))


def _charge_plug_code(battery: _Object | None) -> str | None:
    dc = _integer(_get(battery, "bmsdcchrgconnect"))
    obc = _integer(_get(battery, "obcsts"))
    if dc is None and obc is None:
        return None
    return "1" if dc in {1, 2} or obc == 1 else "0"


def _charge_status_value(battery: _Object | None) -> str | None:
    dc = _integer(_get(battery, "bmsdcchrgconnect"))
    if dc in {1, 2}:
        status = _integer(_get(battery, "bmschrgsts"))
        if status == 2:
            return "3"
        if status == 3:
            return "6"
        return None if status is None else str(status)
    return _value(battery, "chgsts")


def _air_conditioning_code(car: _Object | None) -> str | None:
    valid = _value(car, "cdngoffvalid")
    state = _value(car, "cdngoff")
    if valid is None and state is None:
        return None
    return "1" if valid == "1" and state == "0" else "0"


def _lock_code(network_type: int | None, car: _Object | None) -> str | None:
    raw = _integer(_get(car, "drvdoorlocksts"))
    if raw is None:
        return None
    locked = raw in {0, 2, 3} if network_type == 2 else raw == 1
    return "0" if locked else "1"


def _window_code(car: _Object | None, property_name: str) -> str | None:
    value = _integer(_get(car, property_name))
    return None if value is None else "0" if value == 1 else "1"


def _open_code(car: _Object | None, property_name: str) -> str | None:
    value = _integer(_get(car, property_name))
    return None if value is None else "1" if value == 1 else "0"


def _binary_value(car: _Object | None, property_name: str) -> str | None:
    value = _value(car, property_name)
    return value if value in {"0", "1"} else None


def _enabled_when_valid(
    car: _Object | None,
    valid_property: str,
    state_property: str,
) -> str | None:
    return _binary_value(car, state_property) if _value(car, valid_property) == "1" else None


def _engine_code(car: _Object | None) -> str | None:
    if _value(car, "engstsvalid") != "1":
        return None
    return "1" if _value(car, "engsts") == "1" else "0"


def _comfort_level(
    car: _Object | None,
    valid_property: str,
    state_property: str,
    active_value: str,
) -> str | None:
    if _value(car, valid_property) != "1":
        return None
    return "1" if _value(car, state_property) == active_value else "0"


def _non_negative_value(node: _Object | None, property_name: str) -> str | None:
    value = _double(_get(node, property_name))
    return _format_number(value) if value is not None and value >= 0 else None


def _split_number_unit(
    node: _Object | None,
    property_name: str,
) -> tuple[str | None, str | None]:
    raw = _value(node, property_name)
    if raw is None or not raw.strip():
        return None, None
    value, separator, unit = raw.partition(",")
    return value.strip(), unit.strip() if separator else None


def _add_non_negative_number(
    items: list[CloudStatusItem],
    code: str,
    value: str | None,
    unit: str | None = None,
) -> None:
    number = _double(value)
    if number is not None and number >= 0:
        _add(items, code, _format_number(number), unit)


def _add_split_non_negative(
    items: list[CloudStatusItem],
    code: str,
    node: _Object | None,
    property_name: str,
) -> None:
    value, unit = _split_number_unit(node, property_name)
    _add_non_negative_number(items, code, value, unit)


def _add_percentage(
    items: list[CloudStatusItem],
    code: str,
    value: str | None,
    unit: str | None = None,
) -> None:
    number = _double(value)
    if number is not None and 0 <= number <= 100:
        _add(items, code, _format_number(number), unit)


def _add_split_percentage(
    items: list[CloudStatusItem],
    code: str,
    node: _Object | None,
    property_name: str,
) -> None:
    value, unit = _split_number_unit(node, property_name)
    _add_percentage(items, code, value, unit)


def _window_closed_code(node: _Object | None, property_name: str) -> str | None:
    value = _integer(_get(node, property_name))
    if value == 5:
        return "1"
    if value is not None and 0 <= value <= 4:
        return "0"
    return None


__all__ = ["map_bean_tech_status", "map_china_status"]
