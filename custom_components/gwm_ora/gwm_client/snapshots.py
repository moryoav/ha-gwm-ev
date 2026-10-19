"""Normalized, Home Assistant-independent vehicle snapshots.

The regional clients deliberately stop at small cloud DTOs.  This module is
the single boundary that turns those DTOs into the stable snake-case contract
currently consumed by the integration.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Literal

from .models import (
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    FrozenJsonValue,
)

MINIMUM_OPERATION_TIME_MINUTES = 5
MAXIMUM_OPERATION_TIME_MINUTES = 30
OPERATION_TIME_STEP_MINUTES = 1
DEFAULT_OPERATION_TIME_MINUTES = 15
DEFAULT_TEMPERATURE_C = 22
MINIMUM_TEMPERATURE_C = 16
MAXIMUM_TEMPERATURE_C = 32
TEMPERATURE_STEP_C = 1
DEFAULT_COMMAND_STATUS = "No remote command has run yet"

_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_MAX_UNIX_MILLISECONDS = 253_402_300_799_999
_INTEGER_PATTERN = re.compile(r"[+-]?[0-9]+")
_FLOAT_PATTERN = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

type SnapshotDictionary = dict[str, object]


@dataclass(frozen=True, slots=True, repr=False)
class LocationSnapshot:
    """Validated vehicle coordinates."""

    latitude: float
    longitude: float

    def as_dict(self) -> SnapshotDictionary:
        """Return the existing integration wire shape."""

        return {"latitude": self.latitude, "longitude": self.longitude}


@dataclass(frozen=True, slots=True, repr=False)
class TimestampSnapshot:
    """Cloud and local acquisition timestamps."""

    acquisition_time: datetime | None
    update_time: datetime | None
    last_refresh: datetime

    def as_dict(self) -> SnapshotDictionary:
        """Return ISO-8601 timestamps in the existing integration wire shape."""

        return {
            "acquisition_time": _datetime_text(self.acquisition_time),
            "update_time": _datetime_text(self.update_time),
            "last_refresh": _datetime_text(self.last_refresh),
        }


@dataclass(frozen=True, slots=True)
class VehicleCapabilities:
    """Features enabled for one normalized vehicle."""

    remote_commands: bool = False
    charging_control: bool = False

    def as_dict(self) -> SnapshotDictionary:
        """Return the existing integration wire shape."""

        return {
            "remote_commands": self.remote_commands,
            "charging_control": self.charging_control,
        }


@dataclass(frozen=True, slots=True, repr=False)
class VehicleValues:
    """Known signal values; unsupported and malformed values remain unknown."""

    soc: float | None = None
    range_km: float | None = None
    fuel_level_l: float | None = None
    fuel_range_km: float | None = None
    remaining_charging_time_min: float | None = None
    soce: float | None = None
    tire_pressure_front_left_kpa: float | None = None
    tire_pressure_front_right_kpa: float | None = None
    tire_pressure_rear_left_kpa: float | None = None
    tire_pressure_rear_right_kpa: float | None = None
    tire_temperature_front_left_c: float | None = None
    tire_temperature_front_right_c: float | None = None
    tire_temperature_rear_left_c: float | None = None
    tire_temperature_rear_right_c: float | None = None
    odometer_km: float | None = None
    interior_temperature_c: float | None = None
    charging_status: str | None = None
    charging_active: bool | None = None
    charge_plug_connected: bool | None = None
    ac_active: bool | None = None
    locked: bool | None = None
    window_front_left_open: bool | None = None
    window_front_right_open: bool | None = None
    window_rear_left_open: bool | None = None
    window_rear_right_open: bool | None = None
    window_front_driver_open: bool | None = None
    window_front_passenger_open: bool | None = None
    window_rear_driver_side_open: bool | None = None
    window_rear_passenger_side_open: bool | None = None
    door_front_driver_open: bool | None = None
    door_front_passenger_open: bool | None = None
    door_rear_driver_side_open: bool | None = None
    door_rear_passenger_side_open: bool | None = None
    trunk_open: bool | None = None
    sunroof_position_code: int | None = None
    air_circulation: bool | None = None
    front_defroster: bool | None = None
    rear_defroster: bool | None = None
    gps_authorized: bool | None = None
    tire_pressure_state_front_left: int | None = None
    tire_pressure_state_front_right: int | None = None
    tire_pressure_state_rear_left: int | None = None
    tire_pressure_state_rear_right: int | None = None
    tire_temperature_state_front_left: int | None = None
    tire_temperature_state_front_right: int | None = None
    tire_temperature_state_rear_left: int | None = None
    tire_temperature_state_rear_right: int | None = None
    window_learn_front_left: int | None = None
    window_learn_front_right: int | None = None
    window_learn_rear_left: int | None = None
    window_learn_rear_right: int | None = None
    steering_wheel_heater_active: bool | None = None
    rear_left_seat_heater_level: int | None = None
    rear_right_seat_heater_level: int | None = None
    front_windscreen_heater_active: bool | None = None
    engine_state_code: int | None = None
    front_driver_seat_heater_level: int | None = None
    front_passenger_seat_heater_level: int | None = None
    front_driver_seat_vent_level: int | None = None
    front_passenger_seat_vent_level: int | None = None
    near_beam_active: bool | None = None
    far_beam_active: bool | None = None
    left_turn_lamp_active: bool | None = None
    right_turn_lamp_active: bool | None = None
    oil_alarm_active: bool | None = None
    engine_door_open: bool | None = None
    ac_auto_mode_active: bool | None = None
    air_clean_active: bool | None = None
    cabin_clean_active: bool | None = None
    back_door_open: bool | None = None
    charge_soc: float | None = None
    charging_gun_model: int | None = None
    hcu_powertrain_state: int | None = None
    power: float | None = None
    battery_pack_state: int | None = None
    acc_clean_off: int | None = None
    tbox_state: int | None = None
    wireless_level: int | None = None
    oil_segments: int | None = None
    tire_pressure_indicator_front_left: bool | None = None
    tire_pressure_indicator_front_right: bool | None = None
    tire_pressure_indicator_rear_left: bool | None = None
    tire_pressure_indicator_rear_right: bool | None = None
    aux_battery_level: float | None = None
    remaining_usable_charge_percent: float | None = None
    battery_pack_current: float | None = None
    battery_pack_voltage: float | None = None

    def as_dict(self) -> SnapshotDictionary:
        """Return every released value key, including unknown values."""

        return {
            "soc": self.soc,
            "range_km": self.range_km,
            "fuel_level_l": self.fuel_level_l,
            "fuel_range_km": self.fuel_range_km,
            "remaining_charging_time_min": self.remaining_charging_time_min,
            "soce": self.soce,
            "tire_pressure_front_left_kpa": self.tire_pressure_front_left_kpa,
            "tire_pressure_front_right_kpa": self.tire_pressure_front_right_kpa,
            "tire_pressure_rear_left_kpa": self.tire_pressure_rear_left_kpa,
            "tire_pressure_rear_right_kpa": self.tire_pressure_rear_right_kpa,
            "tire_temperature_front_left_c": self.tire_temperature_front_left_c,
            "tire_temperature_front_right_c": self.tire_temperature_front_right_c,
            "tire_temperature_rear_left_c": self.tire_temperature_rear_left_c,
            "tire_temperature_rear_right_c": self.tire_temperature_rear_right_c,
            "odometer_km": self.odometer_km,
            "interior_temperature_c": self.interior_temperature_c,
            "charging_status": self.charging_status,
            "charging_active": self.charging_active,
            "charge_plug_connected": self.charge_plug_connected,
            "ac_active": self.ac_active,
            "locked": self.locked,
            "window_front_left_open": self.window_front_left_open,
            "window_front_right_open": self.window_front_right_open,
            "window_rear_left_open": self.window_rear_left_open,
            "window_rear_right_open": self.window_rear_right_open,
            "window_front_driver_open": self.window_front_driver_open,
            "window_front_passenger_open": self.window_front_passenger_open,
            "window_rear_driver_side_open": self.window_rear_driver_side_open,
            "window_rear_passenger_side_open": self.window_rear_passenger_side_open,
            "door_front_driver_open": self.door_front_driver_open,
            "door_front_passenger_open": self.door_front_passenger_open,
            "door_rear_driver_side_open": self.door_rear_driver_side_open,
            "door_rear_passenger_side_open": self.door_rear_passenger_side_open,
            "trunk_open": self.trunk_open,
            "sunroof_position_code": self.sunroof_position_code,
            "air_circulation": self.air_circulation,
            "front_defroster": self.front_defroster,
            "rear_defroster": self.rear_defroster,
            "gps_authorized": self.gps_authorized,
            "tire_pressure_state_front_left": self.tire_pressure_state_front_left,
            "tire_pressure_state_front_right": self.tire_pressure_state_front_right,
            "tire_pressure_state_rear_left": self.tire_pressure_state_rear_left,
            "tire_pressure_state_rear_right": self.tire_pressure_state_rear_right,
            "tire_temperature_state_front_left": self.tire_temperature_state_front_left,
            "tire_temperature_state_front_right": self.tire_temperature_state_front_right,
            "tire_temperature_state_rear_left": self.tire_temperature_state_rear_left,
            "tire_temperature_state_rear_right": self.tire_temperature_state_rear_right,
            "window_learn_front_left": self.window_learn_front_left,
            "window_learn_front_right": self.window_learn_front_right,
            "window_learn_rear_left": self.window_learn_rear_left,
            "window_learn_rear_right": self.window_learn_rear_right,
            "steering_wheel_heater_active": self.steering_wheel_heater_active,
            "rear_left_seat_heater_level": self.rear_left_seat_heater_level,
            "rear_right_seat_heater_level": self.rear_right_seat_heater_level,
            "front_windscreen_heater_active": self.front_windscreen_heater_active,
            "engine_state_code": self.engine_state_code,
            "front_driver_seat_heater_level": self.front_driver_seat_heater_level,
            "front_passenger_seat_heater_level": self.front_passenger_seat_heater_level,
            "front_driver_seat_vent_level": self.front_driver_seat_vent_level,
            "front_passenger_seat_vent_level": self.front_passenger_seat_vent_level,
            "near_beam_active": self.near_beam_active,
            "far_beam_active": self.far_beam_active,
            "left_turn_lamp_active": self.left_turn_lamp_active,
            "right_turn_lamp_active": self.right_turn_lamp_active,
            "oil_alarm_active": self.oil_alarm_active,
            "engine_door_open": self.engine_door_open,
            "ac_auto_mode_active": self.ac_auto_mode_active,
            "air_clean_active": self.air_clean_active,
            "cabin_clean_active": self.cabin_clean_active,
            "back_door_open": self.back_door_open,
            "charge_soc": self.charge_soc,
            "charging_gun_model": self.charging_gun_model,
            "hcu_powertrain_state": self.hcu_powertrain_state,
            "power": self.power,
            "battery_pack_state": self.battery_pack_state,
            "acc_clean_off": self.acc_clean_off,
            "tbox_state": self.tbox_state,
            "wireless_level": self.wireless_level,
            "oil_segments": self.oil_segments,
            "tire_pressure_indicator_front_left": self.tire_pressure_indicator_front_left,
            "tire_pressure_indicator_front_right": self.tire_pressure_indicator_front_right,
            "tire_pressure_indicator_rear_left": self.tire_pressure_indicator_rear_left,
            "tire_pressure_indicator_rear_right": self.tire_pressure_indicator_rear_right,
            "aux_battery_level": self.aux_battery_level,
            "remaining_usable_charge_percent": self.remaining_usable_charge_percent,
            "battery_pack_current": self.battery_pack_current,
            "battery_pack_voltage": self.battery_pack_voltage,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ClimateSnapshot:
    """Normalized climate state and supported bounds."""

    mode: Literal["auto", "off"] = "off"
    action: str | None = "off"
    target_temperature_c: int = DEFAULT_TEMPERATURE_C
    operation_time_minutes: int = DEFAULT_OPERATION_TIME_MINUTES
    current_temperature_c: float | None = None
    min_temperature_c: int = MINIMUM_TEMPERATURE_C
    max_temperature_c: int = MAXIMUM_TEMPERATURE_C
    step_temperature_c: int = TEMPERATURE_STEP_C

    def as_dict(self) -> SnapshotDictionary:
        """Return the existing integration wire shape."""

        return {
            "mode": self.mode,
            "action": self.action,
            "target_temperature_c": self.target_temperature_c,
            "operation_time_minutes": self.operation_time_minutes,
            "current_temperature_c": self.current_temperature_c,
            "min_temperature_c": self.min_temperature_c,
            "max_temperature_c": self.max_temperature_c,
            "step_temperature_c": self.step_temperature_c,
        }


@dataclass(frozen=True, slots=True, repr=False)
class RawItemSnapshot:
    """Canonical diagnostic text for one cloud signal."""

    value: str
    unit: str | None = None

    def as_dict(self) -> SnapshotDictionary:
        """Return the existing integration wire shape."""

        return {"value": self.value, "unit": self.unit}


@dataclass(frozen=True, slots=True, repr=False)
class VehicleSnapshot:
    """One complete normalized vehicle snapshot."""

    vin: str = field(repr=False)
    platform: str | None
    name: str
    manufacturer: str | None
    model: str | None
    serial_number: str | None = field(repr=False)
    location: LocationSnapshot | None = field(repr=False)
    timestamps: TimestampSnapshot = field(repr=False)
    capabilities: VehicleCapabilities
    values: VehicleValues = field(repr=False)
    climate: ClimateSnapshot
    command_status: str = DEFAULT_COMMAND_STATUS
    raw_items: Mapping[str, RawItemSnapshot] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_items", MappingProxyType(dict(self.raw_items)))

    def as_dict(self) -> SnapshotDictionary:
        """Return a JSON-serializable copy of the released add-on contract."""

        return {
            "vin": self.vin,
            "platform": self.platform,
            "name": self.name,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial_number": self.serial_number,
            "location": None if self.location is None else self.location.as_dict(),
            "timestamps": self.timestamps.as_dict(),
            "capabilities": self.capabilities.as_dict(),
            "values": self.values.as_dict(),
            "climate": self.climate.as_dict(),
            "command_status": self.command_status,
            "raw_items": {code: item.as_dict() for code, item in self.raw_items.items()},
        }


def map_vehicle_snapshot(
    vehicle: CloudVehicle,
    status: CloudVehicleStatus,
    basics: CloudVehicleBasics,
    *,
    refreshed_at: datetime,
    remote_commands_available: bool,
    charging_control_available: bool = False,
    command_status: str = DEFAULT_COMMAND_STATUS,
) -> VehicleSnapshot:
    """Normalize one regional cloud DTO set into the shared snapshot contract."""

    if not isinstance(vehicle, CloudVehicle):
        raise TypeError("vehicle_invalid")
    if not isinstance(status, CloudVehicleStatus):
        raise TypeError("status_invalid")
    if not isinstance(basics, CloudVehicleBasics):
        raise TypeError("basics_invalid")
    if type(remote_commands_available) is not bool:
        raise TypeError("remote_commands_available_invalid")
    if type(charging_control_available) is not bool:
        raise TypeError("charging_control_available_invalid")
    if not isinstance(command_status, str):
        raise TypeError("command_status_invalid")
    normalized_refresh = _utc_datetime(refreshed_at)
    platform = _normalized_platform(vehicle.platform)

    raw_items = _raw_items(status.items)
    interior_temperature = _number(raw_items, "2201001")
    if interior_temperature is not None:
        interior_temperature /= 10.0

    values = VehicleValues(
        soc=_number(raw_items, "2013021"),
        range_km=_number(raw_items, "2011501"),
        fuel_level_l=_nonnegative_number(raw_items, "2017002"),
        fuel_range_km=_nonnegative_number(raw_items, "2011007"),
        remaining_charging_time_min=_number(raw_items, "2013022"),
        soce=_number(raw_items, "2041301"),
        tire_pressure_front_left_kpa=_number(raw_items, "2101001"),
        tire_pressure_front_right_kpa=_number(raw_items, "2101002"),
        tire_pressure_rear_left_kpa=_number(raw_items, "2101003"),
        tire_pressure_rear_right_kpa=_number(raw_items, "2101004"),
        tire_temperature_front_left_c=_number(raw_items, "2101005"),
        tire_temperature_front_right_c=_number(raw_items, "2101006"),
        tire_temperature_rear_left_c=_number(raw_items, "2101007"),
        tire_temperature_rear_right_c=_number(raw_items, "2101008"),
        odometer_km=_number(raw_items, "2103010"),
        interior_temperature_c=interior_temperature,
        charging_status=_charging_status(raw_items),
        charging_active=_charging_active(raw_items),
        charge_plug_connected=_bool(raw_items, "2042082"),
        ac_active=_bool(raw_items, "2202001"),
        locked=_lock_closed(raw_items),
        window_front_left_open=_window_open(raw_items, "2210001"),
        window_front_right_open=_window_open(raw_items, "2210002"),
        window_rear_left_open=_window_open(raw_items, "2210003"),
        window_rear_right_open=_window_open(raw_items, "2210004"),
        window_front_driver_open=_window_open(raw_items, "2210001"),
        window_front_passenger_open=_window_open(raw_items, "2210002"),
        window_rear_driver_side_open=_window_open(raw_items, "2210004"),
        window_rear_passenger_side_open=_window_open(raw_items, "2210003"),
        door_front_driver_open=_bool(raw_items, "2206002"),
        door_front_passenger_open=_bool(raw_items, "2206004"),
        door_rear_driver_side_open=_bool(raw_items, "2206003"),
        door_rear_passenger_side_open=_bool(raw_items, "2206005"),
        trunk_open=_bool(raw_items, "2206001"),
        sunroof_position_code=_integer(raw_items, "2210005"),
        air_circulation=_bool(raw_items, "2078020"),
        front_defroster=_bool(raw_items, "2222001"),
        rear_defroster=_bool(raw_items, "2210032"),
        gps_authorized=_bool(raw_items, "2310001"),
        tire_pressure_state_front_left=_integer(raw_items, "2102001"),
        tire_pressure_state_front_right=_integer(raw_items, "2102002"),
        tire_pressure_state_rear_left=_integer(raw_items, "2102003"),
        tire_pressure_state_rear_right=_integer(raw_items, "2102004"),
        tire_temperature_state_front_left=_integer(raw_items, "2102007"),
        tire_temperature_state_front_right=_integer(raw_items, "2102008"),
        tire_temperature_state_rear_left=_integer(raw_items, "2102009"),
        tire_temperature_state_rear_right=_integer(raw_items, "2102010"),
        window_learn_front_left=_integer(raw_items, "2210011"),
        window_learn_front_right=_integer(raw_items, "2210010"),
        window_learn_rear_left=_integer(raw_items, "2210013"),
        window_learn_rear_right=_integer(raw_items, "2210012"),
        steering_wheel_heater_active=_bool(raw_items, "2060016"),
        rear_left_seat_heater_level=_level(raw_items, "2424001"),
        rear_right_seat_heater_level=_level(raw_items, "2424002"),
        front_windscreen_heater_active=_bool(raw_items, "2202111"),
        engine_state_code=_integer(raw_items, "2016001"),
        front_driver_seat_heater_level=_level(raw_items, "2220001"),
        front_passenger_seat_heater_level=_level(raw_items, "2220002"),
        front_driver_seat_vent_level=_level(raw_items, "2220003"),
        front_passenger_seat_vent_level=_level(raw_items, "2220004"),
        near_beam_active=_bool(raw_items, "9000001"),
        far_beam_active=_bool(raw_items, "9000002"),
        left_turn_lamp_active=_bool(raw_items, "9000003"),
        right_turn_lamp_active=_bool(raw_items, "9000004"),
        oil_alarm_active=_bool(raw_items, "9000005"),
        engine_door_open=_bool(raw_items, "9000006"),
        ac_auto_mode_active=_bool(raw_items, "9000007"),
        air_clean_active=_bool(raw_items, "9000008"),
        cabin_clean_active=_bool(raw_items, "9000009"),
        back_door_open=_bool(raw_items, "9000010"),
        charge_soc=_number(raw_items, "9000011"),
        charging_gun_model=_integer(raw_items, "9000012"),
        hcu_powertrain_state=_integer(raw_items, "9000013"),
        power=_number(raw_items, "9000014"),
        battery_pack_state=_integer(raw_items, "9000015"),
        acc_clean_off=_integer(raw_items, "9000016"),
        tbox_state=_integer(raw_items, "9000017"),
        wireless_level=_integer(raw_items, "9000018"),
        oil_segments=_integer(raw_items, "9000019"),
        tire_pressure_indicator_front_left=_bool(raw_items, "9000020"),
        tire_pressure_indicator_front_right=_bool(raw_items, "9000021"),
        tire_pressure_indicator_rear_left=_bool(raw_items, "9000022"),
        tire_pressure_indicator_rear_right=_bool(raw_items, "9000023"),
        aux_battery_level=_number(raw_items, "9000024"),
        remaining_usable_charge_percent=_number(raw_items, "9000025"),
        battery_pack_current=_number(raw_items, "9000026"),
        battery_pack_voltage=_number(raw_items, "9000027"),
    )
    ac_on = values.ac_active is True
    climate_configuration = basics.climate
    target_temperature = normalize_temperature(
        None if climate_configuration is None else climate_configuration.temperature,
        DEFAULT_TEMPERATURE_C,
    )
    operation_time = normalize_operation_time(
        None if climate_configuration is None else climate_configuration.operation_time,
        DEFAULT_OPERATION_TIME_MINUTES,
    )

    return VehicleSnapshot(
        vin=vehicle.identifier.value,
        platform=platform,
        name=_first_nonempty(
            vehicle.app_show_series_name,
            vehicle.vehicle_nickname,
            vehicle.model_name,
            "GWM vehicle",
        ),
        manufacturer=_first_nonempty(vehicle.brand_name, vehicle.other_brand_name, "GWM"),
        model=_first_nonempty(vehicle.vehicle_type, vehicle.vehicle_type_name, vehicle.model_name),
        serial_number=status.device_id,
        location=_location(status.latitude, status.longitude),
        timestamps=TimestampSnapshot(
            acquisition_time=_unix_milliseconds(status.acquisition_time_ms),
            update_time=_unix_milliseconds(status.update_time_ms),
            last_refresh=normalized_refresh,
        ),
        capabilities=VehicleCapabilities(
            remote_commands=remote_commands_available,
            charging_control=charging_control_available and platform != "beantech",
        ),
        values=values,
        climate=ClimateSnapshot(
            mode="auto" if ac_on else "off",
            action=None if ac_on else "off",
            target_temperature_c=target_temperature,
            operation_time_minutes=operation_time,
            current_temperature_c=interior_temperature,
        ),
        command_status=command_status,
        raw_items=raw_items,
    )


def normalize_temperature(value: str | None, fallback: int) -> int:
    """Clamp a stored integer temperature to the supported 16-32 C range."""

    parsed = _parse_int32(value)
    if parsed is None:
        return fallback
    return min(MAXIMUM_TEMPERATURE_C, max(MINIMUM_TEMPERATURE_C, parsed))


def valid_temperature(value: str | None) -> int | None:
    """Return a supported stored temperature, or ``None`` when invalid."""

    parsed = _parse_int32(value)
    if parsed is None or not MINIMUM_TEMPERATURE_C <= parsed <= MAXIMUM_TEMPERATURE_C:
        return None
    return parsed


def normalize_operation_time(value: str | None, fallback: int) -> int:
    """Normalize legacy minutes or current seconds into operation minutes."""

    stored_value = _parse_int32(value)
    if stored_value is None:
        return fallback
    if is_valid_operation_time(stored_value):
        return stored_value
    if stored_value % 60 != 0:
        return fallback
    minutes = stored_value // 60
    return minutes if is_valid_operation_time(minutes) else fallback


def is_valid_operation_time(minutes: int) -> bool:
    """Return whether minutes fit the current climate command range."""

    return (
        MINIMUM_OPERATION_TIME_MINUTES <= minutes <= MAXIMUM_OPERATION_TIME_MINUTES
        and minutes % OPERATION_TIME_STEP_MINUTES == 0
    )


def _raw_items(items: tuple[CloudStatusItem, ...]) -> Mapping[str, RawItemSnapshot]:
    normalized: dict[str, RawItemSnapshot] = {}
    for item in items:
        if not isinstance(item, CloudStatusItem) or not item.code.strip():
            continue
        value = _normalize_raw_value(item.value)
        if value is None:
            continue
        normalized[item.code.strip()] = RawItemSnapshot(value=value, unit=item.unit)
    return MappingProxyType(normalized)


def _normalize_raw_value(value: FrozenJsonValue) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if value == math.inf:
            return "Infinity"
        if value == -math.inf:
            return "-Infinity"
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    return json.dumps(_thaw_json(value), ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _thaw_json(value: FrozenJsonValue) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _value(items: Mapping[str, RawItemSnapshot], code: str) -> str | None:
    item = items.get(code)
    return None if item is None else item.value.strip()


def _number(items: Mapping[str, RawItemSnapshot], code: str) -> float | None:
    text = _value(items, code)
    if text is None or _FLOAT_PATTERN.fullmatch(text) is None:
        return None
    try:
        parsed = float(text)
    except (OverflowError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _nonnegative_number(items: Mapping[str, RawItemSnapshot], code: str) -> float | None:
    value = _number(items, code)
    return value if value is not None and value >= 0 else None


def _integer(items: Mapping[str, RawItemSnapshot], code: str) -> int | None:
    value = _number(items, code)
    if value is None or not value.is_integer() or not _INT32_MIN <= value <= _INT32_MAX:
        return None
    return int(value)


def _level(items: Mapping[str, RawItemSnapshot], code: str) -> int | None:
    value = _integer(items, code)
    return value if value is not None and 0 <= value <= 3 else None


def _bool(items: Mapping[str, RawItemSnapshot], code: str) -> bool | None:
    value = _integer(items, code)
    if value == 1:
        return True
    if value == 0:
        return False
    return None


def _charging_status(items: Mapping[str, RawItemSnapshot]) -> str | None:
    value = _integer(items, "2041142")
    if value == 0:
        connected = _bool(items, "2042082")
        if connected is False:
            return "disconnected"
        if connected is True:
            return "connected"
        return None
    if value is None:
        return None
    return {
        1: "charging",
        2: "awaiting_charging",
        3: "charging_complete",
        5: "waiting_for_power",
        6: "error",
    }.get(value)


def _charging_active(items: Mapping[str, RawItemSnapshot]) -> bool | None:
    value = _integer(items, "2041142")
    if value == 1:
        return True
    if value in {0, 2, 3, 5, 6}:
        return False
    return None


def _lock_closed(items: Mapping[str, RawItemSnapshot]) -> bool | None:
    value = _integer(items, "2208001")
    if value == 0:
        return True
    if value == 1:
        return False
    return None


def _window_open(items: Mapping[str, RawItemSnapshot], code: str) -> bool | None:
    value = _integer(items, code)
    if value == 1:
        return False
    if value is not None and value >= 0:
        return True
    return None


def _parse_int32(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if _INTEGER_PATTERN.fullmatch(text) is None:
        return None
    parsed = int(text)
    return parsed if _INT32_MIN <= parsed <= _INT32_MAX else None


def _unix_milliseconds(value: int | None) -> datetime | None:
    if value is None or value <= 0 or value > _MAX_UNIX_MILLISECONDS:
        return None
    try:
        return _UNIX_EPOCH + timedelta(milliseconds=value)
    except OverflowError:
        return None


def _location(latitude: float | None, longitude: float | None) -> LocationSnapshot | None:
    if (
        latitude is None
        or longitude is None
        or not math.isfinite(latitude)
        or not math.isfinite(longitude)
        or not -90 <= latitude <= 90
        or not -180 <= longitude <= 180
    ):
        return None
    return LocationSnapshot(latitude=latitude, longitude=longitude)


def _first_nonempty(*values: str | None) -> str:
    return next((value for value in values if value is not None and value.strip()), "")


def _normalized_platform(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().casefold()
    return normalized or None


def _utc_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("last_refresh_invalid")
    return value.astimezone(UTC)


def _datetime_text(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()
