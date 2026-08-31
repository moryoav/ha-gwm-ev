"""Typed, redaction-safe cloud models for the async GWM client."""

from __future__ import annotations

import math
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import quote

type JsonScalar = None | bool | int | float | str
type FrozenJsonValue = JsonScalar | tuple[FrozenJsonValue, ...] | Mapping[str, FrozenJsonValue]

_MAX_VEHICLE_IDENTIFIER_LENGTH = 512
_MAX_JSON_DEPTH = 64
_MIN_TIMESTAMP = -(1 << 63)
_MAX_TIMESTAMP = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class VehicleIdentifier:
    """An opaque cloud vehicle identifier with a canonical URL encoding."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, str)
            or not 0 < len(self.value) <= _MAX_VEHICLE_IDENTIFIER_LENGTH
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.value)
        ):
            raise ValueError("vehicle_identifier_invalid")

    @property
    def encoded(self) -> str:
        """Return the sole canonical query representation of the identifier."""

        return quote(self.value, safe="", encoding="utf-8", errors="strict")


@dataclass(frozen=True, slots=True)
class GwmSession:
    """One immutable authenticated session snapshot used by read requests."""

    country: str
    device_id: str = field(repr=False)
    access_token: str = field(repr=False)
    app_ssl_context: ssl.SSLContext = field(repr=False)
    gw_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) for value in (self.country, self.device_id, self.access_token)):
            raise ValueError("session_invalid")
        if not isinstance(self.app_ssl_context, ssl.SSLContext):
            raise ValueError("session_invalid")
        if self.gw_id is not None and (
            not isinstance(self.gw_id, str)
            or not self.gw_id
            or len(self.gw_id) > 16 * 1024
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.gw_id)
        ):
            raise ValueError("session_invalid")


@dataclass(frozen=True, slots=True)
class CloudVehicle:
    """The discovery fields needed by later read and normalization tasks."""

    identifier: VehicleIdentifier = field(repr=False)
    default_vehicle: bool = False
    app_show_series_name: str | None = field(default=None, repr=False)
    vehicle_nickname: str | None = field(default=None, repr=False)
    model_name: str | None = field(default=None, repr=False)
    brand_name: str | None = field(default=None, repr=False)
    other_brand_name: str | None = field(default=None, repr=False)
    vehicle_type: str | None = field(default=None, repr=False)
    vehicle_type_name: str | None = field(default=None, repr=False)
    vehicle_id: str | None = field(default=None, repr=False)
    platform: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CloudStatusItem:
    """One unnormalized status signal from the cloud response."""

    code: str = field(repr=False)
    value: FrozenJsonValue = field(repr=False)
    unit: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CloudVehicleStatus:
    """The typed cloud status envelope before normalized snapshot mapping."""

    device_id: str | None = field(default=None, repr=False)
    acquisition_time_ms: int | None = field(default=None, repr=False)
    update_time_ms: int | None = field(default=None, repr=False)
    latitude: float | None = field(default=None, repr=False)
    longitude: float | None = field(default=None, repr=False)
    items: tuple[CloudStatusItem, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class CloudClimateConfiguration:
    """The small basics subset required by later climate mapping."""

    temperature: str | None = field(default=None, repr=False)
    operation_time: str | None = field(default=None, repr=False)
    engine_operation_time: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CloudVehicleBasics:
    """Optional vehicle configuration returned by the basics endpoint."""

    climate: CloudClimateConfiguration | None = field(default=None, repr=False)


def parse_cloud_vehicles(
    data: object,
    *,
    allow_numbers_for_strings: bool,
) -> tuple[CloudVehicle, ...]:
    """Parse a discovery payload without retaining unrelated personal fields."""

    if not isinstance(data, list):
        raise ValueError("vehicle_schema_invalid")

    vehicles: list[CloudVehicle] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, Mapping):
            raise ValueError("vehicle_schema_invalid")
        identifier_text = _required_string(
            item.get("vin"),
            allow_integer=allow_numbers_for_strings,
            category="vehicle_schema_invalid",
        )
        identifier = VehicleIdentifier(identifier_text)
        if identifier.value in seen:
            raise ValueError("vehicle_schema_invalid")
        seen.add(identifier.value)

        default_vehicle = item.get("defaultVehicle", False)
        if not isinstance(default_vehicle, bool):
            raise ValueError("vehicle_schema_invalid")

        vehicles.append(
            CloudVehicle(
                identifier=identifier,
                default_vehicle=default_vehicle,
                app_show_series_name=_optional_string(
                    item.get("appShowSeriesName"), allow_integer=allow_numbers_for_strings
                ),
                vehicle_nickname=_optional_string(item.get("vehicleNick"), allow_integer=allow_numbers_for_strings),
                model_name=_optional_string(item.get("modelName"), allow_integer=allow_numbers_for_strings),
                brand_name=_optional_string(item.get("brandName"), allow_integer=allow_numbers_for_strings),
                other_brand_name=_optional_string(item.get("otBrandName"), allow_integer=allow_numbers_for_strings),
                vehicle_type=_optional_string(item.get("vtype"), allow_integer=allow_numbers_for_strings),
                vehicle_type_name=_optional_string(item.get("vTypeName"), allow_integer=allow_numbers_for_strings),
                vehicle_id=_optional_string(item.get("vehicleId"), allow_integer=allow_numbers_for_strings),
                platform=_optional_string(item.get("belongPlatform"), allow_integer=allow_numbers_for_strings),
            )
        )
    return tuple(vehicles)


def parse_cloud_vehicle_status(
    data: object,
    *,
    allow_stringified_numbers: bool,
    allow_numbers_for_strings: bool,
) -> CloudVehicleStatus:
    """Parse one status payload while preserving only typed status values."""

    if not isinstance(data, Mapping):
        raise ValueError("status_schema_invalid")

    items_value = data.get("items")
    if items_value is None:
        items_value = []
    if not isinstance(items_value, list):
        raise ValueError("status_schema_invalid")
    items: list[CloudStatusItem] = []
    for item in items_value:
        if item is None:
            continue
        if not isinstance(item, Mapping):
            raise ValueError("status_schema_invalid")
        code = _optional_string(
            item.get("code"),
            allow_integer=allow_numbers_for_strings,
        )
        if code is None or not code.strip():
            continue
        items.append(
            CloudStatusItem(
                code=code,
                value=_freeze_json(item.get("value")),
                unit=_optional_string(item.get("unit"), allow_integer=allow_numbers_for_strings),
            )
        )

    return CloudVehicleStatus(
        device_id=_optional_string(data.get("deviceId"), allow_integer=allow_numbers_for_strings),
        acquisition_time_ms=_optional_timestamp(data.get("acquisitionTime"), allow_string=allow_stringified_numbers),
        update_time_ms=_optional_timestamp(data.get("updateTime"), allow_string=allow_stringified_numbers),
        latitude=_optional_coordinate(data.get("latitude"), allow_string=allow_stringified_numbers),
        longitude=_optional_coordinate(data.get("longitude"), allow_string=allow_stringified_numbers),
        items=tuple(items),
    )


def parse_cloud_vehicle_basics(
    data: object,
    *,
    allow_numbers_for_strings: bool,
) -> CloudVehicleBasics:
    """Parse the limited pre-normalization climate configuration."""

    if not isinstance(data, Mapping):
        raise ValueError("basics_schema_invalid")
    config = data.get("config")
    if config is None:
        return CloudVehicleBasics()
    if not isinstance(config, Mapping):
        raise ValueError("basics_schema_invalid")
    return CloudVehicleBasics(
        climate=CloudClimateConfiguration(
            temperature=_optional_string(
                config.get("airConditionerTemperature"),
                allow_integer=allow_numbers_for_strings,
            ),
            operation_time=_optional_string(
                config.get("airConditionerStatusTime"),
                allow_integer=allow_numbers_for_strings,
            ),
            engine_operation_time=_optional_string(
                config.get("engineStatusTime"),
                allow_integer=allow_numbers_for_strings,
            ),
        )
    )


def _required_string(
    value: object,
    *,
    allow_integer: bool,
    category: str,
) -> str:
    result = _optional_string(value, allow_integer=allow_integer)
    if result is None or not result:
        raise ValueError(category)
    return result


def _optional_string(value: object, *, allow_integer: bool) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if allow_integer and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise ValueError("payload_schema_invalid")


def _optional_timestamp(value: object, *, allow_string: bool) -> int | None:
    if value is None:
        return None
    if allow_string and isinstance(value, str):
        digits = value[1:] if value[:1] in {"+", "-"} else value
        if not digits or any(character < "0" or character > "9" for character in digits):
            raise ValueError("payload_schema_invalid")
        value = int(value)
    if not isinstance(value, int) or isinstance(value, bool) or value < _MIN_TIMESTAMP or value > _MAX_TIMESTAMP:
        raise ValueError("payload_schema_invalid")
    return value


def _optional_coordinate(
    value: object,
    *,
    allow_string: bool,
) -> float | None:
    if value is None:
        return None
    if allow_string and isinstance(value, str):
        invalid = False
        try:
            value = float(value)
        except ValueError:
            invalid = True
        if invalid:
            raise ValueError("payload_schema_invalid")
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("payload_schema_invalid")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("payload_schema_invalid")
    return result


def _freeze_json(value: object, *, depth: int = 0) -> FrozenJsonValue:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("payload_schema_invalid")
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("payload_schema_invalid")
        return value
    if isinstance(value, list):
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("payload_schema_invalid")
        return MappingProxyType({key: _freeze_json(item, depth=depth + 1) for key, item in value.items()})
    raise ValueError("payload_schema_invalid")
