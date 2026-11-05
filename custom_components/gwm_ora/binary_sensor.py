"""Binary sensor platform for GWM."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GwmConfigEntry
from .entity import GwmEntity, setup_vehicle_entities, vehicle_value

PARALLEL_UPDATES = 0

BEANTECH_BINARY_SENSOR_KEYS = {
    "near_beam_active",
    "far_beam_active",
    "left_turn_lamp_active",
    "right_turn_lamp_active",
    "oil_alarm_active",
    "engine_door_open",
    "back_door_open",
    "ac_auto_mode_active",
    "air_clean_active",
    "cabin_clean_active",
    "tire_pressure_indicator_front_left",
    "tire_pressure_indicator_front_right",
    "tire_pressure_indicator_rear_left",
    "tire_pressure_indicator_rear_right",
}


@dataclass(frozen=True, kw_only=True)
class GwmBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes a GWM binary sensor."""

    value_fn: Callable[[dict[str, Any] | None], bool | None]


def _bool_value(*keys: str) -> Callable[[dict[str, Any] | None], bool | None]:
    def value_fn(vehicle: dict[str, Any] | None) -> bool | None:
        for key in keys:
            value = vehicle_value(vehicle, key)
            if value is not None:
                return value
        return None

    return value_fn


BINARY_SENSORS: tuple[GwmBinarySensorEntityDescription, ...] = (
    GwmBinarySensorEntityDescription(
        key="charging_active",
        translation_key="charging_active",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        value_fn=_bool_value("charging_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="charge_plug_connected",
        translation_key="charge_plug",
        device_class=BinarySensorDeviceClass.PLUG,
        value_fn=_bool_value("charge_plug_connected"),
    ),
    GwmBinarySensorEntityDescription(
        key="ac_active",
        translation_key="ac_active",
        value_fn=_bool_value("ac_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="lock_open",
        translation_key="lock_open",
        device_class=BinarySensorDeviceClass.LOCK,
        value_fn=lambda vehicle: (
            None if vehicle_value(vehicle, "locked") is None else not vehicle_value(vehicle, "locked")
        ),
    ),
    GwmBinarySensorEntityDescription(
        key="window_front_left_open",
        translation_key="window_front_driver",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=_bool_value("window_front_driver_open", "window_front_left_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="window_front_right_open",
        translation_key="window_front_passenger",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=_bool_value("window_front_passenger_open", "window_front_right_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="window_rear_left_open",
        translation_key="window_rear_left",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=_bool_value("window_rear_passenger_side_open", "window_rear_left_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="window_rear_right_open",
        translation_key="window_rear_right",
        device_class=BinarySensorDeviceClass.WINDOW,
        value_fn=_bool_value("window_rear_driver_side_open", "window_rear_right_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="door_front_driver_open",
        translation_key="door_front_driver",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("door_front_driver_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="door_front_passenger_open",
        translation_key="door_front_passenger",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("door_front_passenger_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="door_rear_driver_side_open",
        translation_key="door_rear_driver_side",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("door_rear_driver_side_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="door_rear_passenger_side_open",
        translation_key="door_rear_passenger_side",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("door_rear_passenger_side_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="trunk_open",
        translation_key="trunk",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("trunk_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="air_circulation",
        translation_key="air_circulation",
        value_fn=_bool_value("air_circulation"),
    ),
    GwmBinarySensorEntityDescription(
        key="front_defroster",
        translation_key="front_defroster",
        value_fn=_bool_value("front_defroster"),
    ),
    GwmBinarySensorEntityDescription(
        key="rear_defroster",
        translation_key="rear_defroster",
        value_fn=_bool_value("rear_defroster"),
    ),
    GwmBinarySensorEntityDescription(
        key="steering_wheel_heater_active",
        translation_key="steering_wheel_heater",
        entity_registry_enabled_default=False,
        value_fn=_bool_value("steering_wheel_heater_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="front_windscreen_heater_active",
        translation_key="front_windscreen_heater",
        entity_registry_enabled_default=False,
        value_fn=_bool_value("front_windscreen_heater_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="gps_authorized",
        translation_key="gps_authorized",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("gps_authorized"),
    ),
    GwmBinarySensorEntityDescription(
        key="near_beam_active",
        translation_key="near_beam",
        device_class=BinarySensorDeviceClass.LIGHT,
        value_fn=_bool_value("near_beam_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="far_beam_active",
        translation_key="far_beam",
        device_class=BinarySensorDeviceClass.LIGHT,
        value_fn=_bool_value("far_beam_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="left_turn_lamp_active",
        translation_key="left_turn_lamp",
        device_class=BinarySensorDeviceClass.LIGHT,
        value_fn=_bool_value("left_turn_lamp_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="right_turn_lamp_active",
        translation_key="right_turn_lamp",
        device_class=BinarySensorDeviceClass.LIGHT,
        value_fn=_bool_value("right_turn_lamp_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="oil_alarm_active",
        translation_key="oil_alarm",
        device_class=BinarySensorDeviceClass.PROBLEM,
        value_fn=_bool_value("oil_alarm_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="engine_door_open",
        translation_key="engine_door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("engine_door_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="back_door_open",
        translation_key="back_door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=_bool_value("back_door_open"),
    ),
    GwmBinarySensorEntityDescription(
        key="ac_auto_mode_active",
        translation_key="ac_auto_mode",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("ac_auto_mode_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="air_clean_active",
        translation_key="air_clean",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("air_clean_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="cabin_clean_active",
        translation_key="cabin_clean",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("cabin_clean_active"),
    ),
    GwmBinarySensorEntityDescription(
        key="tire_pressure_indicator_front_left",
        translation_key="tire_pressure_indicator_front_left",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("tire_pressure_indicator_front_left"),
    ),
    GwmBinarySensorEntityDescription(
        key="tire_pressure_indicator_front_right",
        translation_key="tire_pressure_indicator_front_right",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("tire_pressure_indicator_front_right"),
    ),
    GwmBinarySensorEntityDescription(
        key="tire_pressure_indicator_rear_left",
        translation_key="tire_pressure_indicator_rear_left",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("tire_pressure_indicator_rear_left"),
    ),
    GwmBinarySensorEntityDescription(
        key="tire_pressure_indicator_rear_right",
        translation_key="tire_pressure_indicator_rear_right",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
        value_fn=_bool_value("tire_pressure_indicator_rear_right"),
    ),
)


def _binary_sensor_descriptions_for_vehicle(
    vehicle: dict[str, Any],
    region: str,
) -> tuple[GwmBinarySensorEntityDescription, ...]:
    """Return descriptions supported by the vehicle backend."""
    china_platform = (
        str(vehicle.get("platform") or "").strip().lower()
        if str(region or "").strip().lower() == "cn"
        else ""
    )
    # BeanTech and GTSP already map left-back to 2210004 and right-back to
    # 2210003. Change their names without changing the existing entity bindings.
    rear_names = (
        {
            "window_rear_left_open": "window_rear_right",
            "window_rear_right_open": "window_rear_left",
        }
        if china_platform in {"beantech", "gtsp"}
        else {}
    )
    return tuple(
        replace(description, translation_key=rear_names[description.key])
        if description.key in rear_names
        else description
        for description in BINARY_SENSORS
        if china_platform == "beantech" or description.key not in BEANTECH_BINARY_SENSOR_KEYS
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM binary sensors."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmBinarySensor(entry.runtime_data.coordinator, vehicle["vin"], description)
            for description in _binary_sensor_descriptions_for_vehicle(
                vehicle, entry.runtime_data.coordinator.region
            )
        ),
    )


class GwmBinarySensor(GwmEntity, BinarySensorEntity):
    """A GWM binary sensor."""

    entity_description: GwmBinarySensorEntityDescription

    def __init__(
        self,
        coordinator,
        vin: str,
        description: GwmBinarySensorEntityDescription,
    ) -> None:
        super().__init__(coordinator, vin)
        self.entity_description = description
        self._attr_unique_id = f"{vin}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        return self.entity_description.value_fn(self.vehicle)
