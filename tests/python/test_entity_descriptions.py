"""Static coverage checks for the GWM integration entity descriptions."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

NEW_SENSOR_KEYS = {
    "fuel_level_l",
    "fuel_range_km",
    "tire_pressure_state_front_left",
    "tire_pressure_state_front_right",
    "tire_pressure_state_rear_left",
    "tire_pressure_state_rear_right",
    "tire_temperature_state_front_left",
    "tire_temperature_state_front_right",
    "tire_temperature_state_rear_left",
    "tire_temperature_state_rear_right",
    "window_learn_front_left",
    "window_learn_front_right",
    "window_learn_rear_left",
    "window_learn_rear_right",
    "rear_left_seat_heater_level",
    "rear_right_seat_heater_level",
    "engine_state_code",
    "front_driver_seat_heater_level",
    "front_passenger_seat_heater_level",
    "front_driver_seat_vent_level",
    "front_passenger_seat_vent_level",
    "sunroof_position_code",
    "charge_soc",
    "charging_gun_model",
    "hcu_powertrain_state",
    "power",
    "battery_pack_state",
    "acc_clean_off",
    "tbox_state",
    "wireless_level",
    "oil_segments",
    "aux_battery_level",
    "remaining_usable_charge_percent",
    "battery_pack_current",
    "battery_pack_voltage",
}

NEW_BINARY_SENSOR_KEYS = {
    "door_front_driver_open",
    "door_front_passenger_open",
    "door_rear_driver_side_open",
    "door_rear_passenger_side_open",
    "trunk_open",
    "rear_defroster",
    "steering_wheel_heater_active",
    "front_windscreen_heater_active",
    "gps_authorized",
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


def test_sensor_description_keys_cover_v1_contract() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
    from homeassistant.const import UnitOfElectricCurrent, UnitOfElectricPotential, UnitOfPower
    from homeassistant.helpers.entity import EntityCategory

    from custom_components.gwm_ora.sensor import SENSORS

    keys = {description.key for description in SENSORS}

    assert {
        "soc",
        "range_km",
        "fuel_level_l",
        "fuel_range_km",
        "odometer_km",
        "remaining_charging_time_min",
        "charging_status",
        "soce",
        "interior_temperature_c",
        "tire_pressure_state_front_left",
        "window_learn_front_left",
        "front_driver_seat_heater_level",
        "front_driver_seat_vent_level",
        "engine_state_code",
        "sunroof_position_code",
        "command_status",
    } | NEW_SENSOR_KEYS <= keys

    descriptions = {description.key: description for description in SENSORS}
    assert descriptions["acquisition_time"].entity_category is EntityCategory.DIAGNOSTIC
    assert descriptions["update_time"].entity_category is EntityCategory.DIAGNOSTIC
    assert descriptions["command_status"].entity_category is EntityCategory.DIAGNOSTIC
    assert descriptions["acquisition_time"].entity_registry_enabled_default is False
    assert descriptions["update_time"].entity_registry_enabled_default is False
    assert descriptions["command_status"].entity_registry_enabled_default is not False
    assert descriptions["charging_status"].device_class is SensorDeviceClass.ENUM
    assert descriptions["charging_status"].options == [
        "disconnected",
        "connected",
        "charging",
        "charging_complete",
        "awaiting_charging",
        "waiting_for_power",
        "error",
    ]
    assert descriptions["power"].device_class is SensorDeviceClass.POWER
    assert descriptions["power"].native_unit_of_measurement is UnitOfPower.KILO_WATT
    assert descriptions["power"].state_class is SensorStateClass.MEASUREMENT
    assert descriptions["power"].entity_registry_enabled_default is not False
    assert descriptions["battery_pack_current"].device_class is SensorDeviceClass.CURRENT
    assert (
        descriptions["battery_pack_current"].native_unit_of_measurement
        is UnitOfElectricCurrent.AMPERE
    )
    assert descriptions["battery_pack_current"].state_class is SensorStateClass.MEASUREMENT
    assert descriptions["battery_pack_voltage"].device_class is SensorDeviceClass.VOLTAGE
    assert (
        descriptions["battery_pack_voltage"].native_unit_of_measurement
        is UnitOfElectricPotential.VOLT
    )
    assert descriptions["battery_pack_voltage"].state_class is SensorStateClass.MEASUREMENT


def test_binary_sensor_description_keys_cover_v1_contract() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.binary_sensor import BINARY_SENSORS

    keys = {description.key for description in BINARY_SENSORS}

    assert {
        "charging_active",
        "charge_plug_connected",
        "ac_active",
        "lock_open",
        "window_front_left_open",
        "window_front_right_open",
        "window_rear_left_open",
        "window_rear_right_open",
    } | NEW_BINARY_SENSOR_KEYS <= keys


def test_optional_sensor_metadata_matches_home_assistant_semantics() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
    from homeassistant.const import UnitOfVolume
    from homeassistant.helpers.entity import EntityCategory

    from custom_components.gwm_ora.sensor import SENSORS

    descriptions = {description.key: description for description in SENSORS}
    fuel = descriptions["fuel_level_l"]
    assert fuel.device_class is SensorDeviceClass.VOLUME_STORAGE
    assert fuel.native_unit_of_measurement == UnitOfVolume.LITERS
    assert fuel.state_class is SensorStateClass.MEASUREMENT
    assert fuel.entity_registry_enabled_default is False
    assert descriptions["fuel_range_km"].entity_registry_enabled_default is False

    for key in (
        "front_driver_seat_heater_level",
        "front_passenger_seat_heater_level",
        "front_driver_seat_vent_level",
        "front_passenger_seat_vent_level",
    ):
        assert descriptions[key].entity_category is None
        assert descriptions[key].entity_registry_enabled_default is False

    for key in ("engine_state_code", "sunroof_position_code", "window_learn_front_left"):
        assert descriptions[key].entity_category is EntityCategory.DIAGNOSTIC
        assert descriptions[key].entity_registry_enabled_default is False


def test_optional_binary_sensor_metadata_matches_signal_meaning() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.components.binary_sensor import BinarySensorDeviceClass
    from homeassistant.helpers.entity import EntityCategory

    from custom_components.gwm_ora.binary_sensor import BINARY_SENSORS

    descriptions = {description.key: description for description in BINARY_SENSORS}
    for key in ("steering_wheel_heater_active", "front_windscreen_heater_active"):
        assert descriptions[key].device_class is None
        assert descriptions[key].entity_registry_enabled_default is False

    assert descriptions["front_defroster"].device_class is None
    assert descriptions["rear_defroster"].device_class is None

    assert descriptions["gps_authorized"].entity_category is EntityCategory.DIAGNOSTIC
    assert descriptions["gps_authorized"].entity_registry_enabled_default is False

    for key in (
        "door_front_driver_open",
        "door_front_passenger_open",
        "door_rear_driver_side_open",
        "door_rear_passenger_side_open",
    ):
        assert descriptions[key].device_class is BinarySensorDeviceClass.DOOR


def test_optional_value_functions_tolerate_missing_vehicle_data() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.binary_sensor import BINARY_SENSORS
    from custom_components.gwm_ora.sensor import SENSORS

    sensor_descriptions = {description.key: description for description in SENSORS}
    binary_descriptions = {description.key: description for description in BINARY_SENSORS}

    for key in NEW_SENSOR_KEYS:
        assert sensor_descriptions[key].value_fn(None) is None
        assert sensor_descriptions[key].value_fn({"values": {}}) is None

    for key in NEW_BINARY_SENSOR_KEYS:
        assert binary_descriptions[key].value_fn(None) is None
        assert binary_descriptions[key].value_fn({"values": {}}) is None


def test_beantech_entities_are_isolated_from_other_platforms() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.binary_sensor import (
        BEANTECH_BINARY_SENSOR_KEYS,
        _binary_sensor_descriptions_for_vehicle,
    )
    from custom_components.gwm_ora.sensor import (
        BEANTECH_SENSOR_KEYS,
        _sensor_descriptions_for_vehicle,
    )

    navinfo_sensors = {
        description.key
        for description in _sensor_descriptions_for_vehicle({"platform": "navinfo"}, "cn")
    }
    beantech_sensors = {
        description.key
        for description in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "cn")
    }
    navinfo_binary = {
        description.key
        for description in _binary_sensor_descriptions_for_vehicle({"platform": "navinfo"}, "cn")
    }
    beantech_binary = {
        description.key
        for description in _binary_sensor_descriptions_for_vehicle({"platform": "beantech"}, "cn")
    }
    eu_beantech_sensors = {
        description.key
        for description in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "eu")
    }

    assert BEANTECH_SENSOR_KEYS.isdisjoint(navinfo_sensors)
    assert beantech_sensors >= BEANTECH_SENSOR_KEYS
    assert BEANTECH_BINARY_SENSOR_KEYS.isdisjoint(navinfo_binary)
    assert beantech_binary >= BEANTECH_BINARY_SENSOR_KEYS
    assert BEANTECH_SENSOR_KEYS.isdisjoint(eu_beantech_sensors)


def test_beantech_enum_values_reject_unknown_codes() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.sensor import SENSORS

    descriptions = {description.key: description for description in SENSORS}
    hcu = descriptions["hcu_powertrain_state"]
    gun = descriptions["charging_gun_model"]

    assert hcu.value_fn({"values": {"hcu_powertrain_state": 6}}) == "6"
    assert hcu.value_fn({"values": {"hcu_powertrain_state": 99}}) is None
    assert (
        gun.value_fn(
            {"values": {"charge_plug_connected": True, "charging_gun_model": 1}}
        )
        == "1"
    )
    assert (
        gun.value_fn(
            {"values": {"charge_plug_connected": True, "charging_gun_model": 99}}
        )
        is None
    )


def test_beantech_controls_only_expose_mapped_capabilities() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.button import (
        BEANTECH_REMOTE_ACTIONS,
        CHINA_REMOTE_BUTTONS,
        _china_remote_buttons_for_vehicle,
    )
    from custom_components.gwm_ora.entity import (
        _vehicle_charging_control_available,
    )

    beantech_actions = {
        action
        for action, _ in _china_remote_buttons_for_vehicle({"platform": "beantech"})
    }
    navinfo_actions = {
        action
        for action, _ in _china_remote_buttons_for_vehicle({"platform": "navinfo"})
    }

    assert beantech_actions == BEANTECH_REMOTE_ACTIONS
    assert navinfo_actions == {action for action, _ in CHINA_REMOTE_BUTTONS}
    assert not _vehicle_charging_control_available(
        {"capabilities": {"charging_control": False}},
    )
    assert _vehicle_charging_control_available(
        {"capabilities": {"charging_control": True}},
    )


def test_window_entities_keep_unique_ids_but_use_market_safe_values() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.binary_sensor import BINARY_SENSORS

    descriptions = {description.key: description for description in BINARY_SENSORS}
    driver = descriptions["window_front_left_open"]
    passenger = descriptions["window_front_right_open"]

    assert driver.translation_key == "window_front_driver"
    assert passenger.translation_key == "window_front_passenger"
    assert driver.value_fn({"values": {"window_front_driver_open": True}}) is True
    assert passenger.value_fn({"values": {"window_front_passenger_open": False}}) is False
    assert driver.value_fn({"values": {"window_front_left_open": False}}) is False


def test_entity_keys_and_translation_keys_are_unique_and_complete() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora.binary_sensor import BINARY_SENSORS
    from custom_components.gwm_ora.sensor import SENSORS

    translations = json.loads((ROOT / "custom_components/gwm_ora/translations/en.json").read_text(encoding="utf-8"))[
        "entity"
    ]
    icons = json.loads((ROOT / "custom_components/gwm_ora/icons.json").read_text(encoding="utf-8"))["entity"]

    for platform, descriptions in (("sensor", SENSORS), ("binary_sensor", BINARY_SENSORS)):
        keys = [description.key for description in descriptions]
        assert len(keys) == len(set(keys))
        translation_keys = {description.translation_key for description in descriptions}
        assert translation_keys <= set(translations[platform])
        assert set(icons.get(platform, {})) <= set(translations[platform])
    assert set(icons["button"]) <= set(translations["button"])
    assert set(icons["switch"]) <= set(translations["switch"])


def test_platforms_declare_parallel_updates() -> None:
    pytest.importorskip("homeassistant")
    from custom_components.gwm_ora import binary_sensor, button, climate, device_tracker, lock, number, sensor, switch

    assert sensor.PARALLEL_UPDATES == 0
    assert binary_sensor.PARALLEL_UPDATES == 0
    assert climate.PARALLEL_UPDATES == 0
    assert lock.PARALLEL_UPDATES == 0
    assert button.PARALLEL_UPDATES == 0
    assert number.PARALLEL_UPDATES == 0
    assert switch.PARALLEL_UPDATES == 0
    assert device_tracker.PARALLEL_UPDATES == 0


def test_overseas_comfort_control_metadata() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.const import Platform

    from custom_components.gwm_ora.button import GwmCabinCleanButton
    from custom_components.gwm_ora.const import PLATFORMS
    from custom_components.gwm_ora.switch import GwmFrontDefrosterSwitch

    defroster = object.__new__(GwmFrontDefrosterSwitch)
    circulation = object.__new__(GwmCabinCleanButton)

    assert Platform.BUTTON in PLATFORMS
    assert Platform.SWITCH in PLATFORMS
    assert defroster.translation_key == "front_defroster"
    assert circulation.translation_key == "start_air_circulation"


def test_climate_run_time_number_metadata() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.components.number import NumberDeviceClass, NumberMode
    from homeassistant.const import Platform, UnitOfTime
    from homeassistant.helpers.entity import EntityCategory

    from custom_components.gwm_ora.const import PLATFORMS
    from custom_components.gwm_ora.number import GwmClimateRunTimeNumber

    entity = object.__new__(GwmClimateRunTimeNumber)

    assert Platform.NUMBER in PLATFORMS
    assert Platform.SWITCH in PLATFORMS
    assert entity.translation_key == "climate_run_time"
    assert entity.device_class is NumberDeviceClass.DURATION
    assert entity.entity_category is EntityCategory.CONFIG
    assert entity.mode is NumberMode.SLIDER
    assert entity.native_min_value == 5
    assert entity.native_max_value == 30
    assert entity.native_step == 1
    assert entity.native_unit_of_measurement == UnitOfTime.MINUTES


@pytest.mark.asyncio
async def test_climate_run_time_rejects_fractional_values() -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.gwm_ora.number import GwmClimateRunTimeNumber

    entity = object.__new__(GwmClimateRunTimeNumber)

    with pytest.raises(HomeAssistantError) as error:
        await entity.async_set_native_value(5.9)

    assert error.value.translation_key == "invalid_climate_run_time"
