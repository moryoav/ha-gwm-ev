"""GTSP telemetry reaches HA without borrowing another platform's semantics."""

from datetime import UTC, datetime

import pytest

pytest.importorskip("homeassistant")

from homeassistant.helpers.entity import EntityCategory
from test_beantech_entities import VIN, _context

from custom_components.gwm_ora.device_tracker import GwmDeviceTracker
from custom_components.gwm_ora.diagnostics import async_get_config_entry_diagnostics
from custom_components.gwm_ora.sensor import GTSP_SENSORS, _gtsp_raw_value
from custom_components.gwm_ora.sensor import async_setup_entry as setup_sensors
from gwm_client import CloudVehicle, CloudVehicleBasics, VehicleIdentifier, map_vehicle_snapshot
from gwm_client.china_gtsp import map_gtsp_status


@pytest.mark.asyncio
@pytest.mark.parametrize("region,platform", [
    ("cn", "gtsp"), ("cn", " GTSP "), ("cn", "beantech"), ("cn", "navinfo"),
    ("cn", "unknown"), ("eu", "gtsp"), ("aus", "gtsp"), ("rus", "gtsp"),
])
async def test_gtsp_diagnostics_are_optional_and_isolated(region, platform):
    hass, api, _, _, entry = _context(region, platform)
    added = []
    await setup_sensors(hass, entry, added.extend)
    diagnostics = [entity for entity in added if entity.entity_description.key.startswith("gtsp_")]
    expected = region == "cn" and platform.strip().lower() == "gtsp"
    assert len(diagnostics) == (12 if expected else 0)
    assert len({entity.unique_id for entity in added}) == len(added)
    for entity in diagnostics:
        assert entity.native_value is None
        assert entity.entity_description.entity_category == EntityCategory.DIAGNOSTIC
        assert entity.entity_description.entity_registry_enabled_default is False
        assert entity.entity_description.native_unit_of_measurement is None
        assert entity.entity_description.state_class is None
        assert entity.entity_description.device_class is None
    api.async_vehicle_control.assert_not_awaited()


@pytest.mark.parametrize("value,expected", [
    (None, None), (True, None), ({}, None), ("bad", None), ("nan", None),
    ("inf", None), (2**32, None), (-(2**31) - 1, None), ("1", 1),
    ("27.5", 27.5), (-1, -1), (65535, 65535),
])
def test_raw_sensor_does_not_infer_units_enums_or_sentinel_meanings(value, expected):
    assert _gtsp_raw_value("gtsp_charge_status_code")({
        "raw_items": {"gtsp_charge_status_code": {"value": value}}
    }) == expected
    assert _gtsp_raw_value("gtsp_charge_status_code")(None) is None


@pytest.mark.asyncio
async def test_gtsp_telemetry_snapshot_entities_and_redacted_download():
    hass, _, coordinator, _, entry = _context(platform="gtsp", enabled=False)
    identifier = VehicleIdentifier(VIN)
    status = map_gtsp_status({
        "latitude": 12.345, "longitude": 23.456, "gpsSwitchOn": True,
        "acquisitionTime": 1_700_000_000_000, "oilQty": "23.5,L",
        "vehicleStatusInfo": {
            "mileage": "12345,km", "powerBatteryPercent": 92, "evContnsDistance": 183,
            "charge": {"chargeStatus": "2", "bmsBattSocLim": "80,%"},
        },
    }, identifier=identifier, vehicle_id=None)
    vehicle = map_vehicle_snapshot(
        CloudVehicle(identifier=identifier, platform="gtsp"), status, CloudVehicleBasics(),
        refreshed_at=datetime(2026, 9, 20, tzinfo=UTC), remote_commands_available=False,
    ).as_dict()
    coordinator.async_set_updated_data({"region": "cn", "vehicles": [vehicle]})
    added = []
    await setup_sensors(hass, entry, added.extend)
    sensors = {entity.entity_description.key: entity for entity in added}
    assert sensors["odometer_km"].native_value == 12345
    assert sensors["soc"].native_value == 92
    assert sensors["range_km"].native_value == 183
    assert sensors["acquisition_time"].native_value == datetime.fromtimestamp(1_700_000_000, UTC)
    assert sensors["gtsp_oil_quantity_raw"].native_value == 23.5
    assert sensors["gtsp_charge_status_code"].native_value == 2
    assert sensors["gtsp_charge_limit_raw"].native_value == 80
    assert vehicle["raw_items"]["gtsp_oil_quantity_raw"]["unit"] == "l"
    for key in ("fuel_level_l", "charging_active", "charging_status", "charge_plug_connected"):
        assert vehicle["values"][key] is None
    assert not any(vehicle["capabilities"].values())
    tracker = GwmDeviceTracker(coordinator, VIN)
    assert (tracker.latitude, tracker.longitude) == (12.345, 23.456)

    entry.data, entry.options, entry.title, entry.unique_id = {}, {}, "Synthetic", "private-id"
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    redacted = diagnostics["vehicles"]["vehicles"][0]
    assert redacted["location"] == "**REDACTED**"
    assert redacted["vin"] == "**REDACTED**"
    assert "12.345" not in str(diagnostics) and "23.456" not in str(diagnostics)

    # A later incomplete sample must clear optional values, not retain stale telemetry.
    vehicle["raw_items"] = {}
    vehicle["location"] = None
    assert all(sensors[description.key].native_value is None for description in GTSP_SENSORS)
    assert tracker.latitude is None and tracker.longitude is None
