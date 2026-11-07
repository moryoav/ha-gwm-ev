"""Entity setup context with the real coordinator and an offline cloud API."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator

VIN = "LGWTEST0000000003"

ACCEPTED = {"id": "accepted", "state": "in_progress"}

def _context(region="cn", platform="beantech", enabled=True):
    hass = HomeAssistant("synthetic-config")
    api = SimpleNamespace(**{name: AsyncMock(return_value=ACCEPTED) for name in (
        "async_vehicle_control", "async_set_comfort_mode", "async_set_climate",
        "async_get_charging_mode", "async_get_battery_heat_status", "async_get_battery_heating_appointment",
    )}, async_get_cabin_clean_appointment=AsyncMock(return_value=None), async_set_cabin_clean_appointment=AsyncMock())
    coordinator = GwmDataUpdateCoordinator(hass, api, cloud_client=SimpleNamespace())
    vehicle = {"vin": VIN, "platform": platform, "values": {}, "capabilities": {
        "china_vehicle_commands": enabled, "climate_commands": enabled,
    }}
    coordinator.async_set_updated_data({"region": region, "vehicles": [vehicle]})
    coordinator.async_track_command = Mock()
    entry = SimpleNamespace(runtime_data=SimpleNamespace(api=api, coordinator=coordinator), async_on_unload=lambda callback: None)
    return hass, api, coordinator, vehicle, entry
