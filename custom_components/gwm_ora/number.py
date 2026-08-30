"""Number platform for GWM."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberDeviceClass, NumberEntity, NumberMode
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GwmConfigEntry
from .const import DOMAIN
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM number entities."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmClimateRunTimeNumber(
                entry.runtime_data.api,
                entry.runtime_data.coordinator,
                vehicle["vin"],
            ),
        ),
    )


class GwmClimateRunTimeNumber(GwmEntity, NumberEntity):
    """GWM climate run-time setting."""

    _attr_translation_key = "climate_run_time"
    _attr_device_class = NumberDeviceClass.DURATION
    _attr_entity_category = EntityCategory.CONFIG
    _attr_mode = NumberMode.SLIDER
    _attr_native_min_value = 5
    _attr_native_max_value = 30
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.MINUTES

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_climate_run_time"

    @property
    def available(self) -> bool:
        """Return whether the climate run-time setting is available."""
        return (
            super().available
            and self.climate_commands_available
            and not self.is_china_beantech
        )

    @property
    def native_value(self) -> float | None:
        """Return the saved climate run time in minutes."""
        saved_value = self._api.climate_operation_time_minutes(self.vin)
        if saved_value is not None:
            return float(saved_value)
        vehicle = self.vehicle or {}
        value: Any = (vehicle.get("climate") or {}).get("operation_time_minutes")
        return float(value) if value is not None else None

    async def async_set_native_value(self, value: float) -> None:
        """Save the climate run time used by the next A/C command."""
        if not float(value).is_integer() or value < 5 or value > 30:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="invalid_climate_run_time",
            )

        command = await async_call_gwm_api(
            self._api.async_set_climate(self.vin, operation_time_minutes=int(value))
        )
        self.coordinator.async_track_command(command)
