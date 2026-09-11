"""Number platform for GWM."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberDeviceClass, NumberEntity, NumberMode
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GwmConfigEntry
from .beantech_charging import BeanTechChargingEntity
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
        ) + (
            (GwmChargeSocNumber(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),)
            if entry.runtime_data.coordinator.region == "cn"
            and str(vehicle.get("platform") or "").lower() == "beantech"
            else ()
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


class GwmChargeSocNumber(BeanTechChargingEntity, NumberEntity):
    """Show the last confirmed HA charge limit; the cloud has no limit readback."""

    _attr_translation_key = "charge_soc_limit"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_mode = NumberMode.SLIDER
    _attr_native_min_value = 50
    _attr_native_max_value = 100
    _attr_native_step = 10
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_assumed_state = True
    _requires_charging_control = True

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin)
        self._attr_unique_id = f"{vin}_charge_soc_limit"
        self._confirmed_percent: float | None = None

    @property
    def native_value(self) -> float | None:
        """Keep the value unknown until GWM confirms a command."""
        return self._confirmed_percent

    async def async_set_native_value(self, value: float) -> None:
        if type(value) not in {int, float} or value not in range(50, 101, 10):
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="invalid_charge_soc_limit"
            )
        percent = int(value)
        await self._async_send_command(
            lambda: self._api.async_set_charge_soc(self.vin, percent=percent),
            confirmed=lambda: setattr(self, "_confirmed_percent", float(percent)),
            accepted=lambda: setattr(self, "_confirmed_percent", None),
        )
