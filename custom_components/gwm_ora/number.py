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
            GwmChargeSocNumber(
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
        # BeanTech only accepts whole 5-minute steps (5/10/.../30); other
        # platforms keep the upstream 1-minute step.
        if self.is_china_beantech:
            self._attr_native_step = 5

    @property
    def available(self) -> bool:
        """Return whether the climate run-time setting is available."""
        return super().available and self.climate_commands_available

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


class GwmChargeSocNumber(GwmEntity, NumberEntity):
    """BeanTech charge limit (50-100 %, step 10).

    The car does not report the current limit in the polled snapshot, so the
    value shown is the last one sent from Home Assistant (command-only).
    """

    _attr_translation_key = "charge_soc_limit"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_mode = NumberMode.SLIDER
    _attr_native_min_value = 50
    _attr_native_max_value = 100
    _attr_native_step = 10
    _attr_native_unit_of_measurement = PERCENTAGE

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_charge_soc_limit"

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )

    @property
    def native_value(self) -> float | None:
        """Return the last charge limit sent from Home Assistant."""
        value = self.coordinator.local_flag(self.vin, "charge_soc_limit")
        return float(value) if value is not None else None

    async def async_set_native_value(self, value: float) -> None:
        """Send a new charge limit to the vehicle."""
        percent = int(value)
        if percent % 10 != 0 or percent < 50 or percent > 100:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="invalid_charge_soc_limit",
            )
        command = await async_call_gwm_api(
            self._api.async_set_charge_soc(self.vin, percent=percent)
        )
        self.coordinator.set_local_flag(self.vin, "charge_soc_limit", percent)
        self.coordinator.async_track_command(command)
