"""Climate platform for GWM."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ClimateEntity, ClimateEntityFeature, HVACMode
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM climate entities."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmClimate(entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]),
        ),
    )


class GwmClimate(GwmEntity, ClimateEntity):
    """GWM A/C climate control."""

    _attr_translation_key = "ac_climate"
    _attr_hvac_modes = [HVACMode.OFF, HVACMode.COOL]
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = 1

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_ac_climate"
        # BeanTech only has an automatic mode (no separate cool/heat).
        self._attr_hvac_modes = (
            [HVACMode.OFF, HVACMode.AUTO]
            if self.is_china_beantech
            else [HVACMode.OFF, HVACMode.COOL]
        )
        if coordinator.region == "cn" and not self.is_china_beantech:
            self._attr_hvac_modes.append(HVACMode.HEAT)
        self._requested_hvac_mode: HVACMode | None = None
        self._requested_target_temperature: float | None = None

    @property
    def available(self) -> bool:
        """Return whether climate control is available."""
        return super().available and self.climate_commands_available

    @property
    def climate(self) -> dict[str, Any]:
        """Return climate data."""
        vehicle = self.vehicle or {}
        return vehicle.get("climate") or {}

    @property
    def hvac_mode(self) -> HVACMode:
        """Return current HVAC mode."""
        if self.climate.get("mode") == "off":
            return HVACMode.OFF
        if self.is_china_beantech:
            return self._requested_hvac_mode or HVACMode.AUTO
        return self._requested_hvac_mode or HVACMode.COOL

    @property
    def hvac_action(self) -> str | None:
        """Return current HVAC action."""
        if self._requested_hvac_mode == HVACMode.HEAT and self.climate.get("mode") != "off":
            return "heating"
        return self.climate.get("action")

    @property
    def current_temperature(self) -> float | None:
        """Return current cabin temperature."""
        return self.climate.get("current_temperature_c")

    @property
    def target_temperature(self) -> float | None:
        """Return target temperature."""
        return self._requested_target_temperature or self.climate.get("target_temperature_c")

    @property
    def min_temp(self) -> float:
        """Return minimum temperature."""
        if self.coordinator.region == "cn":
            return 17
        return self.climate.get("min_temperature_c", 16)

    @property
    def max_temp(self) -> float:
        """Return maximum temperature."""
        if self.coordinator.region == "cn":
            return 31
        return self.climate.get("max_temperature_c", 32)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set HVAC mode."""
        mode = {
            HVACMode.COOL: "cool",
            HVACMode.HEAT: "heat",
            HVACMode.AUTO: "auto",
        }.get(hvac_mode, "off")
        command = await async_call_gwm_api(self._api.async_set_climate(self.vin, mode=mode))
        self._requested_hvac_mode = None if hvac_mode == HVACMode.OFF else hvac_mode
        self.coordinator.async_track_command(command)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set target temperature."""
        if (temperature := kwargs.get(ATTR_TEMPERATURE)) is None:
            return
        command = await async_call_gwm_api(self._api.async_set_climate(self.vin, temperature=int(temperature)))
        self._requested_target_temperature = float(temperature)
        self.coordinator.async_track_command(command)
