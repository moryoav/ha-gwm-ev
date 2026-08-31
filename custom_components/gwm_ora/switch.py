"""Switch platform for GWM charging control."""

from __future__ import annotations

import logging
import time
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .const import DEFAULT_CHARGE_WINDOW_HOURS
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities, vehicle_value
from .errors import GwmCommandError

PARALLEL_UPDATES = 0

_LOGGER = logging.getLogger(__name__)


def _charging_plan_is_active(response: dict[str, Any]) -> bool:
    """Return whether a getChargingInfos response contains an active plan."""
    return any(
        plan.get("plan_type") is not None and str(plan["plan_type"]) != "-1"
        for plan in response.get("charge_plan_list") or []
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM switches."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmChargingScheduleSwitch(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmFrontDefrosterSwitch(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
        ),
    )


class GwmFrontDefrosterSwitch(GwmEntity, SwitchEntity):
    """Start or stop the overseas front defroster."""

    _attr_translation_key = "front_defroster"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_front_defroster_control"

    @property
    def available(self) -> bool:
        """Return whether this vehicle reports and supports front defrost."""
        return super().available and self.front_defroster_commands_available

    @property
    def is_on(self) -> bool | None:
        """Return the polled front-defroster state."""
        value = vehicle_value(self.vehicle, "front_defroster")
        return value if isinstance(value, bool) else None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start front defrost for the official app's 15-minute duration."""
        command = await async_call_gwm_api(
            self._api.async_set_front_defroster(self.vin, enabled=True)
        )
        self.coordinator.async_track_command(command)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop front defrost."""
        command = await async_call_gwm_api(
            self._api.async_set_front_defroster(self.vin, enabled=False)
        )
        self.coordinator.async_track_command(command)


class GwmChargingScheduleSwitch(GwmEntity, SwitchEntity):
    """Manual on/off for scheduled charging.

    On sets a charging window from now for DEFAULT_CHARGE_WINDOW_HOURS (the car
    charges only within it); off clears the plan (the car charges whenever it is
    plugged in). For precise windows, use the ``gwm_ora.set_charging_plan``
    service. Optimistic, because the vehicle does not report its charging plan
    in the polled status snapshot.
    """

    _attr_translation_key = "charging_schedule"
    _attr_assumed_state = True

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_charging_schedule"

    async def async_added_to_hass(self) -> None:
        """Load the current charging-plan state when the entity is added."""
        await super().async_added_to_hass()
        if not self.charging_control_available:
            return

        try:
            response = await self._api.async_get_charging_plan(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read the current GWM charging plan: %s", err)
            return

        self.coordinator.set_charging_plan_active(
            self.vin, _charging_plan_is_active(response)
        )

    @property
    def is_on(self) -> bool | None:
        """Return the last known charging-plan state."""
        return self.coordinator.charging_plan_active(self.vin)

    @property
    def available(self) -> bool:
        """Return whether charging control is enabled for this entry."""
        return super().available and self.charging_control_available

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Set a charging window from now for the default duration."""
        now_ms = int(time.time() * 1000)
        end_ms = now_ms + DEFAULT_CHARGE_WINDOW_HOURS * 3600 * 1000
        await async_call_gwm_api(
            self._api.async_set_charging_plan(
                self.vin, enable=True, start_time=now_ms, end_time=end_ms, plan_type=0
            ),
            forbidden_translation_key="charging_control_unavailable",
        )
        self.coordinator.set_charging_plan_active(self.vin, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Clear the charging plan so the car charges whenever it is plugged in."""
        await async_call_gwm_api(
            self._api.async_set_charging_plan(self.vin, enable=False),
            forbidden_translation_key="charging_control_unavailable",
        )
        self.coordinator.set_charging_plan_active(self.vin, False)
