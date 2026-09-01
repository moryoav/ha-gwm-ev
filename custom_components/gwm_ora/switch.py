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

# How long a switch keeps showing the requested state before falling back to
# the value reported by the car.
OPTIMISTIC_STATE_TIMEOUT = 120.0

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
            GwmRemoteStartSwitch(
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


class _OptimisticRemoteSwitch(GwmEntity, SwitchEntity):
    """Switch that shows the requested state until the car reports back.

    Remote commands take a while to land in the polled status snapshot, so a
    plain switch snaps back to the old state right after being toggled. Setting
    ``assumed_state`` would fix that, but it also makes Home Assistant render
    the entity as a pair of on/off buttons instead of a single toggle, so the
    requested state is tracked here with a timeout instead.
    """

    _optimistic_state: bool | None = None
    _optimistic_until: float = 0.0

    def _actual_is_on(self) -> bool | None:
        """Return the state reported by the car."""
        raise NotImplementedError

    @property
    def is_on(self) -> bool | None:
        if (
            self._optimistic_state is not None
            and time.monotonic() < self._optimistic_until
        ):
            return self._optimistic_state
        return self._actual_is_on()

    def _set_optimistic(self, value: bool) -> None:
        """Show ``value`` until the car confirms it or the timeout expires."""
        self._optimistic_state = value
        self._optimistic_until = time.monotonic() + OPTIMISTIC_STATE_TIMEOUT
        self.async_write_ha_state()

    def _handle_coordinator_update(self) -> None:
        # Only stop overriding once the car confirms the requested state, or the
        # timeout expires. Do not budget this by coordinator updates: command
        # status is pushed every couple of seconds, which would clear an
        # optimistic state far sooner than the intended timeout.
        if self._optimistic_state is not None and (
            self._actual_is_on() == self._optimistic_state
            or time.monotonic() >= self._optimistic_until
        ):
            self._optimistic_state = None
        super()._handle_coordinator_update()


class GwmRemoteStartSwitch(_OptimisticRemoteSwitch):
    """Remote engine start/stop for BeanTech vehicles."""

    _attr_translation_key = "remote_start"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_remote_start"

    def _actual_is_on(self) -> bool | None:
        """Return whether the engine is running."""
        return vehicle_value(self.vehicle, "engine_state_code") == 1

    @property
    def available(self) -> bool:
        """Return whether remote start is available."""
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
            and self.security_pin_configured
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start the engine."""
        await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, "remote_start")
        )
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the engine."""
        await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, "remote_stop")
        )
        self._set_optimistic(False)
