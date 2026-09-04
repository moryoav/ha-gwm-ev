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

# How often an entity re-reads a car value that the app can change, so an
# app-side toggle is reflected without restarting Home Assistant.
POLLED_READ_INTERVAL = 60.0

# Departure offset used when arming battery appointment heating without a
# caller-supplied time; the car pre-heats the battery to be ready by then.
DEFAULT_BATTERY_APPOINTMENT_OFFSET_MINUTES = 30

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

    def switches_for_vehicle(vehicle: dict) -> list[GwmEntity]:
        vin = vehicle["vin"]
        api = entry.runtime_data.api
        coordinator = entry.runtime_data.coordinator
        is_beantech = (
            coordinator.region == "cn"
            and str(vehicle.get("platform") or "").lower() == "beantech"
        )
        switches: list[GwmEntity] = [
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="seat_heating_start",
                turn_off_action="seat_heating_stop",
                state_key="front_driver_seat_heater_level",
                translation_key="seat_heating",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="seat_heating_start_passenger",
                turn_off_action="seat_heating_stop_passenger",
                state_key="front_passenger_seat_heater_level",
                translation_key="seat_heating_passenger",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="seat_ventilation_start",
                turn_off_action="seat_ventilation_stop",
                state_key="front_driver_seat_vent_level",
                translation_key="seat_ventilation",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="seat_ventilation_start_passenger",
                turn_off_action="seat_ventilation_stop_passenger",
                state_key="front_passenger_seat_vent_level",
                translation_key="seat_ventilation_passenger",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="steering_wheel_heating",
                turn_off_action="steering_wheel_heatless",
                state_key="steering_wheel_heater_active",
                translation_key="steering_wheel_heating",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="defrost_front_start",
                turn_off_action="defrost_front_stop",
                state_key="front_defroster",
                translation_key="defrost_front",
            ),
            GwmRemoteControlSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="defrost_back_start",
                turn_off_action="defrost_back_stop",
                state_key="rear_defroster",
                translation_key="defrost_back",
            ),
        ]
        if not is_beantech:
            # The overseas charging-schedule and front-defroster switches have no
            # BeanTech equivalent, so they are only created for non-BeanTech cars.
            switches = [
                GwmChargingScheduleSwitch(api, coordinator, vin),
                GwmFrontDefrosterSwitch(api, coordinator, vin),
                *switches,
            ]
        return switches

    setup_vehicle_entities(entry, async_add_entities, switches_for_vehicle)


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
        """Return whether charging control is enabled for this entry.

        BeanTech vehicles use the smart-scheduled-charging switch instead: they
        have a single ``chargingMode`` toggle rather than the plan window this
        switch writes, so exposing both would give one switch that always fails.
        """
        return (
            super().available
            and self.charging_control_available
            and not self.is_china_beantech
        )

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


class GwmRemoteControlSwitch(_OptimisticRemoteSwitch):
    """Generic BeanTech remote-control on/off switch.

    Maps a paired ``turn_on_action``/``turn_off_action`` to the vehicle and
    reads the polled status snapshot for its real state. Seat heating and
    ventilation are exposed as separate driver and passenger switches, each
    reading its own per-seat level from the snapshot.
    """

    def __init__(
        self,
        api,
        coordinator,
        vin: str,
        *,
        turn_on_action: str,
        turn_off_action: str,
        state_key: str,
        translation_key: str,
    ) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._turn_on_action = turn_on_action
        self._turn_off_action = turn_off_action
        self._state_key = state_key
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"

    def _actual_is_on(self) -> bool | None:
        value = vehicle_value(self.vehicle, self._state_key)
        if value is None:
            return None
        return bool(value)

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._turn_on_action)
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._turn_off_action)
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(False)


