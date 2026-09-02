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
            GwmRemoteStartSwitch(api, coordinator, vin),
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
            GwmClimatePresetSwitch(
                api, coordinator, vin, temperature=17, translation_key="fast_cool"
            ),
            GwmClimatePresetSwitch(
                api, coordinator, vin, temperature=31, translation_key="fast_heat"
            ),
            GwmBatteryHeatSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="battery_gun_heat",
                turn_off_action="battery_gun_heat_stop",
                translation_key="battery_gun_heat",
            ),
            GwmBatteryHeatSwitch(
                api,
                coordinator,
                vin,
                turn_on_action="battery_initiative_heat",
                turn_off_action="battery_initiative_heat_stop",
                translation_key="battery_initiative_heat",
            ),
            GwmSmartChargeSwitch(api, coordinator, vin),
            GwmBatteryAppointmentHeatingSwitch(api, coordinator, vin),
            GwmCabinCleanSwitch(api, coordinator, vin),
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


class GwmSmartChargeSwitch(GwmEntity, SwitchEntity):
    """Smart scheduled charging for BeanTech vehicles.

    The car exposes a single ``chargingMode`` toggle: on charges only inside the
    window configured in the app (``customTime``), off charges as soon as it is
    plugged in. The window itself is not editable here -- it is reported as
    attributes so it is visible where the switch is.

    The real ``chargingMode`` is read from ``charge/setting`` and re-read after
    each toggle, so the switch stays in sync with the app instead of trusting a
    start-time-only local guess.
    """

    _attr_translation_key = "smart_charge"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_smart_charge"
        self._start_time: str | None = None
        self._end_time: str | None = None

    async def _async_read_state(self) -> None:
        """Read the charging mode and window from the car."""
        try:
            response = await self._api.async_get_charging_mode(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read the GWM smart charging mode: %s", err)
            return

        self._start_time = response.get("start_time")
        self._end_time = response.get("end_time")
        self.coordinator.set_local_flag(
            self.vin, "smart_charge", bool(response.get("enabled"))
        )

    async def async_added_to_hass(self) -> None:
        """Read the current charging mode when the entity is added."""
        await super().async_added_to_hass()
        if not self.charging_control_available or not self.is_china_beantech:
            return
        await self._async_read_state()

    @property
    def is_on(self) -> bool | None:
        """Return whether scheduled charging is active."""
        return self.coordinator.local_flag(self.vin, "smart_charge")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Expose the charging window configured in the app."""
        if self._start_time is None and self._end_time is None:
            return None
        return {"start_time": self._start_time, "end_time": self._end_time}

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.charging_control_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Charge only inside the window configured in the app."""
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Charge as soon as the car is plugged in."""
        await self._async_set(False)

    async def _async_set(self, enable: bool) -> None:
        command = await async_call_gwm_api(
            self._api.async_set_charging_mode(self.vin, enable=enable),
            forbidden_translation_key="charging_control_unavailable",
        )
        self.coordinator.set_local_flag(self.vin, "smart_charge", enable)
        # Tracked like any other remote command so its result shows up in the
        # command-status sensor. On a terminal state the value is read back so a
        # failure reverts it and a success reflects the vehicle.
        self.coordinator.async_track_command(
            command, on_terminal=self._async_read_state
        )


class GwmBatteryAppointmentHeatingSwitch(GwmEntity, SwitchEntity):
    """BeanTech battery appointment heating on/off.

    The car pre-heats the battery to be ready by a departure time. Arming uses a
    default departure offset; the real armed state is read from
    ``remote-ctrl/config/query`` (not the polled snapshot), so it is cached
    locally and re-read after each toggle.
    """

    _attr_translation_key = "battery_appointment_heating"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_battery_appointment_heating"

    async def _async_read_state(self) -> None:
        try:
            response = await self._api.async_get_battery_heating_appointment(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read battery appointment heating: %s", err)
            return
        self.coordinator.set_local_flag(
            self.vin, "battery_appointment_heating", bool(response.get("enabled"))
        )

    async def async_added_to_hass(self) -> None:
        """Read the armed state when the entity is added."""
        await super().async_added_to_hass()
        if not self.remote_commands_available or not self.is_china_beantech:
            return
        await self._async_read_state()

    @property
    def is_on(self) -> bool | None:
        """Return the last known armed state."""
        return self.coordinator.local_flag(self.vin, "battery_appointment_heating")

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Arm appointment heating for a departure shortly from now."""
        departure_ms = (
            int(time.time() * 1000)
            + DEFAULT_BATTERY_APPOINTMENT_OFFSET_MINUTES * 60 * 1000
        )
        command = await async_call_gwm_api(
            self._api.async_set_battery_heating_appointment(
                self.vin, enable=True, use_car_time_ms=departure_ms
            )
        )
        self.coordinator.set_local_flag(self.vin, "battery_appointment_heating", True)
        self.coordinator.async_track_command(command, on_terminal=self._async_read_state)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Cancel the armed appointment."""
        command = await async_call_gwm_api(
            self._api.async_set_battery_heating_appointment(self.vin, enable=False)
        )
        self.coordinator.set_local_flag(
            self.vin, "battery_appointment_heating", False
        )
        self.coordinator.async_track_command(command, on_terminal=self._async_read_state)


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


class GwmCabinCleanSwitch(_OptimisticRemoteSwitch):
    """BeanTech cabin-clean run trigger.

    Turning on starts the fixed-duration cabin clean immediately; the scheduled
    variant is exposed as a separate ``select`` entity. The command is one-shot,
    so the switch snaps back off once the optimistic timeout elapses.
    """

    _attr_translation_key = "cabin_clean"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_cabin_clean_switch"

    def _actual_is_on(self) -> bool | None:
        return None

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, "cabin_clean")
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._set_optimistic(False)


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
        run_time = self.coordinator.local_flag(self.vin, "remote_start_run_time") or 15
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(
                self.vin, "remote_start", run_time_minutes=run_time
            )
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the engine."""
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, "remote_stop")
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(False)


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


class GwmBatteryHeatSwitch(_OptimisticRemoteSwitch):
    """Battery pack heating (active, or while plugged in).

    The car accepts the heating commands but does not report battery-heat state
    in the polled status snapshot, so the toggled state is kept locally via the
    coordinator's generic local-flag mechanism and only reflects the last
    command sent from Home Assistant.
    """

    def __init__(
        self,
        api,
        coordinator,
        vin: str,
        *,
        turn_on_action: str,
        turn_off_action: str,
        translation_key: str,
    ) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._turn_on_action = turn_on_action
        self._turn_off_action = turn_off_action
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"

    def _actual_is_on(self) -> bool | None:
        """Return the last locally tracked heating state."""
        return self.coordinator.local_flag(self.vin, self._attr_translation_key)

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
        self.coordinator.set_local_flag(self.vin, self._attr_translation_key, True)
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._turn_off_action)
        )
        self.coordinator.async_track_command(command)
        self.coordinator.set_local_flag(self.vin, self._attr_translation_key, False)
        self._set_optimistic(False)


class GwmClimatePresetSwitch(_OptimisticRemoteSwitch):
    """Fast cool / fast heat, driven by the A/C command at a fixed temperature.

    The car has no dedicated fast cool/heat command: both are the normal A/C
    start with the temperature pinned to one end of its 17-31 range.
    """

    def __init__(
        self,
        api,
        coordinator,
        vin: str,
        *,
        temperature: int,
        translation_key: str,
    ) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._temperature = temperature
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"

    @property
    def climate(self) -> dict[str, Any]:
        """Return the vehicle's climate block."""
        vehicle = self.vehicle or {}
        return vehicle.get("climate") or {}

    def _actual_is_on(self) -> bool | None:
        """Return whether the A/C is running at this preset's temperature."""
        if self.climate.get("mode") == "off":
            return False
        return self.climate.get("target_temperature_c") == self._temperature

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.climate_commands_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start the A/C pinned to this preset's temperature."""
        command = await async_call_gwm_api(
            self._api.async_set_climate(
                self.vin, mode="auto", temperature=self._temperature
            )
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the A/C."""
        command = await async_call_gwm_api(
            self._api.async_set_climate(self.vin, mode="off")
        )
        self.coordinator.async_track_command(command)
        self._set_optimistic(False)
