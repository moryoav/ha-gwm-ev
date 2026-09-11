"""Switch platform for GWM charging control."""

from __future__ import annotations

import logging
import time
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .beantech_charging import BeanTechChargingEntity
from .const import DEFAULT_CHARGE_WINDOW_HOURS
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities, vehicle_value
from .errors import GwmCommandError

PARALLEL_UPDATES = 0

_LOGGER = logging.getLogger(__name__)


class GwmSmartChargeSwitch(BeanTechChargingEntity, SwitchEntity):
    """Select scheduled or plug-and-charge mode without changing the saved plan."""

    _attr_translation_key = "smart_charge"
    _requires_charging_control = True

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, read=api.async_get_charging_mode)
        self._attr_unique_id = f"{vin}_smart_charge"

    @property
    def is_on(self) -> bool | None:
        """Return the mode last reported by the vehicle."""
        return self._data.get("enabled")

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_send_command(lambda: self._api.async_set_charging_mode(self.vin, enable=True))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_send_command(lambda: self._api.async_set_charging_mode(self.vin, enable=False))


class GwmBatteryHeatSwitch(BeanTechChargingEntity, SwitchEntity):
    """Control plugged-in or active battery heating with vehicle state readback."""

    def __init__(self, api, coordinator, vin: str, *, plugged_in: bool) -> None:
        super().__init__(api, coordinator, vin, read=api.async_get_battery_heat_status)
        self._action = "battery_gun_heat" if plugged_in else "battery_initiative_heat"
        self._state_key = "gun_warm" if plugged_in else "active_warm"
        self._attr_translation_key = self._action
        self._attr_unique_id = f"{vin}_{self._action}"

    @property
    def is_on(self) -> bool | None:
        """Keep missing switch fields unknown instead of showing them as off."""
        return self._data.get(self._state_key)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_send_command(lambda: self._api.async_vehicle_control(self.vin, self._action))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_send_command(lambda: self._api.async_vehicle_control(self.vin, self._action + "_stop"))


class GwmBatteryAppointmentHeatingSwitch(BeanTechChargingEntity, SwitchEntity):
    """Enable battery heating at a chosen departure time or cancel it."""

    _attr_translation_key = "battery_appointment_heating"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, read=api.async_get_battery_heating_appointment)
        self._attr_unique_id = f"{vin}_battery_appointment_heating"

    @property
    def is_on(self) -> bool | None:
        """Return the appointment state reported by the vehicle."""
        return self._data.get("enabled")

    async def async_turn_on(self, **kwargs: Any) -> None:
        time_ms = self._api.battery_heating_departure_time(self.vin)
        if time_ms is None or time_ms <= dt_util.utcnow().timestamp() * 1000:
            raise HomeAssistantError("Choose a future battery heating departure time first")
        await self._async_send_command(
            lambda: self._api.async_set_battery_heating_appointment(self.vin, enable=True, use_car_time_ms=time_ms)
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_send_command(lambda: self._api.async_set_battery_heating_appointment(self.vin, enable=False))


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
        existing = [
            GwmChargingScheduleSwitch(api, coordinator, vin),
        ]
        if not is_beantech:
            return existing + [GwmFrontDefrosterSwitch(api, coordinator, vin)]
        return [
            GwmSmartChargeSwitch(api, coordinator, vin),
            GwmBatteryHeatSwitch(api, coordinator, vin, plugged_in=True),
            GwmBatteryHeatSwitch(api, coordinator, vin, plugged_in=False),
            GwmBatteryAppointmentHeatingSwitch(api, coordinator, vin),
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


class GwmRemoteControlSwitch(GwmEntity, SwitchEntity):
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

    @property
    def is_on(self) -> bool | None:
        value = vehicle_value(self.vehicle, self._state_key)
        if value is None:
            return None
        return bool(value) if type(value) in {bool, int} else None

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.china_vehicle_commands_available
            and self.is_china_beantech
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._turn_on_action)
        )
        self.coordinator.async_track_command(command)

    async def async_turn_off(self, **kwargs: Any) -> None:
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._turn_off_action)
        )
        self.coordinator.async_track_command(command)
