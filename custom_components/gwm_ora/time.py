"""Time platform for BeanTech time-of-day controls."""

from __future__ import annotations

import logging
from datetime import time as clock_time
from typing import Any

from homeassistant.components.time import TimeEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities
from .errors import GwmCommandError

PARALLEL_UPDATES = 0

_LOGGER = logging.getLogger(__name__)


def _parse_clock(value: str | None) -> clock_time | None:
    """Parse a ``HH:MM`` string into a ``datetime.time``."""
    if not isinstance(value, str):
        return None
    try:
        hour_text, minute_text = value.split(":", 1)
        return clock_time(int(hour_text), int(minute_text))
    except (ValueError, AttributeError):
        return None


def _format_clock(value: clock_time) -> str:
    """Format a ``datetime.time`` as ``HH:MM``."""
    return f"{value.hour:02d}:{value.minute:02d}"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM time entities."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmChargeWindowStartTime(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmChargeWindowEndTime(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmBatteryAppointmentTime(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmCabinCleanAppointmentTime(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
        ),
    )


class _BeanTechTimeEntity(GwmEntity, TimeEntity):
    """Shared BeanTech time-of-day entity base."""

    def __init__(self, api, coordinator, vin: str, *, translation_key: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )


class GwmChargeWindowStartTime(_BeanTechTimeEntity):
    """Start of the BeanTech smart-charge window (HH:MM)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, translation_key="charge_window_start")

    @property
    def native_value(self) -> clock_time | None:
        return _parse_clock(
            self.coordinator.local_flag(self.vin, "charge_window_start")
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if not self.available:
            return
        await self._async_read_window()

    async def _async_read_window(self) -> dict[str, Any] | None:
        try:
            response = await self._api.async_get_charging_mode(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read charge window: %s", err)
            return None
        self.coordinator.set_local_flag(
            self.vin, "charge_window_start", response.get("start_time")
        )
        self.coordinator.set_local_flag(
            self.vin, "charge_window_end", response.get("end_time")
        )
        return response

    async def async_set_value(self, value: clock_time) -> None:
        current = await self._async_read_window()
        end_time = (
            current.get("end_time")
            if current
            else self.coordinator.local_flag(self.vin, "charge_window_end")
        )
        if not isinstance(end_time, str):
            end_time = "07:00"
        command = await async_call_gwm_api(
            self._api.async_set_charge_window(
                self.vin, start_time=_format_clock(value), end_time=end_time
            )
        )
        self.coordinator.async_track_command(command, on_terminal=self._async_read_window)


class GwmChargeWindowEndTime(_BeanTechTimeEntity):
    """End of the BeanTech smart-charge window (HH:MM)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, translation_key="charge_window_end")

    @property
    def native_value(self) -> clock_time | None:
        return _parse_clock(self.coordinator.local_flag(self.vin, "charge_window_end"))

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if not self.available:
            return
        await self._async_read_window()

    async def _async_read_window(self) -> dict[str, Any] | None:
        try:
            response = await self._api.async_get_charging_mode(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read charge window: %s", err)
            return None
        self.coordinator.set_local_flag(
            self.vin, "charge_window_start", response.get("start_time")
        )
        self.coordinator.set_local_flag(
            self.vin, "charge_window_end", response.get("end_time")
        )
        return response

    async def async_set_value(self, value: clock_time) -> None:
        current = await self._async_read_window()
        start_time = (
            current.get("start_time")
            if current
            else self.coordinator.local_flag(self.vin, "charge_window_start")
        )
        if not isinstance(start_time, str):
            start_time = "23:00"
        command = await async_call_gwm_api(
            self._api.async_set_charge_window(
                self.vin, start_time=start_time, end_time=_format_clock(value)
            )
        )
        self.coordinator.async_track_command(command, on_terminal=self._async_read_window)


class GwmBatteryAppointmentTime(_BeanTechTimeEntity):
    """Battery appointment heating departure time (HH:MM, within 24 h)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, translation_key="battery_appointment_time")

    @property
    def native_value(self) -> clock_time | None:
        return _parse_clock(
            self.coordinator.local_flag(self.vin, "battery_appointment_time")
        )

    async def async_set_value(self, value: clock_time) -> None:
        import time as _time

        now = _time.localtime()
        target = _time.mktime(
            (now.tm_year, now.tm_mon, now.tm_mday, value.hour, value.minute, 0, 0, 0, -1)
        )
        now_seconds = _time.mktime(now)
        # A departure earlier today means tomorrow.
        if target < now_seconds:
            target += 24 * 3600
        use_car_time_ms = int(target * 1000)
        self.coordinator.set_local_flag(
            self.vin, "battery_appointment_time", _format_clock(value)
        )
        command = await async_call_gwm_api(
            self._api.async_set_battery_heating_appointment(
                self.vin, enable=True, use_car_time_ms=use_car_time_ms
            )
        )
        self.coordinator.async_track_command(command)


class GwmCabinCleanAppointmentTime(_BeanTechTimeEntity):
    """Cabin-clean appointment time (HH:MM, within 24 h)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(
            api, coordinator, vin, translation_key="cabin_clean_appointment_time"
        )

    @property
    def native_value(self) -> clock_time | None:
        return None

    async def async_set_value(self, value: clock_time) -> None:
        import time as _time

        now = _time.localtime()
        target = _time.mktime(
            (now.tm_year, now.tm_mon, now.tm_mday, value.hour, value.minute, 0, 0, 0, -1)
        )
        now_seconds = _time.mktime(now)
        if target < now_seconds:
            target += 24 * 3600
        time_ms = int(target * 1000)
        await async_call_gwm_api(
            self._api.async_set_cabin_clean_appointment(self.vin, time_ms=time_ms)
        )
