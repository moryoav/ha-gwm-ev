"""Select platform for BeanTech time-of-day dropdowns."""

from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities
from .errors import GwmCommandError

PARALLEL_UPDATES = 0

# How often an entity re-reads a car value the app can change, so an app-side
# change is reflected without restarting Home Assistant.
POLLED_READ_INTERVAL = 60.0

_LOGGER = logging.getLogger(__name__)

# The app offers 5-minute granularity over a full day for these time settings.
_FIVE_MINUTE_TIMES = [
    f"{hour:02d}:{minute:02d}" for hour in range(24) for minute in range(0, 60, 5)
]


def _clock_to_today_ms(value: str) -> int:
    """Convert an ``HH:MM`` selection into today's epoch ms (tomorrow if passed)."""
    hour, minute = value.split(":", 1)
    now = dt_util.now()
    target = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return int(target.timestamp() * 1000)


def _ms_to_clock(value_ms: int) -> str | None:
    """Convert an epoch-ms timestamp into a 5-minute ``HH:MM`` selection."""
    try:
        local = dt_util.as_local(dt_util.utc_from_timestamp(value_ms / 1000))
    except (OverflowError, OSError, ValueError):
        return None
    minute = (local.minute // 5) * 5
    return f"{local.hour:02d}:{minute:02d}"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM select entities."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmChargeWindowStartSelect(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmChargeWindowEndSelect(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmBatteryAppointmentSelect(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
            GwmCabinCleanAppointmentSelect(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),
        ),
    )


class _BeanTechTimeSelect(GwmEntity, SelectEntity):
    """Shared BeanTech time-of-day dropdown entity."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = _FIVE_MINUTE_TIMES

    def __init__(self, api, coordinator, vin: str, *, translation_key: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"
        self._last_read_at = 0.0

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )

    def _handle_coordinator_update(self) -> None:
        """Re-read the charge window on a throttle so app toggles stay synced."""
        super()._handle_coordinator_update()
        reader = getattr(self, "_async_read_window", None)
        if (
            reader is None
            or not self.available
            or time.monotonic() - self._last_read_at < POLLED_READ_INTERVAL
        ):
            return
        self._last_read_at = time.monotonic()
        self.hass.async_create_task(reader())


class GwmChargeWindowStartSelect(_BeanTechTimeSelect):
    """Start of the BeanTech smart-charge window (HH:MM)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, translation_key="charge_window_start")

    @property
    def current_option(self) -> str | None:
        value = self.coordinator.local_flag(self.vin, "charge_window_start")
        return value if value in self._attr_options else None

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

    async def async_select_option(self, option: str) -> None:
        # Optimistically show the new start time, then write it alongside the
        # current end time (read from the last known value, not a fresh read).
        self.coordinator.set_local_flag(self.vin, "charge_window_start", option)
        end_time = self.coordinator.local_flag(self.vin, "charge_window_end")
        if not isinstance(end_time, str):
            end_time = "07:00"
        command = await async_call_gwm_api(
            self._api.async_set_charge_window(
                self.vin, start_time=option, end_time=end_time
            )
        )
        self.coordinator.async_track_command(command, on_terminal=self._async_read_window)


class GwmChargeWindowEndSelect(_BeanTechTimeSelect):
    """End of the BeanTech smart-charge window (HH:MM)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(api, coordinator, vin, translation_key="charge_window_end")

    @property
    def current_option(self) -> str | None:
        value = self.coordinator.local_flag(self.vin, "charge_window_end")
        return value if value in self._attr_options else None

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

    async def async_select_option(self, option: str) -> None:
        # Optimistically show the new end time, then write it alongside the
        # current start time (read from the last known value, not a fresh read).
        self.coordinator.set_local_flag(self.vin, "charge_window_end", option)
        start_time = self.coordinator.local_flag(self.vin, "charge_window_start")
        if not isinstance(start_time, str):
            start_time = "23:00"
        command = await async_call_gwm_api(
            self._api.async_set_charge_window(
                self.vin, start_time=start_time, end_time=option
            )
        )
        self.coordinator.async_track_command(command, on_terminal=self._async_read_window)


class GwmBatteryAppointmentSelect(_BeanTechTimeSelect):
    """Battery appointment heating departure time (HH:MM, within 24 h)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(
            api, coordinator, vin, translation_key="battery_appointment_time"
        )

    @property
    def current_option(self) -> str | None:
        value = self.coordinator.local_flag(self.vin, "battery_appointment_time")
        return value if value in self._attr_options else "08:00"

    async def async_select_option(self, option: str) -> None:
        use_car_time_ms = _clock_to_today_ms(option)
        self.coordinator.set_local_flag(self.vin, "battery_appointment_time", option)
        # Selecting a departure time also arms the appointment, so keep the
        # companion switch in sync with that request.
        self.coordinator.set_local_flag(self.vin, "battery_appointment_heating", True)
        command = await async_call_gwm_api(
            self._api.async_set_battery_heating_appointment(
                self.vin, enable=True, use_car_time_ms=use_car_time_ms
            )
        )
        self.coordinator.async_track_command(command)


class GwmCabinCleanAppointmentSelect(_BeanTechTimeSelect):
    """Cabin-clean scheduled run time (HH:MM, within 24 h)."""

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(
            api, coordinator, vin, translation_key="cabin_clean_appointment_time"
        )

    @property
    def current_option(self) -> str | None:
        value = self.coordinator.local_flag(self.vin, "cabin_clean_appointment_time")
        return value if value in self._attr_options else "08:00"

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if not self.available:
            return
        await self._async_read_state()

    def _handle_coordinator_update(self) -> None:
        """Re-read the scheduled cabin-clean time on a throttle."""
        super()._handle_coordinator_update()
        if (
            not self.available
            or time.monotonic() - self._last_read_at < POLLED_READ_INTERVAL
        ):
            return
        self._last_read_at = time.monotonic()
        self.hass.async_create_task(self._async_read_state())

    async def _async_read_state(self) -> None:
        """Read the scheduled cabin-clean time from the car."""
        try:
            time_ms = await self._api.async_get_cabin_clean_appointment(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read cabin-clean appointment: %s", err)
            return
        if time_ms is None:
            return
        clock = _ms_to_clock(time_ms)
        if clock is not None:
            self.coordinator.set_local_flag(
                self.vin, "cabin_clean_appointment_time", clock
            )

    async def async_select_option(self, option: str) -> None:
        time_ms = _clock_to_today_ms(option)
        await async_call_gwm_api(
            self._api.async_set_cabin_clean_appointment(self.vin, time_ms=time_ms)
        )
        self.coordinator.set_local_flag(self.vin, "cabin_clean_appointment_time", option)
