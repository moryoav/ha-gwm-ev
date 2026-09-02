"""Select platform for BeanTech time-of-day dropdowns."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities
from .errors import GwmCommandError

PARALLEL_UPDATES = 0

_LOGGER = logging.getLogger(__name__)

# The app offers 5-minute granularity over a full day for these time settings.
_FIVE_MINUTE_TIMES = [
    f"{hour:02d}:{minute:02d}" for hour in range(24) for minute in range(0, 60, 5)
]


def _clock_to_today_ms(value: str) -> int:
    """Convert an ``HH:MM`` selection into today's epoch ms (tomorrow if passed)."""
    import time as _time

    hour, minute = value.split(":", 1)
    now = _time.localtime()
    target = _time.mktime(
        (now.tm_year, now.tm_mon, now.tm_mday, int(hour), int(minute), 0, 0, 0, -1)
    )
    now_seconds = _time.mktime(now)
    if target < now_seconds:
        target += 24 * 3600
    return int(target * 1000)


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

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.remote_commands_available
            and self.is_china_beantech
        )


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
        return value if value in self._attr_options else None

    async def async_select_option(self, option: str) -> None:
        use_car_time_ms = _clock_to_today_ms(option)
        self.coordinator.set_local_flag(self.vin, "battery_appointment_time", option)
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
        return value if value in self._attr_options else None

    async def async_select_option(self, option: str) -> None:
        time_ms = _clock_to_today_ms(option)
        self.coordinator.set_local_flag(self.vin, "cabin_clean_appointment_time", option)
        await async_call_gwm_api(
            self._api.async_set_cabin_clean_appointment(self.vin, time_ms=time_ms)
        )
