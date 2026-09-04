"""Select platform for BeanTech time-of-day dropdowns."""

from __future__ import annotations

import logging
import time

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

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


def _ms_to_clock(value_ms: int) -> str | None:
    """Convert an epoch-ms timestamp into a 5-minute ``HH:MM`` selection."""
    import time as _time

    try:
        local = _time.localtime(value_ms // 1000)
    except (OverflowError, OSError, ValueError):
        return None
    minute = (local.tm_min // 5) * 5
    return f"{local.tm_hour:02d}:{minute:02d}"


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
        self.coordinator.set_local_flag(self.vin, "cabin_clean_appointment_time", option)
        await async_call_gwm_api(
            self._api.async_set_cabin_clean_appointment(self.vin, time_ms=time_ms)
        )
