"""BeanTech cabin-clean appointment time."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from gwm_client import GwmClientError

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities
from .errors import GwmCommandError

PARALLEL_UPDATES = 0
POLLED_READ_INTERVAL = 60.0
_LOGGER = logging.getLogger(__name__)
_FIVE_MINUTE_TIMES = [
    f"{hour:02d}:{minute:02d}" for hour in range(24) for minute in range(0, 60, 5)
]


def _clock_to_today_ms(value: str) -> int:
    """Find the next selected local time, accounting for DST transitions."""
    if value not in _FIVE_MINUTE_TIMES:
        raise HomeAssistantError("Choose a cabin-clean time in five-minute steps")
    hour, minute = map(int, value.split(":"))
    now = dt_util.now()
    target = dt_util.find_next_time_expression_time(
        now.replace(microsecond=0) + timedelta(seconds=1), [0], [minute], [hour]
    )
    return int(target.timestamp() * 1000)


def _ms_to_clock(value_ms: int) -> str | None:
    """Keep the reported time exact, including appointments made in the app."""
    try:
        local = dt_util.as_local(dt_util.utc_from_timestamp(value_ms / 1000))
    except (OverflowError, OSError, ValueError):
        return None
    return f"{local.hour:02d}:{local.minute:02d}"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Register the appointment only for mainland-China BeanTech vehicles."""
    setup_vehicle_entities(
        entry, async_add_entities,
        lambda vehicle: (
            (GwmCabinCleanAppointmentSelect(
                entry.runtime_data.api, entry.runtime_data.coordinator, vehicle["vin"]
            ),)
            if entry.runtime_data.coordinator.region == "cn"
            and str(vehicle.get("platform") or "").strip().casefold() == "beantech"
            else ()
        ),
    )


class GwmCabinCleanAppointmentSelect(GwmEntity, SelectEntity):
    """Select the next cabin-clean run time in Home Assistant's timezone."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_translation_key = "cabin_clean_appointment_time"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_cabin_clean_appointment_time"
        self._time_ms: int | None = None
        self._last_read_at = float("-inf")
        self._read_task: asyncio.Task | None = None
        self._write_lock = asyncio.Lock()
        self._generation = 0

    @property
    def available(self) -> bool:
        return super().available and self.china_vehicle_commands_available and self.is_china_beantech

    @property
    def current_option(self) -> str | None:
        if self._time_ms is None or self._time_ms <= dt_util.utcnow().timestamp() * 1000:
            return None
        return _ms_to_clock(self._time_ms)

    @property
    def options(self) -> list[str]:
        current = self.current_option
        return sorted(set(_FIVE_MINUTE_TIMES) | ({current} if current else set()))

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._cancel_read)
        if self.available:
            await self._async_read_state()

    def _cancel_read(self) -> None:
        if self._read_task is not None:
            self._read_task.cancel()

    def _handle_coordinator_update(self) -> None:
        super()._handle_coordinator_update()
        if (
            not self.available or self._write_lock.locked()
            or (self._read_task is not None and not self._read_task.done())
            or time.monotonic() - self._last_read_at < POLLED_READ_INTERVAL
        ):
            return
        self._read_task = self.hass.async_create_task(self._async_read_state())

    async def _async_read_state(self) -> None:
        self._last_read_at = time.monotonic()
        generation = self._generation
        try:
            time_ms = await self._api.async_get_cabin_clean_appointment(self.vin)
        except (GwmCommandError, GwmClientError) as err:
            _LOGGER.debug("Could not read cabin-clean appointment (%s)", type(err).__name__)
            return
        if generation == self._generation and not self._write_lock.locked():
            self._time_ms = time_ms
            self.async_write_ha_state()

    async def async_select_option(self, option: str) -> None:
        async with self._write_lock:
            if option == self.current_option:
                return
            time_ms = _clock_to_today_ms(option)
            self._generation += 1
            await async_call_gwm_api(
                self._api.async_set_cabin_clean_appointment(self.vin, time_ms=time_ms)
            )
            self._time_ms = time_ms
            self._last_read_at = time.monotonic()
            self.async_write_ha_state()
