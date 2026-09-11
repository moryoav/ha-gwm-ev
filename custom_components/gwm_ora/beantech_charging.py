"""State readback and command completion for BeanTech charging entities."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from gwm_client import GwmClientError

from .entity import GwmEntity, async_call_gwm_api
from .errors import GwmCommandError

_LOGGER = logging.getLogger(__name__)
_READ_INTERVAL = 60.0


class BeanTechChargingEntity(GwmEntity):
    """Keep charging state confirmed, platform-specific, and safe across unloads."""

    _requires_charging_control = False

    def __init__(self, api, coordinator, vin: str, *, read=None) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._read = read
        self._data: dict[str, Any] = {}
        self._read_task: asyncio.Task | None = None
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._last_read = float("-inf")
        self._generation = 0
        self._removed = False

    @property
    def available(self) -> bool:
        """Use charging consent for charging settings and remote consent for heat."""
        capabilities = (self.vehicle or {}).get("capabilities") or {}
        permitted = (
            capabilities.get("beantech_charging_commands") is True
            if self._requires_charging_control
            else self.china_vehicle_commands_available
        )
        return super().available and self.is_china_beantech and permitted

    async def async_added_to_hass(self) -> None:
        """Read known settings when the entity joins Home Assistant."""
        await super().async_added_to_hass()
        self.async_on_remove(self._cancel_read)
        await self._async_read_state()

    def _cancel_read(self) -> None:
        """Cancel background reads and suppress late command callbacks on removal."""
        self._removed = True
        if self._read_task is not None:
            self._read_task.cancel()

    def _handle_coordinator_update(self) -> None:
        super()._handle_coordinator_update()
        if (
            self._removed or self._read is None or not self.available
            or self._write_lock.locked()
            or (self._read_task is not None and not self._read_task.done())
            or time.monotonic() - self._last_read < _READ_INTERVAL
        ):
            return
        self._read_task = self.hass.async_create_task(self._async_read_state())

    async def _async_read_state(self) -> None:
        """Serialize readback and discard responses made stale by a newer write."""
        async with self._read_lock:
            if self._removed or self._read is None or not self.available:
                return
            self._last_read = time.monotonic()
            generation = self._generation
            try:
                data = await self._read(self.vin)
            except (GwmCommandError, GwmClientError) as err:
                _LOGGER.debug("Could not read BeanTech charging state (%s)", type(err).__name__)
                return
            if not self._removed and generation == self._generation and not self._write_lock.locked():
                self._data = data
                self.async_write_ha_state()

    async def _async_send_command(
        self,
        send: Callable[[], Awaitable[dict[str, Any]]],
        *,
        confirmed: Callable[[], None] | None = None,
        accepted: Callable[[], None] | None = None,
    ) -> None:
        """Change local confirmed values only after a successful terminal result."""
        async with self._write_lock:
            self._generation += 1
            generation = self._generation
            command = await async_call_gwm_api(send())
            self._last_read = time.monotonic()
            if accepted is not None:
                accepted()
                self.async_write_ha_state()

            async def finished(result: dict[str, Any] | None) -> None:
                if self._removed or generation != self._generation:
                    return
                if result is not None and result.get("state") == "completed" and confirmed is not None:
                    confirmed()
                    self.async_write_ha_state()
                await self._async_read_state()

            self.coordinator.async_track_command(command, on_terminal=finished)
