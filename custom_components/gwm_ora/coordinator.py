"""Data coordinator for GWM."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from gwm_client import GwmAuthenticationError, GwmClientError

from .cloud_commands import GwmCommandApi
from .cloud_runtime import GwmCloudClient
from .const import DOMAIN
from .errors import GwmCommandError

_LOGGER = logging.getLogger(__name__)


class GwmDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator that polls the GWM cloud and tracks vehicle commands."""

    _TERMINAL_COMMAND_STATES = {"completed", "failed", "timeout", "canceled"}

    def __init__(
        self,
        hass: HomeAssistant,
        api: GwmCommandApi,
        *,
        cloud_client: GwmCloudClient,
        config_entry: ConfigEntry | None = None,
        update_interval_seconds: int = 30,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval_seconds),
        )
        self.api = api
        self.cloud_client = cloud_client
        self._command_tasks: dict[str, asyncio.Task[None]] = {}
        self._command_statuses: dict[str, str] = {}
        self._charging_plan_active: dict[str, bool] = {}

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            data = await self.cloud_client.async_get_vehicle_data()
            if self.config_entry is not None:
                try:
                    await self.api.async_cleanup_owned_charging_plans(
                        dict(self.config_entry.data)
                    )
                except Exception:
                    _LOGGER.warning(
                        "Could not inspect owned charging plans; the next poll will retry"
                    )
            return self._overlay_command_statuses(data)
        except GwmAuthenticationError as err:
            self._log_cloud_refresh_failure(err)
            with suppress(Exception):
                await self.cloud_client.async_authentication_rejected()
            raise ConfigEntryAuthFailed(
                "GWM cloud authentication was rejected"
            ) from err
        except GwmClientError as err:
            self._log_cloud_refresh_failure(err)
            message = f"GWM cloud {err.category} during {err.operation}"
            if (api_code := getattr(err, "api_code", None)) is not None:
                message += f" (API code {api_code})"
            raise UpdateFailed(message) from err

    def _log_cloud_refresh_failure(self, error: GwmClientError) -> None:
        """Log only the client's bounded, sanitized failure metadata."""

        _LOGGER.warning(
            "GWM cloud refresh failed: region=%s type=%s category=%s "
            "operation=%s api_code=%s http_status=%s retry_after_seconds=%s",
            self.cloud_client.region,
            type(error).__name__,
            error.category,
            error.operation,
            getattr(error, "api_code", None),
            getattr(error, "status", None),
            getattr(error, "retry_after_seconds", None),
        )

    @property
    def vehicles(self) -> list[dict[str, Any]]:
        """Return vehicle snapshots."""
        data = self.data or {}
        return list(data.get("vehicles", []))

    @property
    def region(self) -> str:
        """Return the configured cloud region."""
        return str((self.data or {}).get("region") or "").lower()

    def vehicle(self, vin: str) -> dict[str, Any] | None:
        """Return one vehicle snapshot by VIN."""
        return next((vehicle for vehicle in self.vehicles if vehicle.get("vin") == vin), None)

    def resolve_vehicle(self, identifier: str) -> dict[str, Any] | None:
        """Return one vehicle snapshot by internal VIN or display serial number.

        Users supply the human-readable VIN (the device serial number, GWM's
        ``showedVin``). Accept the internal identifier too so service calls can
        use either representation.
        """
        display_identifier = identifier.casefold()
        return next(
            (
                vehicle
                for vehicle in self.vehicles
                if identifier == vehicle.get("vin")
                or display_identifier == str(vehicle.get("serial_number") or "").casefold()
            ),
            None,
        )

    def charging_plan_active(self, vin: str) -> bool | None:
        """Return the last known charging-plan state for a vehicle."""
        return self._charging_plan_active.get(vin)

    def set_charging_plan_active(self, vin: str, active: bool) -> None:
        """Update a vehicle's locally known charging-plan state."""
        self._charging_plan_active[vin] = active
        self.async_update_listeners()

    def async_track_command(self, command: dict[str, Any]) -> None:
        """Track a queued remote command and push status updates into HA."""
        self._apply_command_status(command)
        command_id = command.get("id")
        if not command_id or command.get("state") in self._TERMINAL_COMMAND_STATES:
            return

        if command_id in self._command_tasks:
            return

        task = self.hass.async_create_task(self._async_follow_command(command_id))
        self._command_tasks[command_id] = task
        task.add_done_callback(lambda _: self._command_tasks.pop(command_id, None))

    async def async_cancel_command_tasks(self) -> None:
        """Cancel and join in-flight command polling before transport shutdown."""

        tasks = tuple(self._command_tasks.values())
        self._command_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _async_follow_command(self, command_id: str) -> None:
        """Poll one command until the provider reports a terminal state."""
        deadline_seconds = 310 if self.region == "rus" else 130
        poll_interval = 5
        deadline = time.monotonic() + deadline_seconds
        while time.monotonic() < deadline:
            await asyncio.sleep(poll_interval)
            try:
                command = await self.api.async_get_command(command_id)
            except (GwmCommandError, GwmClientError) as err:
                _LOGGER.debug("Could not refresh GWM command %s status: %s", command_id, err)
                continue

            self._apply_command_status(command)
            if command.get("state") not in self._TERMINAL_COMMAND_STATES:
                continue

            if command.get("state") == "completed":
                await self._async_refresh_after_completed_command()
            return

    async def _async_refresh_after_completed_command(self) -> None:
        """Refresh cached vehicle data immediately after a successful command."""
        with suppress(GwmCommandError, GwmClientError):
            self.async_set_updated_data(
                self._overlay_command_statuses(await self.api.async_refresh())
            )

    def _apply_command_status(self, command: dict[str, Any]) -> None:
        """Overlay a command status onto cached coordinator vehicle data."""
        vin = command.get("vin")
        status = command.get("status")
        if (
            not isinstance(vin, str)
            or not vin
            or not isinstance(status, str)
            or not status
        ):
            return

        self._command_statuses[vin] = status
        if not self.data:
            return

        self.async_set_updated_data(self._overlay_command_statuses(self.data))

    def _overlay_command_statuses(self, data: dict[str, Any]) -> dict[str, Any]:
        """Keep the latest local command result across normal cloud refreshes."""

        if not self._command_statuses:
            return data

        vehicles = []
        changed = False
        for vehicle in data.get("vehicles", []):
            status = self._command_statuses.get(vehicle.get("vin"))
            if status is None or vehicle.get("command_status") == status:
                vehicles.append(vehicle)
                continue

            updated = dict(vehicle)
            updated["command_status"] = status
            vehicles.append(updated)
            changed = True

        if not changed:
            return data

        updated_data = dict(data)
        updated_data["vehicles"] = vehicles
        return updated_data
