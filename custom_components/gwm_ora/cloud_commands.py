"""Restart-safe GWM cloud command orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from gwm_client import (
    DEFAULT_OPERATION_TIME_MINUTES,
    DEFAULT_TEMPERATURE_C,
    CabinCleanCommand,
    ChargingPlanCommand,
    ChargingPlanItem,
    ChinaVehicleControlCommand,
    ClimateCommand,
    ClimateMode,
    CloseWindowsCommand,
    DoorLockCommand,
    FrontDefrosterCommand,
    GwmClientError,
    Region,
    VehicleIdentifier,
    is_valid_operation_time,
    normalize_operation_time,
    normalize_temperature,
    select_remote_command_result,
    valid_temperature,
)

from .cloud_auth import GwmCloudCredentials
from .cloud_runtime import GwmCloudClient
from .cloud_storage import (
    GwmCloudStateStore,
    GwmCommandJournalEntry,
    GwmOwnedChargingPlan,
)
from .errors import GwmCommandError, GwmCommandForbidden

_DEFAULT_RESULT_TIMEOUT = timedelta(seconds=90)
_RUSSIA_RESULT_TIMEOUT = timedelta(seconds=300)
_SMART_CHARGE_COMMAND_NAME = "Smart charge"
_LOGGER = logging.getLogger(__name__)


class GwmCommandApi:
    """Expose approved GWM writes over the durable command journal."""

    def __init__(
        self,
        cloud: GwmCloudClient,
        state_store: GwmCloudStateStore,
        credentials: GwmCloudCredentials,
        *,
        enabled: bool,
        charging_enabled: bool = False,
        security_pin: str | None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(state_store) is not GwmCloudStateStore
            or type(credentials) is not GwmCloudCredentials
            or getattr(cloud, "region", None) != credentials.region
            or type(enabled) is not bool
            or type(charging_enabled) is not bool
            or (security_pin is not None and not isinstance(security_pin, str))
            or (clock is not None and not callable(clock))
        ):
            raise ValueError("gwm_command_api_invalid")
        self._cloud = cloud
        self._state_store = state_store
        self._credentials = credentials
        self._enabled = enabled
        self._charging_enabled = charging_enabled
        self._security_pin = security_pin.strip() if security_pin else ""
        self._clock = clock or (lambda: datetime.now(UTC))
        self._commands: dict[str, GwmCommandJournalEntry] = {}
        self._timeout_ids: set[str] = set()
        self._climate_defaults: dict[str, tuple[int, int]] = {}

    async def async_restore(
        self,
        entry_data: dict[str, object],
    ) -> tuple[dict[str, object], ...]:
        """Load accepted commands without ever resending their vehicle operation."""

        journal = await self._state_store.async_get_command_journal(entry_data)
        self._commands = {entry.journal_id: entry for entry in journal}
        return tuple(
            self._command_view(entry)
            for entry in journal
            if entry.state in {"accepted", "polling"}
        )

    async def async_refresh(self) -> dict[str, object]:
        return self._overlay_climate_defaults(await self._cloud.async_get_vehicle_data())

    async def async_get_vehicles(self) -> dict[str, object]:
        return self._overlay_climate_defaults(await self._cloud.async_get_vehicle_data())

    def climate_operation_time_minutes(self, vehicle_id: str) -> int | None:
        """Return a successfully saved run time while cloud reads catch up."""

        defaults = self._climate_defaults.get(vehicle_id)
        return None if defaults is None else defaults[1]

    async def async_set_climate(
        self,
        vin: str,
        *,
        mode: str | None = None,
        temperature: int | None = None,
        operation_time_minutes: int | None = None,
    ) -> dict[str, object]:
        """Validate, resolve, send, and journal one climate request."""

        self._ensure_available()
        if not isinstance(vin, str):
            raise GwmCommandError("A/C command requires a valid vehicle")
        try:
            identifier = VehicleIdentifier(vin)
        except (TypeError, ValueError):
            raise GwmCommandError("A/C command requires a valid vehicle") from None
        normalized_mode = mode.strip().lower() if isinstance(mode, str) else None
        allowed_modes = {None, "cool", "off"}
        if self._cloud.region == "cn":
            allowed_modes.update({"heat", "auto"})
        if normalized_mode not in allowed_modes:
            raise GwmCommandError(
                "A/C mode must be 'cool', 'heat', or 'off' in mainland China"
                if self._cloud.region == "cn"
                else "A/C mode must be 'cool' or 'off' in this region"
            )
        minimum_temperature, maximum_temperature = (
            (17, 31) if self._cloud.region == "cn" else (16, 32)
        )
        if temperature is not None and (
            isinstance(temperature, bool)
            or not isinstance(temperature, int)
            or not minimum_temperature <= temperature <= maximum_temperature
        ):
            raise GwmCommandError(
                "A/C temperature must be a whole number from "
                f"{minimum_temperature} to {maximum_temperature}"
            )
        if operation_time_minutes is not None and (
            isinstance(operation_time_minutes, bool)
            or not isinstance(operation_time_minutes, int)
            or not is_valid_operation_time(operation_time_minutes)
        ):
            raise GwmCommandError(
                "A/C run time must be a whole number from 5 to 30 minutes"
            )
        if (
            normalized_mode is None
            and temperature is None
            and operation_time_minutes is None
        ):
            raise GwmCommandError(
                "A/C command requires a mode, temperature, or run time"
            )

        run_time_only = normalized_mode is None and temperature is None
        context = await self._cloud.async_get_climate_context(
            identifier,
            include_status=temperature is not None and normalized_mode is None,
        )
        climate = context.basics.climate
        saved_defaults = self._climate_defaults.get(identifier.value)
        stored_temperature = (
            str(saved_defaults[0])
            if saved_defaults is not None
            else None if climate is None else climate.temperature
        )
        stored_operation_time = (
            str(saved_defaults[1])
            if saved_defaults is not None
            else None if climate is None else climate.operation_time
        )
        if run_time_only:
            effective_temperature = valid_temperature(stored_temperature)
            if effective_temperature is None:
                raise GwmCommandError(
                    "Current A/C temperature is unavailable; no settings were changed"
                )
        else:
            effective_temperature = normalize_temperature(
                str(temperature) if temperature is not None else stored_temperature,
                DEFAULT_TEMPERATURE_C,
            )
        if self._cloud.region == "cn" and not 17 <= effective_temperature <= 31:
            effective_temperature = DEFAULT_TEMPERATURE_C
        effective_operation_time = (
            operation_time_minutes
            if operation_time_minutes is not None
            else normalize_operation_time(
                stored_operation_time,
                DEFAULT_OPERATION_TIME_MINUTES,
            )
        )
        currently_on = _climate_is_on(context.status)

        if (
            normalized_mode in {"cool", "heat", "auto"}
            or temperature is not None
            or operation_time_minutes is not None
        ):
            await self._cloud.async_update_climate_defaults(
                identifier,
                temperature=effective_temperature,
                operation_time_minutes=effective_operation_time,
            )
            self._climate_defaults[identifier.value] = (
                effective_temperature,
                effective_operation_time,
            )

        should_send = (
            normalized_mode is not None or temperature is not None and currently_on
        )
        command_name = "A/C run time" if run_time_only else "A/C"
        if not should_send:
            message = (
                f"{command_name}: saved; applies to the next A/C command"
                if run_time_only
                else f"{command_name}: saved; A/C is off so no remote command was sent"
            )
            return _local_completed_command(identifier.value, message)

        command = ClimateCommand(
            identifier=identifier,
            mode=cast(ClimateMode, normalized_mode or "cool"),
            temperature=effective_temperature,
            operation_time_minutes=effective_operation_time,
            currently_on=currently_on,
        )
        if self._cloud.region == "cn":
            acceptance = await self._cloud.async_send_climate_command(command)  # type: ignore[call-arg]
        else:
            acceptance = await self._cloud.async_send_climate_command(
                command,
                security_password_hash=_security_password_hash(self._security_pin),
            )
        return await self._record_acceptance(
            identifier, command_name, acceptance.command_id
        )

    def _overlay_climate_defaults(
        self,
        data: dict[str, object],
    ) -> dict[str, object]:
        """Keep successful writes visible while the provider read model is stale."""
        vehicles = data.get("vehicles")
        if not isinstance(vehicles, list) or not self._climate_defaults:
            return data

        updated_vehicles: list[object] = []
        changed = False
        for item in vehicles:
            if not isinstance(item, dict):
                updated_vehicles.append(item)
                continue
            defaults = self._climate_defaults.get(item.get("vin"))
            if defaults is None:
                updated_vehicles.append(item)
                continue
            vehicle = dict(item)
            climate_value = vehicle.get("climate")
            climate = dict(climate_value) if isinstance(climate_value, dict) else {}
            climate["target_temperature_c"] = defaults[0]
            climate["operation_time_minutes"] = defaults[1]
            vehicle["climate"] = climate
            updated_vehicles.append(vehicle)
            changed = True

        if not changed:
            return data
        updated = dict(data)
        updated["vehicles"] = updated_vehicles
        return updated

    async def async_lock(self, vin: str, action: str) -> dict[str, object]:
        """Validate, send, and journal one lock or unlock request."""

        self._ensure_available()
        identifier = _vehicle_identifier(vin, command_name="Door lock")
        normalized_action = action.strip().lower() if isinstance(action, str) else ""
        if normalized_action not in {"lock", "unlock"}:
            raise GwmCommandError("Door lock action must be 'lock' or 'unlock'")
        command_name = "Door lock" if normalized_action == "lock" else "Door unlock"
        command = DoorLockCommand(identifier, normalized_action == "lock")
        if self._cloud.region == "cn":
            acceptance = await self._cloud.async_send_lock_command(command)  # type: ignore[call-arg]
        else:
            acceptance = await self._cloud.async_send_lock_command(
                command,
                security_password_hash=_security_password_hash(self._security_pin),
            )
        return await self._record_acceptance(
            identifier, command_name, acceptance.command_id
        )

    async def async_close_windows(self, vin: str) -> dict[str, object]:
        """Validate, send, and journal one close-all-windows request."""

        self._ensure_available()
        identifier = _vehicle_identifier(vin, command_name="Window close")
        command = CloseWindowsCommand(identifier)
        if self._cloud.region == "cn":
            acceptance = await self._cloud.async_send_close_windows_command(command)  # type: ignore[call-arg]
        else:
            acceptance = await self._cloud.async_send_close_windows_command(
                command,
                security_password_hash=_security_password_hash(self._security_pin),
            )
        return await self._record_acceptance(
            identifier, "Window close", acceptance.command_id
        )

    async def async_set_front_defroster(
        self,
        vin: str,
        *,
        enabled: bool,
    ) -> dict[str, object]:
        """Validate, send, and journal one overseas front-defroster request."""

        self._ensure_overseas_comfort_commands_available()
        identifier = _vehicle_identifier(vin, command_name="Front defroster")
        if type(enabled) is not bool:
            raise GwmCommandError("Front defroster command requires an on or off state")
        acceptance = await self._cloud.async_send_front_defroster_command(
            FrontDefrosterCommand(identifier, enabled),
            security_password_hash=_security_password_hash(self._security_pin),
        )
        return await self._record_acceptance(
            identifier,
            "Front defroster",
            acceptance.command_id,
        )

    async def async_start_cabin_clean(self, vin: str) -> dict[str, object]:
        """Validate, send, and journal the overseas 60-second air-circulation action."""

        self._ensure_overseas_comfort_commands_available()
        identifier = _vehicle_identifier(vin, command_name="Air circulation")
        acceptance = await self._cloud.async_send_cabin_clean_command(
            CabinCleanCommand(identifier),
            security_password_hash=_security_password_hash(self._security_pin),
        )
        return await self._record_acceptance(
            identifier,
            "Air circulation",
            acceptance.command_id,
        )

    async def async_vehicle_control(
        self,
        vin: str,
        action: str,
        *,
        run_time_minutes: int | None = None,
    ) -> dict[str, object]:
        """Validate, send, and journal one extended mainland-China control."""

        self._ensure_china_vehicle_control_available()
        identifier = _vehicle_identifier(vin, command_name="China vehicle control")
        normalized_action = action.strip().lower() if isinstance(action, str) else ""
        try:
            command = ChinaVehicleControlCommand(
                identifier,
                cast(Any, normalized_action),
                run_time_minutes,
            )
        except ValueError:
            raise GwmCommandError(
                "Unsupported China vehicle control or remote-start run time"
            ) from None
        sender = getattr(self._cloud, "async_send_vehicle_control_command", None)
        if not callable(sender):
            raise GwmCommandForbidden(
                "GWM China vehicle controls are not active for this entry"
            )
        acceptance = await sender(command)
        return await self._record_acceptance(
            identifier,
            _CHINA_VEHICLE_CONTROL_NAMES[command.action],
            acceptance.command_id,
        )

    async def async_get_charging_mode(self, vin: str) -> dict[str, Any]:
        """Return the BeanTech smart-charge state and its configured window.

        ``enabled`` is True when the car charges only inside the app-configured
        window (``chargingMode`` 0); the window itself is surfaced as start/end
        time strings.
        """

        self._ensure_charging_available()
        identifier = _vehicle_identifier(vin, command_name="Smart charge")
        data = await self._cloud.async_get_bean_tech_charge_setting(identifier)
        scheduled = data.get("chargingMode") in (0, "0")
        charge_set_param = data.get("chargeSetParam")
        custom = (
            charge_set_param.get("customTime")
            if isinstance(charge_set_param, dict)
            else None
        )
        start_time = None
        end_time = None
        if isinstance(custom, dict):
            raw_start = custom.get("startTime")
            raw_end = custom.get("endTime")
            start_time = raw_start if isinstance(raw_start, str) else None
            end_time = raw_end if isinstance(raw_end, str) else None
        return {
            "enabled": scheduled,
            "start_time": start_time,
            "end_time": end_time,
        }

    async def async_set_charging_mode(
        self,
        vin: str,
        *,
        enable: bool,
    ) -> dict[str, object]:
        """Set the BeanTech smart-charge mode and journal the write for polling."""

        self._ensure_charging_available()
        if type(enable) is not bool:
            raise GwmCommandError("Smart charge command requires an on or off state")
        identifier = _vehicle_identifier(vin, command_name="Smart charge")
        seq_no = await self._cloud.async_set_bean_tech_charging_mode(
            identifier, enable=enable
        )
        return await self._record_acceptance(identifier, _SMART_CHARGE_COMMAND_NAME, seq_no)

    async def async_get_command(self, command_id: str) -> dict[str, object]:
        """Poll one accepted provider ID and persist every terminal transition."""

        entry = self._commands.get(command_id)
        if entry is None:
            raise GwmCommandError("Remote command was not found")
        if entry.state in {"completed", "failed"}:
            return self._command_view(entry)
        now = self._now()
        if now - entry.created_at >= self._result_timeout:
            return await self._mark_timeout(entry, now)
        if entry.state == "accepted":
            entry = await self._durably_update_command(
                entry,
                state="polling",
                updated_at=now,
            )
        try:
            results = await self._cloud.async_get_remote_command_results(
                VehicleIdentifier(entry.vehicle_id),
                entry.cloud_command_id,
                msg_type=(
                    "charge"
                    if entry.command_name == _SMART_CHARGE_COMMAND_NAME
                    else "remote"
                ),
            )
        except GwmClientError:
            raise
        region = None if self._cloud.region == "cn" else Region(self._cloud.region)
        result = select_remote_command_result(
            results,
            command_id=entry.cloud_command_id,
            region=region,
            expected_remote_type=_expected_remote_type(entry.command_name),
        )
        now = self._now()
        if result is None or result.state == "pending":
            if now - entry.created_at >= self._result_timeout:
                return await self._mark_timeout(entry, now)
            return self._command_view(
                entry,
                status=f"{entry.command_name}: accepted by GWM, waiting for vehicle result",
            )
        state = "completed" if result.state == "completed" else "failed"
        entry = await self._durably_update_command(
            entry,
            state=state,
            updated_at=now,
        )
        status_word = "completed" if state == "completed" else "failed"
        details = result.result_message or "no message"
        code = result.result_code or "unknown"
        return self._command_view(
            entry,
            status=f"{entry.command_name}: {status_word} - {details} [{code}]",
        )

    async def _record_acceptance(
        self,
        identifier: VehicleIdentifier,
        command_name: str,
        cloud_command_id: str,
    ) -> dict[str, object]:
        task = asyncio.create_task(
            self._state_store.async_record_accepted_command(
                self._credentials,
                vehicle_id=identifier.value,
                command_name=command_name,
                cloud_command_id=cloud_command_id,
                accepted_at=self._now(),
            )
        )
        try:
            entry = await asyncio.shield(task)
        except asyncio.CancelledError:
            try:
                entry = await task
            except Exception as err:
                raise GwmCommandError(
                    "GWM accepted the command but its recovery journal could not be saved; do not retry"
                ) from err
            self._commands[entry.journal_id] = entry
            raise
        except Exception as err:
            raise GwmCommandError(
                "GWM accepted the command but its recovery journal could not be saved; do not retry"
            ) from err
        self._commands[entry.journal_id] = entry
        return self._command_view(entry)

    async def _durably_update_command(
        self,
        entry: GwmCommandJournalEntry,
        *,
        state: str,
        updated_at: datetime,
    ) -> GwmCommandJournalEntry:
        """Finish a journal transition before propagating lifecycle cancellation."""

        task = asyncio.create_task(
            self._state_store.async_update_command(
                self._credentials,
                entry.journal_id,
                state=state,
                updated_at=updated_at,
            )
        )
        try:
            updated = await asyncio.shield(task)
        except asyncio.CancelledError:
            try:
                updated = await task
            except Exception as err:
                raise GwmCommandError(
                    "GWM command state changed but its recovery journal could not be updated; do not resend"
                ) from err
            self._commands[updated.journal_id] = updated
            raise
        except Exception as err:
            raise GwmCommandError(
                "GWM command state changed but its recovery journal could not be updated; do not resend"
            ) from err
        self._commands[updated.journal_id] = updated
        return updated

    async def _mark_timeout(
        self,
        entry: GwmCommandJournalEntry,
        now: datetime,
    ) -> dict[str, object]:
        entry = await self._durably_update_command(
            entry,
            state="failed",
            updated_at=now,
        )
        self._timeout_ids.add(entry.journal_id)
        return self._command_view(
            entry,
            state="timeout",
            status=f"{entry.command_name}: timed out waiting for vehicle result",
        )

    def _command_view(
        self,
        entry: GwmCommandJournalEntry,
        *,
        state: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        view_state = state or (
            "timeout"
            if entry.journal_id in self._timeout_ids
            else "in_progress"
            if entry.state in {"accepted", "polling"}
            else entry.state
        )
        if status is None:
            status = {
                "accepted": f"{entry.command_name}: accepted by GWM, waiting for vehicle result",
                "polling": f"{entry.command_name}: accepted by GWM, waiting for vehicle result",
                "completed": f"{entry.command_name}: completed",
                "failed": f"{entry.command_name}: failed",
            }[entry.state]
        return {
            "id": entry.journal_id,
            "vin": entry.vehicle_id,
            "name": entry.command_name,
            "state": view_state,
            "status": status,
        }

    @property
    def _result_timeout(self) -> timedelta:
        return (
            _RUSSIA_RESULT_TIMEOUT
            if self._cloud.region == Region.RUSSIA.value
            else _DEFAULT_RESULT_TIMEOUT
        )

    def _ensure_available(self) -> None:
        if not self._enabled:
            raise GwmCommandForbidden("GWM cloud remote commands are disabled")
        if self._cloud.region != "cn" and not self._security_pin:
            raise GwmCommandForbidden(
                "GWM cloud remote commands require a security PIN"
            )

    def _ensure_china_vehicle_control_available(self) -> None:
        if not self._enabled:
            raise GwmCommandForbidden("GWM cloud remote commands are disabled")
        if self._cloud.region != "cn":
            raise GwmCommandForbidden(
                "These vehicle controls are available only for mainland China"
            )

    def _ensure_overseas_comfort_commands_available(self) -> None:
        """Require the overseas remote-command opt-in and security PIN."""

        self._ensure_available()
        if self._cloud.region == "cn":
            raise GwmCommandForbidden(
                "Front defroster and air circulation controls are not available for mainland China"
            )

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise GwmCommandError("GWM command clock is invalid")
        return value.astimezone(UTC)

    async def async_get_charging_plan(
        self,
        vin: str,
    ) -> dict[str, object]:
        """Return the current validated charging-plan shape."""

        self._ensure_charging_available()
        identifier = _vehicle_identifier(vin, command_name="Charging plan")
        return (await self._cloud.async_get_charging_plan(identifier)).as_dict()

    async def async_set_charging_plan(
        self,
        vin: str,
        *,
        enable: bool,
        start_time: int | None = None,
        end_time: int | None = None,
        plan_type: int | None = None,
        weeks: str | None = None,
    ) -> dict[str, object]:
        """Set or clear one exact integration-owned charging plan."""

        self._ensure_charging_available()
        identifier = _vehicle_identifier(vin, command_name="Charging plan")
        try:
            command = ChargingPlanCommand(
                identifier=identifier,
                enable=enable,
                start_time_ms=start_time,
                end_time_ms=end_time,
                plan_type=plan_type,
                weeks=weeks,
            )
        except (TypeError, ValueError):
            raise GwmCommandError("Charging plan requires a valid window and options") from None
        await self._cloud.async_set_charging_plan(command)
        if not enable:
            await self._durably_remove_owned_plan(identifier.value)
            return {}

        assert start_time is not None
        assert end_time is not None
        owned = GwmOwnedChargingPlan(
            vehicle_id=identifier.value,
            plan_id=None,
            plan_type=plan_type or 0,
            start_time_ms=start_time,
            end_time_ms=end_time,
            weeks=weeks or "",
        )
        await self._durably_save_owned_plan(owned)
        try:
            current = await self._cloud.async_get_charging_plan(identifier)
            matching = next(
                (
                    candidate
                    for candidate in current.items
                    if _charging_plan_matches(candidate, owned)
                ),
                None,
            )
            if matching is not None:
                await self._durably_save_owned_plan(
                    GwmOwnedChargingPlan(
                        vehicle_id=owned.vehicle_id,
                        plan_id=matching.plan_id,
                        plan_type=owned.plan_type,
                        start_time_ms=owned.start_time_ms,
                        end_time_ms=owned.end_time_ms,
                        weeks=owned.weeks,
                    )
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.warning(
                "Charging plan was set, but its server ID could not be confirmed"
            )
        return {}

    async def async_cleanup_owned_charging_plans(
        self,
        entry_data: dict[str, object],
    ) -> None:
        """Clear only unchanged integration-owned plans after opt-out."""

        if self._charging_enabled:
            return
        owned_plans = await self._state_store.async_get_owned_charging_plans(entry_data)
        for owned in owned_plans:
            try:
                identifier = VehicleIdentifier(owned.vehicle_id)
                current = await self._cloud.async_get_charging_plan(identifier)
                matching = next(
                    (
                        candidate
                        for candidate in current.items
                        if _charging_plan_matches(candidate, owned)
                    ),
                    None,
                )
                if matching is not None:
                    await self._cloud.async_set_charging_plan(
                        ChargingPlanCommand(identifier=identifier, enable=False)
                    )
                    _LOGGER.info(
                        "Cleared an unchanged integration-owned charging plan after opt-out"
                    )
                elif any(candidate.active for candidate in current.items):
                    _LOGGER.info(
                        "Left a charging plan unchanged because the official app replaced it"
                    )
                await self._durably_remove_owned_plan(identifier.value)
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.warning(
                    "Could not inspect or clear an owned charging plan; the next poll will retry"
                )

    def _ensure_charging_available(self) -> None:
        if not self._charging_enabled:
            raise GwmCommandForbidden("GWM cloud charging control is disabled")

    async def _durably_save_owned_plan(self, plan: GwmOwnedChargingPlan) -> None:
        task = asyncio.create_task(
            self._state_store.async_set_owned_charging_plan(self._credentials, plan)
        )
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        except Exception as err:
            raise GwmCommandError(
                "GWM accepted the charging plan but ownership could not be saved; do not retry"
            ) from err

    async def _durably_remove_owned_plan(self, vehicle_id: str) -> None:
        task = asyncio.create_task(
            self._state_store.async_remove_owned_charging_plan(
                self._credentials,
                vehicle_id,
            )
        )
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        except Exception as err:
            raise GwmCommandError(
                "GWM cleared the charging plan but ownership could not be updated; do not retry"
            ) from err


def _climate_is_on(status: object) -> bool:
    items = getattr(status, "items", ()) if status is not None else ()
    return any(item.code == "2202001" and str(item.value) == "1" for item in items)


def _charging_plan_matches(
    candidate: ChargingPlanItem,
    owned: GwmOwnedChargingPlan,
) -> bool:
    return (
        candidate.active
        and (owned.plan_id is None or candidate.plan_id == owned.plan_id)
        and candidate.plan_type == str(owned.plan_type)
        and candidate.start_time_ms == owned.start_time_ms
        and candidate.end_time_ms == owned.end_time_ms
        and candidate.weeks == owned.weeks
    )


def _security_password_hash(pin: str) -> str:
    return hashlib.md5(
        pin.encode("ascii", errors="replace"), usedforsecurity=False
    ).hexdigest()


def _vehicle_identifier(vin: object, *, command_name: str) -> VehicleIdentifier:
    if not isinstance(vin, str):
        raise GwmCommandError(f"{command_name} command requires a valid vehicle")
    try:
        return VehicleIdentifier(vin)
    except (TypeError, ValueError):
        raise GwmCommandError(
            f"{command_name} command requires a valid vehicle"
        ) from None


def _expected_remote_type(command_name: str) -> str:
    if command_name == _SMART_CHARGE_COMMAND_NAME:
        return "charge"
    if command_name in {"A/C", "A/C run time"}:
        return "0x04"
    if command_name in {"Door lock", "Door unlock"}:
        return "0x05"
    if command_name == "Window close":
        return "0x08"
    if command_name == "Front defroster":
        return "0x0B"
    if command_name == "Air circulation":
        return "0x11"
    if command_name in _CHINA_VEHICLE_CONTROL_NAMES.values():
        return "china"
    raise GwmCommandError(
        "Remote command journal contains an unsupported command family"
    )


def _local_completed_command(vin: str, status: str) -> dict[str, object]:
    return {
        "id": secrets.token_hex(16),
        "vin": vin,
        "name": "A/C",
        "state": "completed",
        "status": status,
    }


_CHINA_VEHICLE_CONTROL_NAMES = {
    "remote_start": "Remote start",
    "remote_stop": "Remote stop",
    "horn": "Sound horn",
    "flash_lights": "Flash lights",
    "horn_and_lights": "Sound horn and flash lights",
    "tailgate_open": "Tailgate open",
    "tailgate_close": "Tailgate close",
    "sunroof_close": "Sunroof close",
    "sunroof_tilt": "Sunroof tilt",
    "sunroof_half": "Sunroof half open",
    "sunroof_full": "Sunroof fully open",
    "cabin_purge": "Cabin purge",
    "force_refresh": "Force refresh",
    "seat_heating_start": "Driver seat heating",
    "seat_heating_stop": "Driver seat heating off",
    "seat_heating_start_passenger": "Passenger seat heating",
    "seat_heating_stop_passenger": "Passenger seat heating off",
    "seat_ventilation_start": "Driver seat ventilation",
    "seat_ventilation_stop": "Driver seat ventilation off",
    "seat_ventilation_start_passenger": "Passenger seat ventilation",
    "seat_ventilation_stop_passenger": "Passenger seat ventilation off",
    "steering_wheel_heating": "Steering wheel heating",
    "steering_wheel_heatless": "Steering wheel heating off",
    "defrost_front_start": "Front defrost",
    "defrost_front_stop": "Front defrost off",
    "defrost_back_start": "Rear defrost",
    "defrost_back_stop": "Rear defrost off",
    "cabin_clean": "Cabin clean",
    "comfort_warm": "Comfort warm",
    "comfort_cool": "Comfort cool",
    "comfort_off": "Comfort off",
}


__all__ = ["GwmCommandApi"]
