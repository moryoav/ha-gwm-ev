"""Typed remote-command contracts shared by regional clients and HA orchestration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from .models import VehicleIdentifier
from .regions import Region

type ClimateMode = Literal["auto", "off"]
type ChinaVehicleControlAction = Literal[
    "remote_start",
    "remote_stop",
    "horn",
    "flash_lights",
    "horn_and_lights",
    "tailgate_open",
    "tailgate_close",
    "sunroof_close",
    "sunroof_tilt",
    "sunroof_half",
    "sunroof_full",
    "cabin_purge",
    "force_refresh",
]
type RemoteCommandState = Literal["pending", "completed", "failed"]

NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS: frozenset[ChinaVehicleControlAction] = frozenset(
    {
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "horn_and_lights",
        "tailgate_open",
        "tailgate_close",
        "sunroof_close",
        "sunroof_tilt",
        "sunroof_half",
        "sunroof_full",
        "cabin_purge",
        "force_refresh",
    }
)
BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS: frozenset[ChinaVehicleControlAction] = frozenset(
    {
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "sunroof_close",
    }
)

_COMMAND_IDENTIFIER = re.compile(r"[\x21-\x7e]{1,512}")
_OVERSEAS_SEQUENCE = re.compile(r"[0-9a-f]{32}1234")
_MD5_HASH = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True, slots=True, repr=False)
class ClimateCommand:
    """One fully resolved climate operation ready for a regional wire client."""

    identifier: VehicleIdentifier = field(repr=False)
    mode: ClimateMode
    temperature: int
    operation_time_minutes: int
    currently_on: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.identifier) is not VehicleIdentifier
            or self.mode not in {"auto", "off"}
            or isinstance(self.temperature, bool)
            or not isinstance(self.temperature, int)
            or not 16 <= self.temperature <= 32
            or isinstance(self.operation_time_minutes, bool)
            or not isinstance(self.operation_time_minutes, int)
            or not 5 <= self.operation_time_minutes <= 30
            or type(self.currently_on) is not bool
        ):
            raise ValueError("climate_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class DoorLockCommand:
    """One lock or unlock operation ready for a regional wire client."""

    identifier: VehicleIdentifier = field(repr=False)
    lock: bool

    def __post_init__(self) -> None:
        if type(self.identifier) is not VehicleIdentifier or type(self.lock) is not bool:
            raise ValueError("door_lock_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class CloseWindowsCommand:
    """One close-all-windows operation ready for a regional wire client."""

    identifier: VehicleIdentifier = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.identifier) is not VehicleIdentifier:
            raise ValueError("close_windows_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class FrontDefrosterCommand:
    """One front-defroster start or stop operation."""

    identifier: VehicleIdentifier = field(repr=False)
    enabled: bool

    def __post_init__(self) -> None:
        if type(self.identifier) is not VehicleIdentifier or type(self.enabled) is not bool:
            raise ValueError("front_defroster_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class CabinCleanCommand:
    """One fixed-duration external-air cabin-clean operation."""

    identifier: VehicleIdentifier = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.identifier) is not VehicleIdentifier:
            raise ValueError("cabin_clean_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class ChinaVehicleControlCommand:
    """One platform-filtered mainland-China vehicle-control operation."""

    identifier: VehicleIdentifier = field(repr=False)
    action: ChinaVehicleControlAction
    run_time_minutes: int | None = None

    def __post_init__(self) -> None:
        valid_run_time = self.run_time_minutes is None or (
            not isinstance(self.run_time_minutes, bool)
            and isinstance(self.run_time_minutes, int)
            and 5 <= self.run_time_minutes <= 30
        )
        if (
            type(self.identifier) is not VehicleIdentifier
            or self.action not in NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS
            or not valid_run_time
            or (self.action != "remote_start" and self.run_time_minutes is not None)
        ):
            raise ValueError("china_vehicle_control_command_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class RemoteCommandAcceptance:
    """Provider-owned identifier returned only after command acceptance."""

    command_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.command_id, str) or _COMMAND_IDENTIFIER.fullmatch(self.command_id) is None:
            raise ValueError("command_acceptance_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class RemoteCommandResultItem:
    """One provider result candidate before regional correlation."""

    command_id: str | None = field(default=None, repr=False)
    remote_type: str | None = None
    result_code: str | None = None
    result_message: str | None = None

    def __post_init__(self) -> None:
        for value in (self.command_id, self.remote_type, self.result_code, self.result_message):
            if value is not None and (
                not isinstance(value, str)
                or len(value) > 512
                or any(ord(character) < 0x20 for character in value)
            ):
                raise ValueError("command_result_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class RemoteCommandResult:
    """One correlated provider outcome in the integration's stable lifecycle."""

    state: RemoteCommandState
    result_code: str | None = None
    result_message: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {"pending", "completed", "failed"}:
            raise ValueError("command_result_invalid")
        for value in (self.result_code, self.result_message):
            if value is not None and (
                not isinstance(value, str)
                or len(value) > 512
                or any(ord(character) < 0x20 for character in value)
            ):
                raise ValueError("command_result_invalid")


def validate_overseas_command_inputs(
    command: (
        CabinCleanCommand
        | ClimateCommand
        | CloseWindowsCommand
        | DoorLockCommand
        | FrontDefrosterCommand
    ),
    *,
    security_password_hash: str,
    sequence_number: str,
    region: Region,
) -> None:
    """Reject malformed or region-incompatible command material before I/O."""

    if (
        type(command)
        not in {
            CabinCleanCommand,
            ClimateCommand,
            CloseWindowsCommand,
            DoorLockCommand,
            FrontDefrosterCommand,
        }
        or type(region) is not Region
        or region not in {Region.EU, Region.ANZ, Region.RUSSIA}
        or not isinstance(security_password_hash, str)
        or _MD5_HASH.fullmatch(security_password_hash) is None
        or not isinstance(sequence_number, str)
        or _OVERSEAS_SEQUENCE.fullmatch(sequence_number) is None
    ):
        raise ValueError("remote_command_invalid")


def parse_remote_command_results(
    value: object,
    *,
    allow_integer_strings: bool,
) -> tuple[RemoteCommandResultItem, ...]:
    """Decode only the result fields needed for safe regional correlation."""

    if not isinstance(value, list):
        raise ValueError("command_result_invalid")
    results: list[RemoteCommandResultItem] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("command_result_invalid")
        results.append(
            RemoteCommandResultItem(
                command_id=_optional_text(item.get("hwCommandId"), allow_integer_strings),
                remote_type=_optional_text(item.get("remoteType"), allow_integer_strings),
                result_code=_optional_text(item.get("resultCode"), allow_integer_strings),
                result_message=_optional_text(item.get("resultMsg"), allow_integer_strings),
            )
        )
    return tuple(results)


def select_remote_command_result(
    results: tuple[RemoteCommandResultItem, ...],
    *,
    command_id: str,
    region: Region | None,
    expected_remote_type: str = "0x04",
) -> RemoteCommandResult | None:
    """Apply the add-on's proven regional correlation and result semantics."""

    if (
        not isinstance(results, tuple)
        or any(type(result) is not RemoteCommandResultItem for result in results)
        or not isinstance(command_id, str)
        or _COMMAND_IDENTIFIER.fullmatch(command_id) is None
        or (region is not None and type(region) is not Region)
        or not isinstance(expected_remote_type, str)
    ):
        raise ValueError("command_result_invalid")

    if region is not Region.RUSSIA:
        selected = next(
            (
                result
                for result in results
                if result.command_id is not None
                and result.command_id.casefold() == command_id.casefold()
            ),
            results[0] if results else None,
        )
    else:
        exact_sequence = tuple(
            result
            for result in results
            if result.command_id is not None
            and result.command_id.casefold() == command_id.casefold()
        )
        exact_command = tuple(
            result
            for result in exact_sequence
            if (result.remote_type or "").casefold() == expected_remote_type.casefold()
        )
        missing_sequence = tuple(
            result
            for result in results
            if not result.command_id
            and (result.remote_type or "").casefold() == expected_remote_type.casefold()
        )
        matching_type = tuple(
            result
            for result in results
            if (result.remote_type or "").casefold() == expected_remote_type.casefold()
        )
        candidates = exact_command or exact_sequence or missing_sequence or matching_type
        selected = (
            next((result for result in candidates if _successful(result)), None)
            or next((result for result in candidates if _pending(result, russian=True)), None)
            or next((result for result in candidates if result.result_code == "11"), None)
            or (candidates[0] if candidates else None)
        )

    if selected is None:
        return None
    if _pending(selected, russian=region is Region.RUSSIA) or (
        region is Region.RUSSIA and selected.result_code == "11"
    ):
        state: RemoteCommandState = "pending"
    else:
        state = "completed" if _successful(selected) else "failed"
    return RemoteCommandResult(
        state=state,
        result_code=selected.result_code,
        result_message=selected.result_message,
    )


def _optional_text(value: object, allow_integer: bool) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if allow_integer and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise ValueError("command_result_invalid")


def _pending(result: RemoteCommandResultItem, *, russian: bool) -> bool:
    return result.result_code == "2000" or russian and result.result_code == "1000"


def _successful(result: RemoteCommandResultItem) -> bool:
    return result.result_code in {"0", "6"} or (
        result.result_message is not None and result.result_message.casefold() == "success"
    )


__all__ = [
    "BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS",
    "CabinCleanCommand",
    "ChinaVehicleControlAction",
    "ChinaVehicleControlCommand",
    "CloseWindowsCommand",
    "ClimateCommand",
    "ClimateMode",
    "DoorLockCommand",
    "FrontDefrosterCommand",
    "NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS",
    "RemoteCommandAcceptance",
    "RemoteCommandResult",
    "RemoteCommandResultItem",
    "parse_remote_command_results",
    "select_remote_command_result",
]
