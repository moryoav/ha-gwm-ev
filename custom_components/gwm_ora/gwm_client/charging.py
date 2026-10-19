"""Typed charging-plan contracts shared by regional clients and HA orchestration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .models import VehicleIdentifier

_WEEKS = re.compile(r"[01]{7}")
_MINIMUM_UNIX_MILLISECONDS = -62_135_596_800_000
_MAXIMUM_UNIX_MILLISECONDS = 253_402_300_799_999
_MINIMUM_WINDOW_MILLISECONDS = 5 * 60 * 1000


@dataclass(frozen=True, slots=True)
class ChargingPlanItem:
    """One bounded charging-plan item returned by GWM."""

    plan_id: int
    plan_type: str
    start_time_ms: int
    end_time_ms: int | None
    weeks: str = ""

    def __post_init__(self) -> None:
        if (
            isinstance(self.plan_id, bool)
            or not isinstance(self.plan_id, int)
            or not -(2**63) <= self.plan_id < 2**63
            or not isinstance(self.plan_type, str)
            or not self.plan_type
            or len(self.plan_type) > 32
            or any(ord(character) < 0x20 for character in self.plan_type)
            or not _valid_milliseconds(self.start_time_ms, allow_zero=True)
            or (
                self.end_time_ms is not None
                and not _valid_milliseconds(self.end_time_ms, allow_zero=True)
            )
            or not isinstance(self.weeks, str)
            or len(self.weeks) > 64
            or any(ord(character) < 0x20 for character in self.weeks)
        ):
            raise ValueError("charging_plan_item_invalid")

    @property
    def active(self) -> bool:
        """Return whether this item represents an enabled plan."""

        return bool(self.plan_type.strip()) and self.plan_type != "-1"

    def as_dict(self) -> dict[str, object]:
        """Return the integration's existing snake-case plan shape."""

        return {
            "plan_id": self.plan_id,
            "plan_type": self.plan_type,
            "start_time": self.start_time_ms,
            "end_time": self.end_time_ms,
            "weeks": self.weeks,
        }


@dataclass(frozen=True, slots=True)
class ChargingPlanInfo:
    """The bounded set of plans currently reported for one vehicle."""

    items: tuple[ChargingPlanItem, ...] = field(default=())

    def __post_init__(self) -> None:
        if (
            not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(type(item) is not ChargingPlanItem for item in self.items)
        ):
            raise ValueError("charging_plan_info_invalid")

    def as_dict(self) -> dict[str, object]:
        """Return the integration's existing snake-case response shape."""

        return {"charge_plan_list": [item.as_dict() for item in self.items]}


@dataclass(frozen=True, slots=True, repr=False)
class ChargingPlanCommand:
    """One validated charging-plan set or clear operation."""

    identifier: VehicleIdentifier = field(repr=False)
    enable: bool
    start_time_ms: int | None = None
    end_time_ms: int | None = None
    plan_type: int | None = None
    weeks: str | None = None

    def __post_init__(self) -> None:
        if type(self.identifier) is not VehicleIdentifier or type(self.enable) is not bool:
            raise ValueError("charging_plan_command_invalid")
        if not self.enable:
            if any(
                value is not None
                for value in (
                    self.start_time_ms,
                    self.end_time_ms,
                    self.plan_type,
                    self.weeks,
                )
            ):
                raise ValueError("charging_plan_command_invalid")
            return
        if not _valid_milliseconds(self.start_time_ms) or not _valid_milliseconds(
            self.end_time_ms
        ):
            raise ValueError("charging_plan_command_invalid")
        assert isinstance(self.start_time_ms, int)
        assert isinstance(self.end_time_ms, int)
        if (
            self.end_time_ms - self.start_time_ms < _MINIMUM_WINDOW_MILLISECONDS
            or self.plan_type is not None
            and (type(self.plan_type) is not int or self.plan_type != 0)
            or self.weeks is not None
            and self.weeks != ""
            and _WEEKS.fullmatch(self.weeks) is None
        ):
            raise ValueError("charging_plan_command_invalid")


def parse_charging_plan_info(
    value: object,
    *,
    allow_numeric_strings: bool,
) -> ChargingPlanInfo:
    """Decode only the charging-plan fields used by ownership-safe control."""

    if not isinstance(value, Mapping):
        raise ValueError("charging_plan_info_invalid")
    raw_items = value.get("chargePlanList")
    if raw_items is None:
        return ChargingPlanInfo()
    if not isinstance(raw_items, list) or len(raw_items) > 100:
        raise ValueError("charging_plan_info_invalid")
    items: list[ChargingPlanItem] = []
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            raise ValueError("charging_plan_info_invalid")
        items.append(
            ChargingPlanItem(
                plan_id=_integer(raw.get("planId"), allow_numeric_strings),
                plan_type=_text(raw.get("planType"), allow_numeric_strings),
                start_time_ms=_integer(
                    raw.get("startTime"),
                    allow_numeric_strings,
                ),
                end_time_ms=(
                    None
                    if raw.get("endTime") is None
                    else _integer(raw.get("endTime"), allow_numeric_strings)
                ),
                weeks=_optional_text(raw.get("weeks"), allow_numeric_strings),
            )
        )
    return ChargingPlanInfo(tuple(items))


def _valid_milliseconds(value: object, *, allow_zero: bool = False) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (allow_zero and value == 0 or _MINIMUM_UNIX_MILLISECONDS <= value <= _MAXIMUM_UNIX_MILLISECONDS)
    )


def _integer(value: object, allow_string: bool) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if allow_string and isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError:
            pass
    raise ValueError("charging_plan_info_invalid")


def _text(value: object, allow_integer: bool) -> str:
    if isinstance(value, str):
        return value
    if allow_integer and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise ValueError("charging_plan_info_invalid")


def _optional_text(value: object, allow_integer: bool) -> str:
    return "" if value is None else _text(value, allow_integer)


__all__ = [
    "ChargingPlanCommand",
    "ChargingPlanInfo",
    "ChargingPlanItem",
    "parse_charging_plan_info",
]
