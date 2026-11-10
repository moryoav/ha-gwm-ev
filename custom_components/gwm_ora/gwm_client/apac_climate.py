"""Validated APAC climate command payloads; this module does not send requests."""

from __future__ import annotations

import re
from typing import Literal

from .commands import ClimateCommand
from .models import VehicleIdentifier

_PIN_HASH = re.compile(r"[0-9a-f]{32}\Z")
_SEQUENCE = re.compile(r"[0-9a-f]{32}1234\Z")


def climate_payload(
    command: ClimateCommand, *, security_password_hash: str, sequence_number: str
) -> dict[str, object]:
    """Build one validated climate request using the APAC app's observed contract."""
    if (
        type(command) is not ClimateCommand
        or not isinstance(security_password_hash, str)
        or _PIN_HASH.fullmatch(security_password_hash) is None
        or not isinstance(sequence_number, str)
        or _SEQUENCE.fullmatch(sequence_number) is None
    ):
        raise ValueError("apac_climate_command_invalid")
    active = command.mode == "auto"
    return {
        "instructions": {
            "0x04": {
                "airConditioner": {
                    "operationTime": str(command.operation_time_minutes if active else 0),
                    "switchOrder": "1" if active else "2",
                    "temperature": str(command.temperature),
                }
            }
        },
        "remoteType": "0",
        "securityPassword": security_password_hash,
        "seqNo": sequence_number,
        "type": 2,
        "vin": command.identifier.value,
    }


def validate_climate_payload(body: object, vehicle_id: str) -> None:
    """Reject any request that is not a precisely shaped climate operation."""
    try:
        if type(body) is not dict:
            raise ValueError
        ac = body["instructions"]["0x04"]["airConditioner"]
        if type(ac) is not dict or ac["switchOrder"] not in {"1", "2"}:
            raise ValueError
        mode: Literal["auto", "off"] = "auto" if ac["switchOrder"] == "1" else "off"
        temperature = int(ac["temperature"])
        duration = int(ac["operationTime"]) if mode == "auto" else 5
        command = ClimateCommand(VehicleIdentifier(vehicle_id), mode, temperature, duration)
        if body != climate_payload(command, security_password_hash=body["securityPassword"], sequence_number=body["seqNo"]):
            raise ValueError
    except (TypeError, ValueError, KeyError, OverflowError):
        raise ValueError("apac_climate_command_invalid") from None


def climate_defaults_payload(identifier: VehicleIdentifier, temperature: int, operation_time_minutes: int) -> dict[str, object]:
    """Build the prior APAC app's saved climate settings request."""
    if (
        type(identifier) is not VehicleIdentifier or type(temperature) is not int or not 16 <= temperature <= 32
        or type(operation_time_minutes) is not int or not 5 <= operation_time_minutes <= 30
    ):
        raise ValueError("apac_climate_defaults_invalid")
    return {"airConditionerTemperature": str(temperature), "airConditionerTime": str(operation_time_minutes * 60), "vin": identifier.value}


def validate_climate_defaults_payload(body: object, vehicle_id: str) -> None:
    """Reject malformed settings writes and mismatched vehicle identifiers."""
    try:
        if type(body) is not dict:
            raise ValueError
        seconds = int(body["airConditionerTime"])
        if seconds % 60 or body != climate_defaults_payload(VehicleIdentifier(vehicle_id), int(body["airConditionerTemperature"]), seconds // 60):
            raise ValueError
    except (TypeError, ValueError, KeyError, OverflowError):
        raise ValueError("apac_climate_defaults_invalid") from None
