"""Explicit APAC control payloads based on the previously tested integration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from types import MappingProxyType

from .models import VehicleIdentifier

_ACTIONS: Mapping[str, tuple[str, dict[str, object]]] = MappingProxyType({
    "tailgate_open": ("0x09", {"switchOrder": "1", "operationTime": "0"}),
    "tailgate_close": ("0x09", {"switchOrder": "2", "operationTime": "0"}),
    "charge_now": ("0x01", {"switchOrder": "1"}),
    "charge_off": ("0x01", {"switchOrder": "2"}),
    "steering_wheel_heating": ("0x19", {"operationTime": "15", "switchOrder": "1"}),
    "steering_wheel_heatless": ("0x19", {"operationTime": "0", "switchOrder": "2"}),
    "lock": ("0x05", {"operationTime": "0", "switchOrder": "2"}),
    "unlock": ("0x05", {"operationTime": "0", "switchOrder": "1"}),
    "close_windows": ("0x08", {"switchOrder": "2", "window": {"leftFront": "0", "leftBack": "0", "rightFront": "0", "rightBack": "0", "skyLight": ""}}),
    "horn": ("0x06", {"search": {"whistle": "1", "flashing": "0"}}),
    "flash_lights": ("0x06", {"search": {"whistle": "0", "flashing": "1"}}),
    "horn_and_lights": ("0x06", {"search": {"whistle": "1", "flashing": "1"}}),
    "sunroof_close": ("0x08", {"window": {"skyLight": 0}}),
    "defrost_front_start": ("0x0B", {"defrost": {"defrostFront": 1, "operationTime": "15", "switchOrder": "1"}}),
    "defrost_front_stop": ("0x0B", {"defrost": {"defrostFront": 0, "operationTime": "0", "switchOrder": "2"}}),
    "defrost_back_start": ("0x0B", {"defrost": {"switchOrder": "1", "operationTime": "15", "defrostBack": "1"}}),
    "defrost_back_stop": ("0x0B", {"defrost": {"switchOrder": "2", "defrostBack": "1"}}),
    "cabin_clean": ("0x11", {"operationTime": "60", "switchOrder": "1"}),
    "remote_start": ("0x04", {"airConditioner": {"operationTime": "15", "switchOrder": "1", "temperature": "22"}}),
    "remote_stop": ("0x04", {"airConditioner": {"operationTime": "0", "switchOrder": "2"}}),
})
_SEAT_ACTIONS = frozenset({
    "seat_heating_start", "seat_heating_stop", "seat_heating_start_passenger", "seat_heating_stop_passenger",
    "seat_ventilation_start", "seat_ventilation_stop", "seat_ventilation_start_passenger", "seat_ventilation_stop_passenger",
} | {f"seat_{kind}{passenger}_level_{level}" for kind in ("heating", "ventilation") for passenger in ("", "_passenger") for level in (1, 2, 3)})


def control_remote_type(action: str) -> str:
    """Return the instruction family used by an allowlisted APAC action."""
    if not isinstance(action, str) or action not in _ACTIONS and action not in _SEAT_ACTIONS:
        raise ValueError("apac_control_invalid")
    return "0x0A" if action in _SEAT_ACTIONS else _ACTIONS[action][0]


def control_payload(
    identifier: VehicleIdentifier, action: str, *, security_password_hash: str, sequence_number: str,
    driver_right: bool | None = None,
) -> dict[str, object]:
    """Construct only previously implemented APAC T5 control payloads."""
    if (
        type(identifier) is not VehicleIdentifier
        or not isinstance(action, str)
        or action not in _ACTIONS and action not in _SEAT_ACTIONS
        or action in _SEAT_ACTIONS and type(driver_right) is not bool
        or not isinstance(security_password_hash, str)
        or re.fullmatch(r"[0-9a-f]{32}", security_password_hash) is None
        or not isinstance(sequence_number, str)
        or re.fullmatch(r"[0-9a-f]{32}1234", sequence_number) is None
    ):
        raise ValueError("apac_control_invalid")
    parameters: dict[str, object]
    if action in _SEAT_ACTIONS:
        stopping = "stop" in action
        seat = {"operationMode": "1" if action.startswith("seat_heating_") else "2", "switchOrder": "2" if stopping else "1", "operationTime": "0" if stopping else "5"}
        if stopping:
            seat.update({"leftFront": "0", "rightFront": "0", "leftBack": "0", "rightBack": "0"})
        else:
            passenger = "passenger" in action
            right = driver_right != passenger
            seat["rightFront" if right else "leftFront"] = action[-1] if "_level_" in action else "3"
        instruction, parameters = "0x0A", {"seat": seat}
    else:
        instruction, parameters = _ACTIONS[action]
    return {
        "instructions": {instruction: deepcopy(parameters)},
        "remoteType": "0",
        "securityPassword": security_password_hash,
        "seqNo": sequence_number,
        "type": 2,
        "vin": identifier.value,
    }


def validate_control_payload(body: object, identifier: str) -> None:
    """Reject all payloads other than the explicitly supported controls."""
    try:
        if type(body) is not dict:
            raise ValueError
        vehicle = VehicleIdentifier(identifier)
        if not any(
            body == control_payload(vehicle, action, security_password_hash=body["securityPassword"], sequence_number=body["seqNo"])
            for action in _ACTIONS
        ) and not any(
            body == control_payload(vehicle, action, security_password_hash=body["securityPassword"], sequence_number=body["seqNo"], driver_right=right)
            for action in _SEAT_ACTIONS for right in (False, True)
        ):
            raise ValueError
    except (TypeError, ValueError, KeyError):
        raise ValueError("apac_control_invalid") from None
