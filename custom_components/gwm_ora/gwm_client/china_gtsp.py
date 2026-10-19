"""Experimental, read-only GTSP contract from GWM Android 2.1.8 evidence.

GTSP shares existing app signing constants and account tokens, but not the
BeanTech wire contract or status mapper. No digital-key identity is used.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping
from contextlib import suppress
from urllib.parse import quote, unquote

from ._diagnostics import _envelope_shape, _json_type
from .china_crypto import _BEAN_TECH_SECRET, BEAN_TECH_APP_KEY, _java_url_encode, sha256_hex
from .china_status import _copy_object, _validated_device_id
from .errors import GwmApiError, GwmSchemaError
from .models import CloudStatusItem, CloudVehicleStatus, VehicleIdentifier

STATUS_PATH = "/mabdm/app-bff-vehicle/app-api/api/v2.0/vehicle/getLastStatus"
STATUS_URL = "https://apgdm.gwmcloudcn.com" + STATUS_PATH
_LOGGER = logging.getLogger(__name__)
_FIXED_HEADERS = {
    "brand": "10",
    "terminal": "GW_APP_GWM",
    "rs": "2",
    "enterPriseId": "CC01",
    "requestForm": "android",
    "channel": "APP",
    "language": "zh-cn",
    "requestfrom": "poll",
    "Accept-Encoding": "gzip",
    "User-Agent": "okhttp/4.2.2",
}
_TOKEN_HEADERS = ("ampToken", "accessToken", "tokenId")
_HEADERS = frozenset(_FIXED_HEADERS) | frozenset(_TOKEN_HEADERS) | {
    "vin", "gwm-auth-appkey", "gwm-auth-nonce", "gwm-auth-timestamp", "gwm-auth-sign",
}
_FIELDS = ("powerbatterypercent", "remainelectricpercent", "evcontnsdistance", "premileage")

# Separate signal names prevent unverified GTSP codes acquiring another
# platform's units or enum meanings in the shared snapshot mapper.
GTSP_DIAGNOSTIC_FIELDS = {
    "gtsp_oil_quantity_raw": ("root", "oilqty"),
    "gtsp_secondary_oil_quantity_raw": ("root", "secoilqty"),
    "gtsp_tbox_status_code": ("root", "tboxstatus"),
    "gtsp_charge_status_code": ("charge", "chargestatus"),
    "gtsp_charge_mode_code": ("charge", "chargemode"),
    "gtsp_charge_connected_code": ("charge", "chargeconnected"),
    "gtsp_connect_status_code": ("charge", "connectsts"),
    "gtsp_dc_charge_connection_code": ("charge", "bmsdcchrgconnect"),
    "gtsp_charge_limit_raw": ("charge", "bmsbattsoclim"),
    "gtsp_charging_time_raw": ("charge", "chargingtime"),
    "gtsp_charge_duration_raw": ("charge", "chargedurationtime"),
    "gtsp_reported_range_raw": ("status", "premileage"),
    "gtsp_engine_status_code": ("status", "enginests"),
    "gtsp_powertrain_status_code": ("status", "powertrainsts"),
    "gtsp_gear_status_code": ("status", "hcugearsts"),
    "gtsp_cabin_temperature_raw": ("status", "cbntemp"),
    "gtsp_battery_voltage_raw": ("status", "bmspackvolt"),
    "gtsp_battery_current_raw": ("status", "bmspackcurr"),
    "gtsp_charging_power_raw": ("status", "vcuchrgpowerdisp"),
    "gtsp_power_raw": ("status", "power"),
    "gtsp_ac_status_code": ("status", "airconditionsts"),
    "gtsp_lock_status_code": ("door", "maindrvedoorlocksts"),
    "gtsp_driver_door_code": ("door", "maindrvedoorsts"),
    "gtsp_passenger_door_code": ("door", "vicedoorsts"),
    "gtsp_rear_left_door_code": ("door", "lbdoorsts"),
    "gtsp_rear_right_door_code": ("door", "rbdoorsts"),
    "gtsp_back_door_code": ("door", "backdoorsts"),
    "gtsp_sunroof_code": ("windows", "skylightsts"),
    **{
        f"gtsp_{position}_{label}_code": (group, prefix + field)
        for position, prefix in (("front_left", "lf"), ("front_right", "rf"), ("rear_left", "lb"), ("rear_right", "rb"))
        for label, group, field in (
            ("window", "windows", "winposnsts"),
            ("window_learning", "windows", "winlearnsts"),
            ("tire_pressure_indicator", "tirepress", "tirepressindcrsts"),
            ("tire_temperature_status", "tiretemp", "tiretempsts"),
        )
    },
}
_RAW_UNITS = frozenset({"%", "km", "min", "s", "h", "l", "km/h", "kpa", "bar", "c", "℃", "°c", "a", "v", "w", "kw"})
_ROOT_FIELDS = frozenset({"latitude", "longitude", "gpsswitchon", "hutswitchon", "acquisitiontime", "updatetime", "oilqty", "secoilqty", "tboxstatus"})
_STATUS_FIELDS = frozenset(_FIELDS) | {
    "mileage", "speed", "vehiclespeed", "vehspeed", "enginests", "ignitionstatus", "drivingstatus",
    "hcupowertrainsts", "remainoil", "oilqty", "powerbatterydisplayval", "batterypremileage",
    "incartemperature", "airconditionsts", "battpackcurr", "battpackvolt", "efficiency", "power",
} | {field for group, field in GTSP_DIAGNOSTIC_FIELDS.values() if group == "status"}
_CHARGE_FIELDS = frozenset(_FIELDS) | {field for group, field in GTSP_DIAGNOSTIC_FIELDS.values() if group == "charge"} | {
    "charginggunstatus", "charginggunmodel", "chargesoc",
}
_GROUP_FIELDS = {
    "door": frozenset({"maindrvedoorlocksts", "maindrvedoorsts", "vicedoorsts", "lbdoorsts", "rbdoorsts", "tailgateopenupsts"}),
    "tirepress": frozenset({"lftirepressval", "rftirepressval", "lbtirepressval", "rbtirepressval"}),
    "tiretemp": frozenset({"lftiretempval", "rftiretempval", "lbtiretempval", "rbtiretempval"}),
    "windows": frozenset({"lfwinposnsts", "rfwinposnsts", "lbwinposnsts", "rbwinposnsts", "skylightsts"}),
}
_GROUP_FIELDS = {
    group: names | {field for source, field in GTSP_DIAGNOSTIC_FIELDS.values() if source == group}
    for group, names in _GROUP_FIELDS.items()
}

# GTSP-only provisional BeanTech-like enums. Never pass unrecognized codes to
# generic Boolean helpers, which can interpret extra values as open/unlocked.
_BINARY_FIELDS = {
    "maindrvedoorlocksts": "2208001",  # 0 locked, 1 unlocked
    "maindrvedoorsts": "2206002",  # 0 closed, 1 open
    "vicedoorsts": "2206004",
    "lbdoorsts": "2206003",
    "rbdoorsts": "2206005",
}
_WINDOW_FIELDS = {
    "lfwinposnsts": "2210001", "rfwinposnsts": "2210002",
    "lbwinposnsts": "2210004", "rbwinposnsts": "2210003",
}


def gtsp_sign(method: str, path: str, nonce: str, timestamp: str, parameter: str) -> str:
    """Sign decoded path/query text; the mixed timestamp prefix is intentional."""
    decoded_path = "/" + "/".join(unquote(part) for part in path.split("/") if part)
    canonical = (
        method.upper() + decoded_path
        + f"gwm-auth-appkey:{BEAN_TECH_APP_KEY}gwm-auth-nonce:{nonce}"
        + f"bt-auth-timestamp:{timestamp}" + parameter + _BEAN_TECH_SECRET
    )
    # Java replaceAll("\\s", "") operates on ASCII whitespace by default.
    return sha256_hex(_java_url_encode(re.sub(r"[ \t\n\x0b\f\r]", "", canonical)))


def status_headers(
    *, vin: str, pt_token: str, access_token: str, token_id: str, nonce: str, timestamp: str,
) -> dict[str, str]:
    """Build only the captured ordinary and signing headers for status polling."""
    return {
        **_FIXED_HEADERS,
        "ampToken": pt_token,
        "accessToken": access_token,
        "tokenId": token_id,
        "vin": vin,
        "gwm-auth-appkey": BEAN_TECH_APP_KEY,
        "gwm-auth-nonce": nonce,
        "gwm-auth-timestamp": timestamp,
        "gwm-auth-sign": gtsp_sign("GET", STATUS_PATH, nonce, timestamp, "vin=" + vin),
    }


def validate_status_request(
    *, operation: str, method: str, url: str, headers: Mapping[str, str], body: bytes | None,
) -> None:
    """Allow one exact GET route; never allow GTSP commands or host overrides."""
    vin = headers.get("vin", "")
    nonce = headers.get("gwm-auth-nonce", "")
    timestamp = headers.get("gwm-auth-timestamp", "")
    if (
        operation != "get_last_status" or method != "GET" or body is not None
        or re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin, re.IGNORECASE) is None
        or url != STATUS_URL + "?vin=" + quote(vin, safe="")
        or set(headers) != _HEADERS
        or any(headers.get(name) != value for name, value in _FIXED_HEADERS.items())
        or any(not headers.get(name, "").strip() for name in _TOKEN_HEADERS)
        or headers.get("gwm-auth-appkey") != BEAN_TECH_APP_KEY
        or re.fullmatch(r"[0-9a-f]{16}", nonce) is None
        or re.fullmatch(r"[0-9]{13}", timestamp) is None
        or headers.get("gwm-auth-sign") != gtsp_sign("GET", STATUS_PATH, nonce, timestamp, "vin=" + vin)
    ):
        raise ValueError("route_invalid")


def decode_status_envelope(root: Mapping[str, object]) -> object:
    """Accept only the evidenced success code and an explicit object payload."""
    code = root.get("code")
    if not isinstance(code, str) or not code:
        raise GwmSchemaError(operation="get_last_status")
    if code != "000000":
        raise GwmApiError(operation="get_last_status", api_code=code)
    data = root.get("data")
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation="get_last_status")
    return data


def _number(value: object, *, unit: str, maximum: float) -> str | None:
    if type(value) not in {str, int, float}:
        return None
    text = str(value)
    if len(text) > 128:
        return None
    number, separator, supplied_unit = text.partition(",")
    if separator and supplied_unit.strip().casefold() != unit:
        return None
    try:
        parsed = float(number)
    except ValueError:
        return None
    if not math.isfinite(parsed) or not 0 <= parsed <= maximum:
        return None
    return format(parsed, ".15g")


def map_gtsp_status(
    data: object, *, identifier: VehicleIdentifier, vehicle_id: str | None,
) -> CloudVehicleStatus:
    """Map supported telemetry and isolated raw codes, never retaining responses.

    preMileage provisionally means fuel range, based on the app comparison and
    BeanTech schema. New measurements require an explicit recognized unit.
    """
    root = _copy_object(data)
    log_status_shape(root)
    status_value = root.get("vehiclestatusinfo")
    status = {} if status_value is None else _copy_object(status_value)
    charge_value = status.get("charge")
    charge = {} if charge_value is None else _copy_object(charge_value)
    if not (
        any(name in status for name in _STATUS_FIELDS | _GROUP_FIELDS.keys())
        or any(name in charge for name in _FIELDS) or any(name in root for name in _ROOT_FIELDS)
        or any(field in charge for group, field in GTSP_DIAGNOSTIC_FIELDS.values() if group == "charge")
    ):
        raise ValueError("status_schema_invalid")
    items: list[CloudStatusItem] = []
    for code, unit, maximum, candidates in (
        ("2013021", "%", 100, (
            (status, "powerbatterypercent"), (charge, "powerbatterypercent"),
            (status, "remainelectricpercent"),
        )),
        ("2011501", "km", 10000, (
            (status, "evcontnsdistance"), (charge, "evcontnsdistance"),
        )),
    ):
        for node, name in candidates:
            value = _number(node.get(name), unit=unit, maximum=maximum)
            if value is not None:
                items.append(CloudStatusItem(code, value, unit))
                break
    odometer = _number(status.get("mileage"), unit="km", maximum=10_000_000)
    if odometer is not None:
        items.append(CloudStatusItem("2103010", odometer, "km"))
    nodes = {"root": root, "status": status, "charge": charge,
             **{group: _optional_object(status.get(group)) for group in _GROUP_FIELDS}}
    for code, field, unit, maximum in (
        ("2017002", "remainoil", "L", 300),
        ("2011007", "premileage", "km", 10000),
    ):
        measurement_value = status.get(field)
        if field == "premileage" and measurement_value is None:
            measurement_value = charge.get(field)
        item = _measurement(code, measurement_value, unit=unit, minimum=0, maximum=maximum)
        if item is not None:
            items.append(item)
    for index, prefix in enumerate(("lf", "rf", "lb", "rb"), start=1):
        for group, suffix, code, unit, minimum, maximum in (
            ("tirepress", "tirepressval", f"210100{index}", "kPa", 0, 600),
            ("tiretemp", "tiretempval", f"210100{index + 4}", "°C", -40, 125),
        ):
            item = _measurement(code, nodes[group].get(prefix + suffix), unit=unit, minimum=minimum, maximum=maximum)
            if item is not None:
                items.append(item)
    for group, fields, mapping in (
        ("door", _BINARY_FIELDS, {"0": "0", "1": "1"}),
        ("windows", _WINDOW_FIELDS, {"0": "0", "1": "0", "2": "0", "3": "0", "4": "0", "5": "1"}),
    ):
        for field, code in fields.items():
            raw = _raw_number(code, nodes[group].get(field))
            if raw is not None and raw.unit is None and raw.value in mapping:
                items.append(CloudStatusItem(code, mapping[str(raw.value)]))
    for code, (group, name) in GTSP_DIAGNOSTIC_FIELDS.items():
        raw_value = nodes[group].get(name)
        if code == "gtsp_reported_range_raw" and raw_value is None:
            raw_value = charge.get(name)
        item = _raw_number(code, raw_value)
        if item is not None:
            items.append(item)
    timestamp = root.get("acquisitiontime")
    # Do not invent freshness or guess seconds vs milliseconds.
    acquisition_time = (
        timestamp if type(timestamp) is int and 100_000_000_000 <= timestamp <= 253_402_300_799_999 else None
    )
    latitude, longitude = _coordinates(root)
    with suppress(Exception):
        _LOGGER.debug(
            "GWM GTSP fields: status_present=%s charge_present=%s soc_mapped=%s "
            "electric_range_mapped=%s timestamp_ms_valid=%s odometer_mapped=%s location_mapped=%s",
            tuple(name for name in _FIELDS if name in status),
            tuple(name for name in _FIELDS if name in charge),
            any(item.code == "2013021" for item in items),
            any(item.code == "2011501" for item in items),
            acquisition_time is not None,
            odometer is not None,
            latitude is not None,
        )
    return CloudVehicleStatus(
        device_id=_validated_device_id(vehicle_id, identifier),
        acquisition_time_ms=acquisition_time,
        update_time_ms=acquisition_time,
        latitude=latitude,
        longitude=longitude,
        items=tuple(items),
    )


def _raw_number(code: str, value: object) -> CloudStatusItem | None:
    """Keep bounded numeric diagnostics with no assumed enum or unit semantics."""
    if type(value) not in {str, int, float} or len(str(value)) > 128:
        return None
    text, separator, suffix = str(value).partition(",")
    unit = suffix.strip().casefold() if separator else None
    if unit is not None and unit not in _RAW_UNITS:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    if not math.isfinite(number) or not -(2**31) <= number <= 2**32 - 1:
        return None
    return CloudStatusItem(code, format(number, ".15g"), unit)


def _measurement(code: str, value: object, *, unit: str, minimum: float, maximum: float) -> CloudStatusItem | None:
    """Require wire units and bounded values for newly supported measurements."""
    item = _raw_number(code, value)
    allowed = {"°c", "℃", "c"} if unit == "°C" else {unit.casefold()}
    if item is None or item.unit not in allowed:
        return None
    if not minimum <= float(str(item.value)) <= maximum:
        return None
    return CloudStatusItem(code, item.value, unit)


def _optional_object(value: object) -> dict[str, object]:
    """Malformed optional telemetry must not discard otherwise usable status."""
    try:
        return _copy_object(value)
    except ValueError:
        return {}


def _coordinates(root: Mapping[str, object]) -> tuple[float | None, float | None]:
    """Retain reported coordinates without inventing a fix or a conversion."""
    gps = root.get("gpsswitchon")
    if gps is not None and gps is not True:
        return None, None
    values: list[float] = []
    for name, limit in (("latitude", 90), ("longitude", 180)):
        raw = root.get(name)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return None, None
        try:
            value = float(raw)
        except OverflowError:
            return None, None
        if not math.isfinite(value) or not -limit <= value <= limit:
            return None, None
        values.append(value)
    if values == [0.0, 0.0]:
        return None, None
    return values[0], values[1]


def log_status_shape(root: Mapping[str, object]) -> None:
    """Log fixed property paths and types only, with bounded shallow traversal.

    Unknown keys can contain identifiers, so only their count is reported.
    Candidate names do not claim that any of those fields are supported.
    """
    with suppress(Exception):
        if not _LOGGER.isEnabledFor(logging.DEBUG):
            return
        fields: list[str] = []
        unknown = 0

        def record(node: Mapping[str, object], path: str, names: frozenset[str], groups: frozenset[str]) -> None:
            nonlocal unknown
            unknown += len(set(node) - names - groups)
            for name in sorted(names):
                if name not in node:
                    continue
                value = node[name]
                unit = ""
                if isinstance(value, str) and len(value) <= 128 and "," in value:
                    suffix = value.partition(",")[2].strip().casefold()
                    unit = ":unit=" + (suffix if suffix in _RAW_UNITS else "unrecognized")
                fields.append(f"{path}.{name}:{_json_type(value)}{unit}")

        record(root, "data", _ROOT_FIELDS, frozenset({"vehiclestatusinfo"}))
        if "vehiclestatusinfo" in root:
            fields.append("data.vehiclestatusinfo:" + _json_type(root["vehiclestatusinfo"]))
        status_value = root.get("vehiclestatusinfo")
        if isinstance(status_value, Mapping):
            status = _copy_object(status_value)
            record(status, "data.vehiclestatusinfo", _STATUS_FIELDS, frozenset(_GROUP_FIELDS) | {"charge"})
            for group, names in {"charge": _CHARGE_FIELDS, **_GROUP_FIELDS}.items():
                if group in status:
                    fields.append(f"data.vehiclestatusinfo.{group}:" + _json_type(status[group]))
                if isinstance(status.get(group), Mapping):
                    node = _copy_object(status[group])
                    record(node, "data.vehiclestatusinfo." + group, names, frozenset())
        _LOGGER.debug("GWM GTSP schema: fields=%s unlisted_fields=%s", tuple(fields), unknown)


def log_response(status: int, body: bytes) -> None:
    """Log bounded envelope metadata only, never URLs, headers or field values."""
    with suppress(Exception):
        if not _LOGGER.isEnabledFor(logging.DEBUG):
            return
        shape = _envelope_shape(body)
        _LOGGER.debug(
            "GWM GTSP response: tls=established http_status=%s api_code=%s "
            "data_present=%s data_type=%s envelope_reason=%s",
            status, shape.api_code, shape.data_present, shape.data_type, shape.reason,
        )


def log_failure(category: str) -> None:
    """Emit only known failure labels; exception messages may contain secrets."""
    with suppress(Exception):
        safe = category if category in {
            "tls_error", "network_error", "deadline_exceeded", "redirect_rejected",
            "response_too_large", "protocol_error", "configuration_error", "client_closed",
        } else "client_error"
        _LOGGER.debug("GWM GTSP transport failure: category=%s", safe)
