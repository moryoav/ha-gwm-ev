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

from ._diagnostics import _envelope_shape
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
    """Map provisional SOC/electric range only, without retaining raw responses.

    preMileage is intentionally excluded: its electric/combined range meaning
    is not confirmed. Plain electric-range numbers provisionally use km.
    """
    root = _copy_object(data)
    status = _copy_object(root.get("vehiclestatusinfo"))
    charge_value = status.get("charge")
    charge = {} if charge_value is None else _copy_object(charge_value)
    if not any(name in node for node in (status, charge) for name in _FIELDS):
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
    timestamp = root.get("acquisitiontime")
    # Do not invent freshness or guess seconds vs milliseconds.
    acquisition_time = (
        timestamp if type(timestamp) is int and 100_000_000_000 <= timestamp <= 253_402_300_799_999 else None
    )
    with suppress(Exception):
        _LOGGER.debug(
            "GWM GTSP fields: status_present=%s charge_present=%s soc_mapped=%s "
            "electric_range_mapped=%s timestamp_ms_valid=%s",
            tuple(name for name in _FIELDS if name in status),
            tuple(name for name in _FIELDS if name in charge),
            any(item.code == "2013021" for item in items),
            any(item.code == "2011501" for item in items),
            acquisition_time is not None,
        )
    return CloudVehicleStatus(
        device_id=_validated_device_id(vehicle_id, identifier),
        acquisition_time_ms=acquisition_time,
        update_time_ms=acquisition_time,
        items=tuple(items),
    )


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
