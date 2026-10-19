"""Reuse-only mainland-China discovery/status feasibility client.

This is intentionally not production China authentication.  It accepts only
the five existing session values used by two read operations, never refreshes
or persists them, and cannot request SMS codes or send vehicle mutations.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Self, cast
from urllib.parse import quote

from ._dotnet_json import encode_dotnet_json
from ._protocol import _Deadline
from .china_crypto import (
    AUTO_AI_CKEY,
    DEFAULT_NOTE_ID,
    auto_ai_sign,
    decrypt_g_app,
    default_sign,
    format_china_timestamp,
)
from .china_transport import (
    ChinaAiohttpTransport,
    _ChinaAsyncTransport,
    _ChinaTransportRequest,
    _ChinaTransportResponse,
)
from .config import RequestTimeouts
from .errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRateLimitError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from .models import VehicleIdentifier

_DISCOVERY_URL = "https://gapp-api.gwmapp-h.com/gcar/v1/app/android/vehicle/query-vehicle-list"
_AUTO_AI_URL = "https://ti.gwm.com.cn:8443/tsp/ead"
_SOURCE_APP_VERSION = "2.1.5"
_SOURCE_APP_CODE = "2150"
_OFFICIAL_USER_AGENT = "okhttp/4.2.2"
_DISCOVERY_BODY = b'{"vehicleVersion":13}'
_MAX_JSON_DEPTH = 64
_MAX_ALLOWED_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_SECRET_LENGTH = 16 * 1024
_MAX_DEVICE_SOURCE_LENGTH = 128
_MAX_OPERATION_TIMEOUT = 24 * 60 * 60
_VIN = re.compile(r"[A-HJ-NPR-Z0-9]{17}", re.IGNORECASE)
_DEVICE_SOURCE = re.compile(r"[0-9A-Fa-f-]+")


@dataclass(frozen=True, slots=True)
class ChinaPocConfig:
    """Non-secret timeout and response ceilings for the isolated POC."""

    timeouts: RequestTimeouts = field(default_factory=RequestTimeouts)
    max_compressed_bytes: int = 4 * 1024 * 1024
    max_response_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if type(self.timeouts) is not RequestTimeouts:
            raise ValueError("timeouts_invalid")
        for value in (self.max_compressed_bytes, self.max_response_bytes):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _MAX_ALLOWED_RESPONSE_BYTES
            ):
                raise ValueError("response_limit_invalid")


@dataclass(frozen=True, slots=True)
class ChinaReusedSession:
    """The minimal existing session snapshot required by China reads."""

    device_id: str = field(repr=False)
    g_token: str = field(repr=False)
    bean_tech_access_token: str = field(repr=False)
    user_id: str = field(repr=False)
    bean_id: str = field(repr=False)
    auto_ai_token_id: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            normalized_device_id = normalize_china_device_id(self.device_id)
        except (TypeError, ValueError) as error:
            raise ValueError("china_session_invalid") from error
        values = (
            self.g_token,
            self.bean_tech_access_token,
            self.user_id,
            self.bean_id,
            self.auto_ai_token_id,
        )
        if not all(_valid_session_value(value) for value in values):
            raise ValueError("china_session_invalid")
        object.__setattr__(self, "device_id", normalized_device_id)


@dataclass(frozen=True, slots=True)
class ChinaPocVehicle:
    """The discovery fields needed to authorize the synthetic status read."""

    identifier: VehicleIdentifier = field(repr=False)
    platform: str | None = field(default=None, repr=False)
    vehicle_id: str | None = field(default=None, repr=False)
    network_type: int | None = field(default=None, repr=False)
    series_name: str | None = field(default=None, repr=False)
    brand_name: str | None = field(default=None, repr=False)
    vehicle_type: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ChinaPocStatus:
    """Privacy-minimized evidence that a typed AutoAI status body was read."""

    identifier: VehicleIdentifier = field(repr=False)
    last_update_ms: int | None = field(default=None, repr=False)
    section_count: int = 0
    signal_count: int = 0


class ChinaPocClient:
    """Closed, lifecycle-managed discovery/status POC for an existing session."""

    def __init__(
        self,
        config: ChinaPocConfig,
        session: ChinaReusedSession,
        *,
        transport: _ChinaAsyncTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(config) is not ChinaPocConfig or type(session) is not ChinaReusedSession:
            raise GwmConfigurationError()
        if clock is not None and not callable(clock):
            raise GwmConfigurationError()
        self._config = config
        self._session = session
        self._clock = clock or _utc_now
        self._transport: _ChinaAsyncTransport
        if transport is None:
            self._transport = ChinaAiohttpTransport.create_owned(
                max_compressed_bytes=config.max_compressed_bytes,
                max_response_bytes=config.max_response_bytes,
            )
            self._owns_transport = True
        else:
            self._transport = transport
            self._owns_transport = False
        self._vehicles: dict[str, ChinaPocVehicle] = {}
        self._closed = False
        self._closing = False
        self._close_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> Self:
        if self._closed or self._closing:
            raise GwmClosedError()
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            try:
                async with self._request_lock:
                    if self._owns_transport:
                        await self._transport.aclose()
            except BaseException:
                self._closing = False
                raise
            self._closed = True
            self._closing = False

    async def acquire_vehicles(self, *, timeout: float | None = None) -> tuple[ChinaPocVehicle, ...]:
        """Read and retain only the vehicle fields needed by the status POC."""

        operation = "acquire_vehicles"
        return await self._run_operation(
            operation,
            timeout=timeout,
            action=self._acquire_vehicles_locked,
            commit=self._commit_vehicles,
        )

    async def _acquire_vehicles_locked(
        self,
        deadline: _Deadline,
    ) -> tuple[ChinaPocVehicle, ...]:
        self._vehicles = {}
        response = await self._send_locked(
            self._build_discovery_request(self._read_clock(operation="acquire_vehicles")),
            deadline=deadline,
        )
        try:
            data = _decode_g_app_envelope(response, operation="acquire_vehicles")
            value = _property(data, "acquireVehiclesList") if isinstance(data, Mapping) else None
            if value is None:
                value = data
            vehicles = _parse_vehicles(value)
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation="acquire_vehicles") from None
        return vehicles

    def _commit_vehicles(
        self,
        vehicles: tuple[ChinaPocVehicle, ...],
    ) -> None:
        self._vehicles = {vehicle.identifier.value.casefold(): vehicle for vehicle in vehicles}

    async def get_last_status(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> ChinaPocStatus:
        """Read status for one NavInfo vehicle from the preceding discovery."""

        operation = "get_last_status"
        if type(identifier) is not VehicleIdentifier:
            raise GwmRoutePolicyError(operation=operation)
        return await self._run_operation(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_last_status_locked(identifier, deadline=deadline),
        )

    async def _get_last_status_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        deadline: _Deadline,
    ) -> ChinaPocStatus:
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation="get_last_status")
        if vehicle.platform is None or vehicle.platform.casefold() != "navinfo":
            raise GwmRoutePolicyError(operation="get_last_status")
        response = await self._send_locked(
            self._build_status_request(
                vehicle.identifier,
                self._read_clock(operation="get_last_status"),
            ),
            deadline=deadline,
        )
        try:
            body = _decode_auto_ai_envelope(response, operation="get_last_status")
            status = _parse_status(body, identifier=vehicle.identifier)
        except GwmAuthenticationError:
            self._vehicles = {}
            raise
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation="get_last_status") from None
        return status

    async def _run_operation[T](
        self,
        operation: str,
        *,
        timeout: float | None,
        action: Callable[[_Deadline], Awaitable[T]],
        commit: Callable[[T], None] | None = None,
    ) -> T:
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        expires_at = loop.time() + total
        if not math.isfinite(expires_at):
            raise GwmConfigurationError(operation=operation)
        deadline = _Deadline(expires_at)
        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    result = await action(deadline)
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    if commit is not None:
                        commit(result)
                    return result
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None
        except GwmClientError as error:
            raise _sanitized_error(error, operation=operation) from None
        except Exception:
            raise GwmNetworkError(operation=operation) from None

    async def _send_locked(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
    ) -> _ChinaTransportResponse:
        response = await self._transport.execute(
            request,
            deadline=deadline,
            connect_timeout=self._config.timeouts.connect,
            read_timeout=self._config.timeouts.read,
        )
        if type(response) is not _ChinaTransportResponse:
            raise GwmProtocolError(operation=request.operation)
        return response

    def _build_discovery_request(self, instant: datetime) -> _ChinaTransportRequest:
        timestamp = str(_epoch_milliseconds(instant) // 1000 * 1000)
        signing_headers = {
            "Authorization": self._session.bean_tech_access_token,
            "SourceApp": "GWM",
            "SourceType": "ANDROID",
            "SourceAppVer": _SOURCE_APP_VERSION,
            "Timestamp": timestamp,
            "DeviceId": self._session.device_id,
            "AppId": "GWM-APP-ANDROID-1100018",
            "NoteId": DEFAULT_NOTE_ID,
        }
        signature = default_sign(
            "POST",
            _DISCOVERY_URL,
            _DISCOVERY_BODY.decode("ascii"),
            signing_headers,
        )
        return _ChinaTransportRequest(
            operation="acquire_vehicles",
            service="g_app",
            method="POST",
            url=_DISCOVERY_URL,
            body=_DISCOVERY_BODY,
            headers={
                "G-TOKEN": self._session.g_token,
                "Authorization": self._session.bean_tech_access_token,
                "ssoId": self._session.user_id,
                "SourceApp": "GWM",
                "SourceType": "ANDROID",
                "SourceAppVer": _SOURCE_APP_VERSION,
                "SourceAppCode": _SOURCE_APP_CODE,
                "Timestamp": timestamp,
                "DeviceId": self._session.device_id,
                "AppId": "GWM-APP-ANDROID-1100018",
                "beanId": self._session.bean_id,
                "NoteId": DEFAULT_NOTE_ID,
                "Sign": signature,
                "Accept-Encoding": "gzip",
                "User-Agent": _OFFICIAL_USER_AGENT,
                "Content-Type": "application/json; charset=UTF-8",
            },
        )

    def _build_status_request(
        self,
        identifier: VehicleIdentifier,
        instant: datetime,
    ) -> _ChinaTransportRequest:
        timestamp = str(_epoch_milliseconds(instant))
        wrapper = {
            "body": {"vin": identifier.value},
            "header": {
                "brandType": "gwm",
                "cVer": _SOURCE_APP_VERSION,
                "fn": "GW.M.GET_VEHICLE_STATE",
                "fv": "0202",
                "mobileId": self._session.device_id,
                "osType": "Android",
                "osVer": "",
                "rs": "2",
                "ts": format_china_timestamp(instant),
                "tk": self._session.auto_ai_token_id,
                "v": "1.0",
            },
        }
        payload = encode_dotnet_json(wrapper)
        url = _AUTO_AI_URL + "?p=" + quote(payload, safe="", encoding="utf-8", errors="strict")
        return _ChinaTransportRequest(
            operation="get_last_status",
            service="auto_ai",
            method="GET",
            url=url,
            body=None,
            headers={
                "v": "1.0",
                "cid": self._session.device_id,
                "client": "phone",
                "sign": auto_ai_sign(timestamp),
                "time": timestamp,
                "ckey": AUTO_AI_CKEY,
                "protocolVer": "2.1.2",
                "token": self._session.auto_ai_token_id,
                "brandType": "GWM",
                "Accept-Encoding": "gzip",
                "User-Agent": _OFFICIAL_USER_AGENT,
            },
        )

    def _read_clock(self, *, operation: str) -> datetime:
        try:
            instant = self._clock()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
            raise GwmConfigurationError(operation=operation)
        if _epoch_milliseconds(instant) < 0:
            raise GwmConfigurationError(operation=operation)
        return instant

    def _validated_timeout(self, timeout: float | None, *, operation: str) -> float:
        value = self._config.timeouts.total if timeout is None else timeout
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
            or value <= 0
            or value > self._config.timeouts.total
            or value > _MAX_OPERATION_TIMEOUT
        ):
            raise GwmConfigurationError(operation=operation)
        return float(value)


def normalize_china_device_id(value: str) -> str:
    """Apply the add-on's hyphen removal, truncation, and zero-padding rule."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_DEVICE_SOURCE_LENGTH
        or _DEVICE_SOURCE.fullmatch(value) is None
    ):
        raise ValueError("china_device_id_invalid")
    normalized = value.replace("-", "")
    if not normalized:
        raise ValueError("china_device_id_invalid")
    return normalized[:32].ljust(32, "0")


def _valid_session_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_SECRET_LENGTH
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _epoch_milliseconds(instant: datetime) -> int:
    utc = instant.astimezone(UTC)
    delta = utc - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 24 * 60 * 60) + delta.seconds) * 1000 + delta.microseconds // 1000


def _decode_g_app_envelope(response: _ChinaTransportResponse, *, operation: str) -> object:
    root = _decode_json_response(response, operation=operation)
    code = _scalar_text(_property(root, "code"))
    if code is not None and code not in {"0", "000000", "200"}:
        raise GwmApiError(operation=operation, api_code=code)
    data = _property(root, "data")
    if data is None:
        data = root
    if isinstance(data, str) and data.startswith("G_A("):
        try:
            decrypted = decrypt_g_app(data)
            data = _decode_json_bytes(decrypted.encode("utf-8"))
        except (RecursionError, OverflowError, UnicodeError, ValueError):
            raise GwmSchemaError(operation=operation) from None
    return data


def _decode_auto_ai_envelope(response: _ChinaTransportResponse, *, operation: str) -> object:
    root = _decode_json_response(response, operation=operation)
    if _property(root, "header") is None and _property(root, "data") is not None:
        synthetic = _ChinaTransportResponse(response.status, response.headers, response.body)
        unwrapped = _decode_g_app_envelope(synthetic, operation=operation)
        if not isinstance(unwrapped, Mapping):
            raise GwmSchemaError(operation=operation)
        root = unwrapped
    header = _property(root, "header")
    if header is not None and not isinstance(header, Mapping):
        raise GwmSchemaError(operation=operation)
    code = _scalar_text(_property(header, "c")) if header is not None else None
    if code is not None and code != "0":
        raise GwmApiError(operation=operation, api_code=code)
    body = _property(root, "body")
    return root if body is None else body


def _decode_json_response(response: _ChinaTransportResponse, *, operation: str) -> Mapping[str, object]:
    if response.status in {401, 403}:
        raise GwmAuthenticationError(operation=operation)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry_seconds = (
            int(retry_after)
            if retry_after and len(retry_after) <= 10 and retry_after.isdecimal()
            else None
        )
        raise GwmRateLimitError(operation=operation, retry_after_seconds=retry_seconds)
    if not 200 <= response.status <= 299:
        raise GwmHttpError(operation=operation, status=response.status)
    try:
        value = _decode_json_bytes(response.body)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        ValueError,
    ):
        raise GwmSchemaError(operation=operation) from None
    if not isinstance(value, Mapping):
        raise GwmSchemaError(operation=operation)
    return value


def _decode_json_bytes(value: bytes) -> object:
    result = json.loads(
        value.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_json_constant,
    )
    _validate_json_depth(result)
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    normalized: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in normalized:
            raise ValueError("duplicate_json_key")
        normalized.add(folded)
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("invalid_json_number")


def _validate_json_depth(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("json_too_deep")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("invalid_json_number")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth=depth + 1)


def _property(value: object, name: str) -> object:
    if not isinstance(value, Mapping):
        return None
    for key, child in value.items():
        if isinstance(key, str) and key.casefold() == name.casefold():
            return child
    return None


def _scalar_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return format(value, "g")
    raise ValueError("scalar_invalid")


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    result = _scalar_text(value)
    if result is None or not result or len(result) > 512:
        raise ValueError("vehicle_schema_invalid")
    return result


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        digits = value[1:] if value[:1] in {"+", "-"} else value
        if not digits or not digits.isdecimal():
            raise ValueError("vehicle_schema_invalid")
        value = int(value)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not -(1 << 31) <= value < 1 << 31
    ):
        raise ValueError("vehicle_schema_invalid")
    return value


def _parse_vehicles(value: object) -> tuple[ChinaPocVehicle, ...]:
    if not isinstance(value, list):
        raise ValueError("vehicle_schema_invalid")
    vehicles: list[ChinaPocVehicle] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("vehicle_schema_invalid")
        vin = _property(item, "vin")
        if vin is None or vin == "":
            continue
        if not isinstance(vin, str) or _VIN.fullmatch(vin) is None:
            raise ValueError("vehicle_schema_invalid")
        folded = vin.casefold()
        if folded in seen:
            raise ValueError("vehicle_schema_invalid")
        seen.add(folded)
        vehicles.append(
            ChinaPocVehicle(
                identifier=VehicleIdentifier(vin),
                platform=_optional_text(_property(item, "belongPlatform")),
                vehicle_id=_optional_text(_property(item, "vehicleId")),
                network_type=_optional_integer(_property(item, "vehicleNetworkType")),
                series_name=_optional_text(_property(item, "appShowSeriesName")),
                brand_name=_optional_text(_property(item, "brandName")),
                vehicle_type=_optional_text(_property(item, "vtype")),
            )
        )
    return tuple(vehicles)


def _parse_status(value: object, *, identifier: VehicleIdentifier) -> ChinaPocStatus:
    if not isinstance(value, Mapping):
        raise ValueError("status_schema_invalid")
    status = _property(value, "vehicleSts")
    if status is None:
        status = value
    if not isinstance(status, Mapping):
        raise ValueError("status_schema_invalid")
    if all(_property(status, name) is None for name in ("lastUpdate", "carStatus", "battSts")):
        raise ValueError("status_schema_invalid")
    last_update = _optional_timestamp(_property(status, "lastUpdate"))
    section_count = sum(isinstance(child, Mapping) for child in status.values())
    signal_count = _count_scalar_leaves(status)
    return ChinaPocStatus(
        identifier=identifier,
        last_update_ms=last_update,
        section_count=section_count,
        signal_count=signal_count,
    )


def _optional_timestamp(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        if not value or not value.isdecimal():
            raise ValueError("status_schema_invalid")
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 63:
        raise ValueError("status_schema_invalid")
    return value


def _count_scalar_leaves(value: Mapping[object, object]) -> int:
    total = 0
    for child in value.values():
        if isinstance(child, Mapping):
            total += _count_scalar_leaves(child)
        elif isinstance(child, list):
            total += sum(1 for item in child if not isinstance(item, Mapping | list))
        else:
            total += 1
    return total


def _sanitized_error(error: GwmClientError, *, operation: str) -> GwmClientError:
    error_type = type(error)
    if error_type is GwmHttpError:
        return GwmHttpError(operation=operation, status=cast(GwmHttpError, error).status)
    if error_type is GwmRateLimitError:
        rate = cast(GwmRateLimitError, error)
        return GwmRateLimitError(
            operation=operation,
            api_code=rate.api_code,
            retry_after_seconds=rate.retry_after_seconds,
        )
    if error_type is GwmApiError:
        return GwmApiError(operation=operation, api_code=cast(GwmApiError, error).api_code)
    if error_type is GwmAuthenticationError:
        return GwmAuthenticationError(
            operation=operation,
            api_code=cast(GwmAuthenticationError, error).api_code,
        )
    if error_type is GwmClosedError:
        return GwmClosedError(operation=operation)
    if error_type is GwmConfigurationError:
        return GwmConfigurationError(operation=operation)
    if error_type is GwmDeadlineExceededError:
        return GwmDeadlineExceededError(operation=operation)
    if error_type is GwmNetworkError:
        return GwmNetworkError(operation=operation)
    if error_type is GwmProtocolError:
        return GwmProtocolError(operation=operation)
    if error_type is GwmRedirectError:
        return GwmRedirectError(operation=operation)
    if error_type is GwmResponseTooLargeError:
        return GwmResponseTooLargeError(operation=operation)
    if error_type is GwmRoutePolicyError:
        return GwmRoutePolicyError(operation=operation)
    if error_type is GwmSchemaError:
        return GwmSchemaError(operation=operation)
    if error_type is GwmTlsError:
        return GwmTlsError(operation=operation)
    return GwmNetworkError(operation=operation)


__all__ = [
    "ChinaPocClient",
    "ChinaPocConfig",
    "ChinaPocStatus",
    "ChinaPocVehicle",
    "ChinaReusedSession",
    "normalize_china_device_id",
]
