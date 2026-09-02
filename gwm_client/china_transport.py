"""Isolated bounded transport for the mainland-China protocol.

The overseas client intentionally rejects compressed responses and has a
different route/header contract.  This module keeps China's authentication,
gzip, and fixed-port requirements behind a separate closed wire boundary.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import ssl
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal, Protocol, Self
from urllib.parse import quote, unquote_to_bytes, urlsplit

import aiohttp
from yarl import URL

from ._dotnet_json import encode_dotnet_json
from ._protocol import _Deadline
from .china_crypto import (
    AUTO_AI_CKEY,
    BEAN_TECH_APP_KEY,
    DEFAULT_NOTE_ID,
    ChinaCryptoError,
    auto_ai_sign,
    bean_tech_sign,
    decrypt_g_app,
    default_sign,
    format_china_timestamp,
)
from .errors import (
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmTlsError,
)

type _ChinaService = Literal["g_app", "bean_tech", "auto_ai"]
type _ChinaOperation = Literal[
    "request_verification",
    "login",
    "refresh_token",
    "initialize_bean_tech",
    "initialize_auto_ai",
    "acquire_vehicles",
    "get_last_status",
    "get_charging_plan",
    "set_charging_plan",
    "send_climate_command",
    "save_climate_config",
    "send_lock_command",
    "send_close_windows_command",
    "send_vehicle_control_command",
    "get_remote_command_result",
    "get_remote_command_records",
    "generate_security_token",
    "get_bean_tech_charge_setting",
    "set_bean_tech_charging_mode",
    "get_bean_tech_battery_heating_appointment",
    "set_bean_tech_battery_heating_appointment",
    "set_bean_tech_charge_soc",
    "set_bean_tech_cabin_clean_appointment",
    "set_bean_tech_ac_temperature",
    "set_bean_tech_charge_window",
]

_G_APP_ORIGIN = "https://gapp-api.gwmapp-h.com"
_SMS_REQUEST_URL = _G_APP_ORIGIN + "/api-guser/v5/user/login-sms/send"
_SMS_LOGIN_URL = _G_APP_ORIGIN + "/api-guser/v5/user/sms-login"
_REFRESH_URL = _G_APP_ORIGIN + "/api-guser/v5/token/refresh"
_BEAN_TECH_LOGIN_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v1.0/userAuth/loginSSOAccount"
)
_BEAN_TECH_STATUS_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v2.0/vehicle/getLastStatus"
)
_BEAN_TECH_STATUS_PATH = "/app-api/api/v2.0/vehicle/getLastStatus"
_NAVINFO_RESULT_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/result"
)
_NAVINFO_RESULT_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/result"
_NAVINFO_CLIMATE_CONFIG_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/config"
)
_NAVINFO_CLIMATE_CONFIG_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/config"
_BEAN_TECH_SEND_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v1.0/vehicle/T5/sendCmd"
)
_BEAN_TECH_SEND_PATH = "/app-api/api/v1.0/vehicle/T5/sendCmd"
_BEAN_TECH_TIMELY_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/timely"
)
_BEAN_TECH_TIMELY_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/timely"
_BEAN_TECH_RESULT_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
)
_BEAN_TECH_RESULT_PATH = "/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
_BEAN_TECH_SECURITY_TOKEN_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/security/generate-token"
)
_BEAN_TECH_SECURITY_TOKEN_PATH = "/app-api/api/v3.0/vehicle/security/generate-token"
_BEAN_TECH_RECORDS_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/records/query"
)
_BEAN_TECH_RECORDS_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/records/query"
_BEAN_TECH_CHARGE_SETTING_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/charge/setting"
)
_BEAN_TECH_CHARGE_SETTING_PATH = "/app-api/api/v3.0/vehicle/charge/setting"
_BEAN_TECH_CONFIG_QUERY_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/config/query"
)
_BEAN_TECH_CONFIG_QUERY_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/config/query"
_BEAN_TECH_SUBSCRIBE_URL = (
    "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/subscribe"
)
_BEAN_TECH_SUBSCRIBE_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/subscribe"
_AUTO_AI_LOGIN_ORIGIN = _G_APP_ORIGIN
_AUTO_AI_LOGIN_PATH = "/tsp/v1/proxy/navinfo/GW.M.APP_LOGIN"
_DISCOVERY_URL = (
    "https://gapp-api.gwmapp-h.com/gcar/v1/app/android/vehicle/query-vehicle-list"
)
_AUTO_AI_ORIGIN = "https://ti.gwm.com.cn:8443"
_AUTO_AI_PATH = "/tsp/ead"
_DISCOVERY_BODY = b'{"vehicleVersion":13}'
_OFFICIAL_USER_AGENT = "okhttp/4.2.2"
_READ_CHUNK_BYTES = 64 * 1024
_MAX_DECIMAL_HEADER_LENGTH = 20
_MAX_ALLOWED_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_STATUS_URL_LENGTH = 256 * 1024
_MAX_STATUS_PAYLOAD_LENGTH = 64 * 1024
_MAX_REQUEST_BODY_LENGTH = 256 * 1024
_MAX_WIRE_JSON_DEPTH = 16
_SAFE_RESPONSE_HEADERS = frozenset({"content-type", "retry-after"})
_SKIP_AUTO_HEADERS = frozenset({"Accept", "Accept-Encoding", "User-Agent"})
_HEADER_NAME = re.compile(r"[-!#$%&'*+.^_`|~0-9A-Za-z]+")
_DEVICE_ID = re.compile(r"[0-9A-Fa-f]{32}")
_VIN = re.compile(r"[A-HJ-NPR-Z0-9]{17}", re.IGNORECASE)
_G_APP_ENVELOPE = re.compile(r"G_A\([A-Za-z0-9+/]+={0,2},1\)")
_LOWER_HEX_16 = re.compile(r"[0-9a-f]{16}")
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{32}")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
_BEAN_TECH_SEQUENCE = re.compile(r"[0-9a-f]{32}[0-9]{4}")
_BASE64_SHA1 = re.compile(r"[A-Za-z0-9+/]{27}=")
_CLOCK_TIME = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")
_WEEKLY_REPEAT = re.compile(r"[01]{7}")
_G_APP_BASE_HEADERS = frozenset(
    {
        "Authorization",
        "SourceApp",
        "SourceType",
        "SourceAppVer",
        "SourceAppCode",
        "Timestamp",
        "DeviceId",
        "AppId",
        "NoteId",
        "Sign",
        "Accept-Encoding",
        "User-Agent",
        "Content-Type",
    }
)
_G_APP_REFRESH_REQUIRED_HEADERS = frozenset({"G-TOKEN", "ssoId"})
_G_APP_REFRESH_OPTIONAL_HEADERS = frozenset({"beanId"})
_BEAN_TECH_LOGIN_HEADERS = frozenset(
    {
        "bt-auth-appkey",
        "bt-auth-nonce",
        "bt-auth-timestamp",
        "bt-auth-sign",
        "rs",
        "appId",
        "brand",
        "terminal",
        "enterPriseId",
        "cVer",
        "tenantId",
        "operatorRole",
        "Accept-Encoding",
        "User-Agent",
        "Content-Type",
    }
)
_BEAN_TECH_LOGIN_OPTIONAL_HEADERS = frozenset({"beanId"})
_AUTO_AI_LOGIN_HEADERS = frozenset(
    {
        "v",
        "cid",
        "client",
        "sign",
        "time",
        "ckey",
        "protocolVer",
        "brandType",
        "Accept-Encoding",
        "User-Agent",
    }
)
_DISCOVERY_HEADERS = frozenset(
    {
        "G-TOKEN",
        "Authorization",
        "ssoId",
        "SourceApp",
        "SourceType",
        "SourceAppVer",
        "SourceAppCode",
        "Timestamp",
        "DeviceId",
        "AppId",
        "beanId",
        "NoteId",
        "Sign",
        "Accept-Encoding",
        "User-Agent",
        "Content-Type",
    }
)
_STATUS_HEADERS = frozenset(
    {
        "v",
        "cid",
        "client",
        "sign",
        "time",
        "ckey",
        "protocolVer",
        "token",
        "brandType",
        "Accept-Encoding",
        "User-Agent",
    }
)
_BEAN_TECH_STATUS_HEADERS = frozenset(
    {
        "bt-auth-appkey",
        "bt-auth-nonce",
        "bt-auth-timestamp",
        "bt-auth-sign",
        "rs",
        "appId",
        "brand",
        "terminal",
        "enterPriseId",
        "accessToken",
        "beanId",
        "cVer",
        "vin",
        "tenantId",
        "operatorRole",
        "tokenId",
        "Accept-Encoding",
        "User-Agent",
    }
)
_BEAN_TECH_COMMAND_HEADERS = _BEAN_TECH_STATUS_HEADERS | frozenset({"Content-Type"})
_BEAN_TECH_TIMELY_TOKEN_HEADERS = _BEAN_TECH_COMMAND_HEADERS | frozenset({"securityToken"})


@dataclass(frozen=True, slots=True)
class ChinaTransportCapabilities:
    """Non-secret evidence about the deliberately selected China adapter."""

    protocol_service_aliases: tuple[str, ...] = ("g_app", "bean_tech", "auto_ai")
    enabled_read_service_aliases: tuple[str, ...] = ("g_app", "bean_tech", "auto_ai")
    enabled_auth_service_aliases: tuple[str, ...] = ("g_app", "bean_tech", "auto_ai")
    bean_tech_http_deferred: bool = False
    bounded_gzip: bool = True
    http2_preferred_by_app: bool = True
    http2_available_in_adapter: bool = False
    live_http_version_validation_required: bool = True


@dataclass(frozen=True, slots=True)
class _ChinaTransportRequest:
    operation: _ChinaOperation
    service: _ChinaService
    method: Literal["GET", "POST"]
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        copied = _validated_headers(self.headers)
        if self.operation in {"request_verification", "login", "refresh_token"}:
            _validate_g_app_auth_request(self, copied)
        elif self.operation == "initialize_bean_tech":
            _validate_bean_tech_login_request(self, copied)
        elif self.operation == "initialize_auto_ai":
            _validate_auto_ai_login_request(self, copied)
        elif self.operation == "acquire_vehicles":
            _validate_discovery_request(self, copied)
        elif self.operation in {"get_last_status", "get_charging_plan"}:
            _validate_status_request(self, copied)
        elif self.operation == "set_charging_plan":
            _validate_charging_plan_request(self, copied)
        elif self.operation == "send_climate_command":
            _validate_climate_command_request(self, copied)
        elif self.operation == "save_climate_config":
            _validate_navinfo_climate_config_request(self, copied)
        elif self.operation == "send_lock_command":
            _validate_lock_window_command_request(self, copied, command_kind="lock")
        elif self.operation == "send_close_windows_command":
            _validate_lock_window_command_request(self, copied, command_kind="windows")
        elif self.operation == "send_vehicle_control_command":
            _validate_vehicle_control_command_request(self, copied)
        elif self.operation == "get_remote_command_result":
            _validate_remote_command_result_request(self, copied)
        elif self.operation == "get_remote_command_records":
            _validate_bean_tech_records_request(self, copied)
        elif self.operation == "generate_security_token":
            _validate_bean_tech_security_token_request(self, copied)
        elif self.operation == "get_bean_tech_charge_setting":
            _validate_bean_tech_charge_setting_request(self, copied)
        elif self.operation == "set_bean_tech_charging_mode":
            _validate_bean_tech_charge_setting_write_request(self, copied)
        elif self.operation == "get_bean_tech_battery_heating_appointment":
            _validate_bean_tech_config_query_request(self, copied)
        elif self.operation == "set_bean_tech_battery_heating_appointment":
            _validate_bean_tech_battery_heating_appointment_request(self, copied)
        elif self.operation == "set_bean_tech_charge_soc":
            _validate_bean_tech_charge_soc_request(self, copied)
        elif self.operation == "set_bean_tech_cabin_clean_appointment":
            _validate_bean_tech_subscribe_request(self, copied)
        elif self.operation == "set_bean_tech_ac_temperature":
            _validate_bean_tech_config_request(self, copied)
        elif self.operation == "set_bean_tech_charge_window":
            _validate_bean_tech_charge_setting_write_request(self, copied)
        else:  # pragma: no cover - the Literal is still a runtime boundary
            raise ValueError("operation_invalid")
        object.__setattr__(self, "headers", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class _ChinaTransportResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("http_status_invalid")
        if not isinstance(self.body, bytes):
            raise ValueError("response_body_invalid")
        object.__setattr__(
            self,
            "headers",
            MappingProxyType(
                {
                    str(name).lower(): str(value)
                    for name, value in self.headers.items()
                    if str(name).lower() in _SAFE_RESPONSE_HEADERS
                }
            ),
        )


class _ChinaAsyncTransport(Protocol):
    async def execute(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _ChinaTransportResponse: ...

    async def aclose(self) -> None: ...


class ChinaAiohttpTransport:
    """Execute the allowed China authentication and reads without ambient HTTP state."""

    capabilities = ChinaTransportCapabilities()

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        owns_session: bool = False,
        max_compressed_bytes: int = 4 * 1024 * 1024,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        _validate_response_limit(max_compressed_bytes)
        _validate_response_limit(max_response_bytes)
        if type(owns_session) is not bool:
            raise ValueError("session_ownership_invalid")
        self._session = session
        self._owns_session = owns_session
        self._max_compressed_bytes = max_compressed_bytes
        self._max_response_bytes = max_response_bytes
        self._ssl_context: ssl.SSLContext | None = None
        self._closed = False
        self._closing = False
        self._close_lock = asyncio.Lock()
        self._ssl_context_lock = asyncio.Lock()

    @classmethod
    def create_owned(
        cls,
        *,
        max_compressed_bytes: int = 4 * 1024 * 1024,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> Self:
        """Create a dedicated HTTP/1.1 adapter inside the active event loop."""

        _validate_response_limit(max_compressed_bytes)
        _validate_response_limit(max_response_bytes)
        if cls is not ChinaAiohttpTransport:
            raise TypeError("transport_subclass_not_supported")
        session = aiohttp.ClientSession(
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            middlewares=(),
            raise_for_status=False,
            skip_auto_headers=_SKIP_AUTO_HEADERS,
            trace_configs=[],
            trust_env=False,
        )
        session._retry_connection = False
        return cls(
            session,
            owns_session=True,
            max_compressed_bytes=max_compressed_bytes,
            max_response_bytes=max_response_bytes,
        )

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
                if self._owns_session and not self._session.closed:
                    await self._session.close()
            except BaseException:
                self._closing = False
                raise
            self._closed = True
            self._closing = False

    async def execute(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _ChinaTransportResponse:
        """Send one validated China request and decode at most one gzip stream."""

        if type(request) is not _ChinaTransportRequest:
            raise GwmRoutePolicyError()
        operation = request.operation
        if type(deadline) is not _Deadline or not all(
            _valid_phase_timeout(value) for value in (connect_timeout, read_timeout)
        ):
            raise GwmConfigurationError(operation=operation)
        if self._closed or self._closing or self._session.closed:
            raise GwmClosedError(operation=operation)
        self._validate_session_policy(operation=operation)
        ssl_context = await self._async_ssl_context(operation=operation)
        _validate_tls_context(ssl_context)

        loop = asyncio.get_running_loop()
        remaining = deadline.remaining(loop.time())
        if remaining <= 0:
            raise GwmDeadlineExceededError(operation=operation)
        timeout = aiohttp.ClientTimeout(
            total=remaining,
            connect=min(connect_timeout, remaining),
            sock_read=min(read_timeout, remaining),
        )

        failure: GwmClientError | None = None
        try:
            async with self._session.request(
                request.method,
                URL(request.url, encoded=True),
                allow_redirects=False,
                auto_decompress=False,
                auth=None,
                cookies={},
                data=request.body,
                headers=request.headers,
                middlewares=(),
                params=None,
                proxy=None,
                proxy_auth=None,
                raise_for_status=False,
                skip_auto_headers=_SKIP_AUTO_HEADERS,
                ssl=ssl_context,
                timeout=timeout,
            ) as response:
                return await self._read_response(response, operation=operation)
        except asyncio.CancelledError:
            raise
        except GwmClientError:
            raise
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            aiohttp.ClientSSLError,
            aiohttp.ServerFingerprintMismatch,
            ssl.CertificateError,
            ssl.SSLError,
        ):
            failure = GwmTlsError(operation=operation)
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, OSError):
            failure = GwmNetworkError(operation=operation)
        except aiohttp.ClientError:
            failure = GwmNetworkError(operation=operation)
        if failure is not None:
            raise failure
        raise GwmNetworkError(operation=operation)

    async def _async_ssl_context(self, *, operation: str) -> ssl.SSLContext:
        """Load system trust off the event loop before the first request."""

        if self._ssl_context is not None:
            return self._ssl_context
        async with self._ssl_context_lock:
            if self._ssl_context is not None:
                return self._ssl_context
            try:
                context = await asyncio.to_thread(_create_ssl_context)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise GwmTlsError(operation=operation) from None
            if not isinstance(context, ssl.SSLContext):
                raise GwmTlsError(operation=operation)
            self._ssl_context = context
            return context

    async def _read_response(
        self,
        response: aiohttp.ClientResponse,
        *,
        operation: str,
    ) -> _ChinaTransportResponse:
        if 300 <= response.status <= 399:
            raise GwmRedirectError(operation=operation)

        encoding_value = _single_response_header(
            response.headers,
            "Content-Encoding",
            operation=operation,
        )
        encoding = (encoding_value or "").strip().lower()
        if encoding not in {"", "identity", "gzip"}:
            raise GwmProtocolError(operation=operation)
        wire_limit = (
            self._max_compressed_bytes
            if encoding == "gzip"
            else self._max_response_bytes
        )
        content_length = _validated_content_length(
            _single_response_header(
                response.headers,
                "Content-Length",
                operation=operation,
            ),
            operation=operation,
        )
        if content_length is not None and content_length > wire_limit:
            raise GwmResponseTooLargeError(operation=operation)

        if encoding == "gzip":
            body, wire_count = await self._read_gzip(response, operation=operation)
        else:
            body, wire_count = await self._read_identity(response, operation=operation)
        if content_length is not None and content_length != wire_count:
            raise GwmProtocolError(operation=operation)
        return _ChinaTransportResponse(
            status=response.status,
            headers=_selected_headers(response.headers, operation=operation),
            body=body,
        )

    async def _read_identity(
        self,
        response: aiohttp.ClientResponse,
        *,
        operation: str,
    ) -> tuple[bytes, int]:
        body = bytearray()
        async for chunk in response.content.iter_chunked(_READ_CHUNK_BYTES):
            data = _validated_chunk(chunk, operation=operation)
            if len(body) + len(data) > self._max_response_bytes:
                raise GwmResponseTooLargeError(operation=operation)
            body.extend(data)
        return bytes(body), len(body)

    async def _read_gzip(
        self,
        response: aiohttp.ClientResponse,
        *,
        operation: str,
    ) -> tuple[bytes, int]:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        compressed_count = 0
        body = bytearray()
        try:
            async for chunk in response.content.iter_chunked(_READ_CHUNK_BYTES):
                data = _validated_chunk(chunk, operation=operation)
                compressed_count += len(data)
                if compressed_count > self._max_compressed_bytes:
                    raise GwmResponseTooLargeError(operation=operation)
                if inflater.eof and data:
                    raise GwmProtocolError(operation=operation)
                remaining = self._max_response_bytes - len(body)
                inflated = inflater.decompress(data, remaining + 1)
                if len(inflated) > remaining or inflater.unconsumed_tail:
                    raise GwmResponseTooLargeError(operation=operation)
                body.extend(inflated)
                if inflater.unused_data:
                    raise GwmProtocolError(operation=operation)
            remaining = self._max_response_bytes - len(body)
            tail = inflater.flush(remaining + 1)
        except zlib.error:
            raise GwmProtocolError(operation=operation) from None
        if len(tail) > remaining:
            raise GwmResponseTooLargeError(operation=operation)
        body.extend(tail)
        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise GwmProtocolError(operation=operation)
        return bytes(body), compressed_count

    def _validate_session_policy(self, *, operation: str) -> None:
        if isinstance(self._session, aiohttp.ClientSession) and (
            type(self._session) is not aiohttp.ClientSession
            or type(self._session.connector) is not aiohttp.TCPConnector
        ):
            raise GwmConfigurationError(operation=operation)
        if self._session.trust_env:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "auto_decompress", None) is not False:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_auth", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_proxy", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_proxy_auth", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if self._session.headers:
            raise GwmConfigurationError(operation=operation)
        if not isinstance(self._session.cookie_jar, aiohttp.DummyCookieJar):
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_raise_for_status", None) is not False:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_retry_connection", None) is not False:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_middlewares", None) != ():
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_trace_configs", None) not in ([], ()):
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_request_class", None) is not aiohttp.ClientRequest:
            raise GwmConfigurationError(operation=operation)
        if (
            getattr(self._session, "_response_class", None)
            is not aiohttp.ClientResponse
        ):
            raise GwmConfigurationError(operation=operation)
        skip_auto_headers = getattr(self._session, "skip_auto_headers", None)
        if skip_auto_headers is None or {
            str(name).lower() for name in skip_auto_headers
        } != {name.lower() for name in _SKIP_AUTO_HEADERS}:
            raise GwmConfigurationError(operation=operation)


def _validated_headers(headers: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise ValueError("header_invalid")
    copied: dict[str, str] = {}
    normalized: set[str] = set()
    for name, value in headers.items():
        lower = name.lower() if isinstance(name, str) else ""
        if (
            not isinstance(name, str)
            or _HEADER_NAME.fullmatch(name) is None
            or lower in normalized
            or not isinstance(value, str)
            or (not value and name != "Authorization")
            or len(value) > 16 * 1024
            or any(
                ord(character) < 0x20 or ord(character) > 0x7E for character in value
            )
        ):
            raise ValueError("header_invalid")
        normalized.add(lower)
        copied[name] = value
    return copied


def _validate_g_app_auth_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    routes = {
        "request_verification": (_SMS_REQUEST_URL, _validate_sms_request_body),
        "login": (_SMS_LOGIN_URL, _validate_sms_login_body),
        "refresh_token": (_REFRESH_URL, _validate_refresh_body),
    }
    try:
        expected_url, body_validator = routes[request.operation]
    except KeyError:
        raise ValueError("route_invalid") from None

    header_names = set(headers)
    if request.operation == "refresh_token":
        required_headers = _G_APP_BASE_HEADERS | _G_APP_REFRESH_REQUIRED_HEADERS
        if (
            not header_names >= required_headers
            or not header_names <= required_headers | _G_APP_REFRESH_OPTIONAL_HEADERS
        ):
            raise ValueError("route_invalid")
        if any(
            not _safe_wire_text(headers.get(name), maximum=16 * 1024)
            for name in header_names
            & (_G_APP_REFRESH_REQUIRED_HEADERS | _G_APP_REFRESH_OPTIONAL_HEADERS)
        ):
            raise ValueError("route_invalid")
    elif header_names != _G_APP_BASE_HEADERS or headers.get("Authorization") != "":
        raise ValueError("route_invalid")

    if (
        request.service != "g_app"
        or request.method != "POST"
        or request.url != expected_url
        or not _valid_g_app_static_headers(headers)
        or not isinstance(request.body, bytes)
        or len(request.body) > _MAX_REQUEST_BODY_LENGTH
    ):
        raise ValueError("route_invalid")
    raw_body = _ascii_body(request.body)
    if raw_body is None or _G_APP_ENVELOPE.fullmatch(raw_body) is None:
        raise ValueError("route_invalid")
    logical_body = _decode_wire_object_from_g_app(raw_body)
    if logical_body is None or not body_validator(logical_body):
        raise ValueError("route_invalid")
    if request.operation == "refresh_token" and logical_body.get(
        "token"
    ) != headers.get("G-TOKEN"):
        raise ValueError("route_invalid")
    if headers.get("Sign") != default_sign("POST", request.url, raw_body, headers):
        raise ValueError("route_invalid")


def _validate_sms_request_body(body: Mapping[str, object]) -> bool:
    return (
        list(body) == ["phone", "flag"]
        and _valid_phone(body.get("phone"))
        and body.get("flag") == "LOGIN"
    )


def _validate_sms_login_body(body: Mapping[str, object]) -> bool:
    return (
        list(body) == ["code", "phone", "deviceToken"]
        and _safe_wire_text(body.get("code"), maximum=64)
        and _valid_phone(body.get("phone"))
        and body.get("deviceToken") == ""
    )


def _validate_refresh_body(body: Mapping[str, object]) -> bool:
    return (
        list(body) == ["token", "refreshToken"]
        and _safe_wire_text(body.get("token"), maximum=16 * 1024)
        and _safe_wire_text(body.get("refreshToken"), maximum=16 * 1024)
    )


def _validate_bean_tech_login_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_LOGIN_URL
        or not set(headers) >= _BEAN_TECH_LOGIN_HEADERS
        or not set(headers)
        <= _BEAN_TECH_LOGIN_HEADERS | _BEAN_TECH_LOGIN_OPTIONAL_HEADERS
        or raw_body is None
        or body is None
        or list(body) != ["appType", "deviceId", "phone", "ssoId", "ssoToken"]
        or body.get("appType") != 0
        or _DEVICE_ID.fullmatch(_string(body.get("deviceId"))) is None
        or not _valid_phone(body.get("phone"))
        or not _safe_wire_text(body.get("ssoId"), maximum=16 * 1024)
        or not _safe_wire_text(body.get("ssoToken"), maximum=16 * 1024)
        or headers.get("bt-auth-appkey") != BEAN_TECH_APP_KEY
        or _LOWER_HEX_16.fullmatch(headers.get("bt-auth-nonce", "")) is None
        or not _epoch_milliseconds(headers.get("bt-auth-timestamp", ""))
        or headers.get("rs") != "2"
        or headers.get("appId") != "097a7099af30d960"
        or headers.get("brand") != "10"
        or headers.get("terminal") != "GW_APP_GWM"
        or headers.get("enterPriseId") != "CC01"
        or (
            "beanId" in headers
            and not _safe_wire_text(headers.get("beanId"), maximum=16 * 1024)
        )
        or headers.get("cVer") != "2.1.5"
        or headers.get("tenantId") != "1"
        or headers.get("operatorRole") != "0"
        or headers.get("Accept-Encoding") != "gzip"
        or headers.get("User-Agent") != _OFFICIAL_USER_AGENT
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or encode_dotnet_json(body) != raw_body
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            "/app-api/api/v1.0/userAuth/loginSSOAccount",
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_auto_ai_login_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    if (
        request.service != "auto_ai"
        or request.method != "GET"
        or request.body is not None
        or set(headers) != _AUTO_AI_LOGIN_HEADERS
        or not _valid_auto_ai_headers(headers, token_required=False)
        or not _valid_auto_ai_url(
            request.url,
            headers,
            origin=_AUTO_AI_LOGIN_ORIGIN,
            path=_AUTO_AI_LOGIN_PATH,
            function="GW.M.APP_LOGIN",
            body_validator=_valid_auto_ai_login_body,
            token_required=False,
        )
    ):
        raise ValueError("route_invalid")


def _valid_auto_ai_login_body(body: Mapping[str, object]) -> bool:
    return (
        list(body) == ["appType", "phone", "pushId", "pushKey", "ssoid", "ssoTk"]
        and body.get("appType") == 0
        and _valid_phone(body.get("phone"))
        and body.get("pushId") == "0"
        and body.get("pushKey") == "0"
        and _safe_wire_text(body.get("ssoid"), maximum=16 * 1024)
        and _safe_wire_text(body.get("ssoTk"), maximum=16 * 1024)
    )


def _valid_g_app_static_headers(headers: Mapping[str, str]) -> bool:
    return (
        headers.get("SourceApp") == "GWM"
        and headers.get("SourceType") == "ANDROID"
        and headers.get("SourceAppVer") == "2.1.5"
        and headers.get("SourceAppCode") == "2150"
        and headers.get("AppId") == "GWM-APP-ANDROID-1100018"
        and headers.get("NoteId") == DEFAULT_NOTE_ID
        and headers.get("Accept-Encoding") == "gzip"
        and headers.get("User-Agent") == _OFFICIAL_USER_AGENT
        and headers.get("Content-Type") == "application/json; charset=UTF-8"
        and _DEVICE_ID.fullmatch(headers.get("DeviceId", "")) is not None
        and _LOWER_HEX_64.fullmatch(headers.get("Sign", "")) is not None
        and _second_aligned_epoch(headers.get("Timestamp", ""))
    )


def _ascii_body(body: bytes) -> str | None:
    try:
        return body.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None


def _utf8_body(body: object) -> str | None:
    if not isinstance(body, bytes) or not body or len(body) > _MAX_REQUEST_BODY_LENGTH:
        return None
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _decode_wire_object_from_g_app(raw_body: str) -> Mapping[str, object] | None:
    try:
        plaintext = decrypt_g_app(raw_body)
    except (ChinaCryptoError, TypeError, ValueError):
        return None
    return _decode_wire_object(plaintext)


def _decode_wire_object(raw_body: str) -> Mapping[str, object] | None:
    try:
        value = json.loads(
            raw_body,
            object_pairs_hook=_unique_wire_object,
            parse_constant=_reject_wire_constant,
        )
        _validate_wire_json_depth(value)
        if not isinstance(value, dict) or encode_dotnet_json(value) != raw_body:
            return None
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
    ):
        return None
    return value


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _valid_phone(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 64 and all(
        character.isprintable() and not character.isspace() for character in value
    )


def _validate_discovery_request(
    request: _ChinaTransportRequest, headers: Mapping[str, str]
) -> None:
    if (
        request.service != "g_app"
        or request.method != "POST"
        or request.url != _DISCOVERY_URL
        or request.body != _DISCOVERY_BODY
        or set(headers) != _DISCOVERY_HEADERS
        or headers.get("SourceApp") != "GWM"
        or headers.get("SourceType") != "ANDROID"
        or headers.get("SourceAppVer") != "2.1.5"
        or headers.get("SourceAppCode") != "2150"
        or headers.get("AppId") != "GWM-APP-ANDROID-1100018"
        or headers.get("NoteId") != "145765423214576567716671"
        or headers.get("Accept-Encoding") != "gzip"
        or headers.get("User-Agent") != _OFFICIAL_USER_AGENT
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or _DEVICE_ID.fullmatch(headers.get("DeviceId", "")) is None
        or not _safe_wire_text(headers.get("G-TOKEN"), maximum=16 * 1024)
        or not _safe_wire_text(headers.get("Authorization"), maximum=16 * 1024)
        or not _safe_wire_text(headers.get("ssoId"), maximum=16 * 1024)
        or not _safe_wire_text(headers.get("beanId"), maximum=16 * 1024)
        or headers.get("Sign")
        != default_sign("POST", request.url, _DISCOVERY_BODY.decode("ascii"), headers)
        or not _second_aligned_epoch(headers.get("Timestamp", ""))
    ):
        raise ValueError("route_invalid")


def _validate_status_request(
    request: _ChinaTransportRequest, headers: Mapping[str, str]
) -> None:
    if request.service == "bean_tech":
        _validate_bean_tech_status_request(request, headers)
        return
    if (
        request.service != "auto_ai"
        or request.method != "GET"
        or request.body is not None
        or set(headers) != _STATUS_HEADERS
        or not _valid_auto_ai_headers(headers, token_required=True)
        or not _valid_auto_ai_url(
            request.url,
            headers,
            origin=_AUTO_AI_ORIGIN,
            path=_AUTO_AI_PATH,
            function="GW.M.GET_VEHICLE_STATE",
            body_validator=_valid_status_body,
            token_required=True,
        )
    ):
        raise ValueError("route_invalid")


def _validate_climate_command_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    valid_route = any(
        _valid_auto_ai_url(
            request.url,
            headers,
            origin=_AUTO_AI_ORIGIN,
            path=_AUTO_AI_PATH,
            function=function,
            body_validator=_climate_body_validator(variant),
            token_required=True,
        )
        for function, variant in (
            ("GW.M.SEND_COMMON_COMMAND", "off"),
            ("GW.M.SET_AND_OPEN_COMMAND", "start"),
        )
    )
    valid_auto_ai = (
        request.service == "auto_ai"
        and request.method == "GET"
        and request.body is None
        and set(headers) == _STATUS_HEADERS
        and _valid_auto_ai_headers(headers, token_required=True)
        and valid_route
    )
    valid_bean_tech = _valid_bean_tech_command_request(
        request,
        headers,
        command_kind="climate",
    )
    if not valid_auto_ai and not valid_bean_tech:
        raise ValueError("route_invalid")


def _validate_navinfo_climate_config_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    configs = body.get("configs") if isinstance(body, Mapping) else None
    command_body = configs.get("cmdBody") if isinstance(configs, Mapping) else None
    operation_time = (
        command_body.get("operationTime")
        if isinstance(command_body, Mapping)
        else None
    )
    temperature = (
        command_body.get("temperature")
        if isinstance(command_body, Mapping)
        else None
    )
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _NAVINFO_CLIMATE_CONFIG_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or list(body) != ["configs", "vin"]
        or not isinstance(configs, Mapping)
        or list(configs) != ["cmdBody", "controlType"]
        or not isinstance(command_body, Mapping)
        or list(command_body) != ["allowStartEng", "operationTime", "temperature"]
        or command_body.get("allowStartEng") != 1
        or isinstance(operation_time, bool)
        or not isinstance(operation_time, int)
        or not 300 <= operation_time <= 1800
        or operation_time % 60 != 0
        or isinstance(temperature, bool)
        or not isinstance(temperature, int)
        or not 17 <= temperature <= 31
        or configs.get("controlType") != "AIR_CONDITIONER_START"
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or encode_dotnet_json(body) != raw_body
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _NAVINFO_CLIMATE_CONFIG_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_charging_plan_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    if (
        request.service != "auto_ai"
        or request.method != "GET"
        or request.body is not None
        or set(headers) != _STATUS_HEADERS
        or not _valid_auto_ai_headers(headers, token_required=True)
        or not _valid_auto_ai_url(
            request.url,
            headers,
            origin=_AUTO_AI_ORIGIN,
            path=_AUTO_AI_PATH,
            function="GW.M.SEND_CHARGE_SETTINGS_WEEKLY",
            body_validator=_valid_charging_plan_body,
            token_required=True,
        )
    ):
        raise ValueError("route_invalid")


def _valid_charging_plan_body(body: Mapping[str, object]) -> bool:
    if (
        list(body)
        != [
            "flag",
            "signStr",
            "userId",
            "userType",
            "vin",
            "chargeingMode",
            "chargingStartTime",
            "chargingEndTime",
            "repeatTimes",
        ]
        or body.get("flag") != 1
        or _LOWER_HEX_32.fullmatch(str(body.get("signStr", ""))) is None
        or not _safe_wire_text(body.get("userId"), maximum=16 * 1024)
        or body.get("userType") != "0"
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("chargeingMode") not in {"0", "1"}
    ):
        return False
    start = body.get("chargingStartTime")
    end = body.get("chargingEndTime")
    repeat = body.get("repeatTimes")
    if body.get("chargeingMode") == "1":
        return start == "00:00" and end == "00:00" and repeat == "0000000"
    return (
        isinstance(start, str)
        and _CLOCK_TIME.fullmatch(start) is not None
        and isinstance(end, str)
        and _CLOCK_TIME.fullmatch(end) is not None
        and isinstance(repeat, str)
        and _WEEKLY_REPEAT.fullmatch(repeat) is not None
    )


def _validate_lock_window_command_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
    *,
    command_kind: Literal["lock", "windows"],
) -> None:
    expected_codes = {1, 2} if command_kind == "lock" else {3}
    valid_auto_ai = (
        request.service == "auto_ai"
        and request.method == "GET"
        and request.body is None
        and set(headers) == _STATUS_HEADERS
        and _valid_auto_ai_headers(headers, token_required=True)
        and _valid_auto_ai_url(
            request.url,
            headers,
            origin=_AUTO_AI_ORIGIN,
            path=_AUTO_AI_PATH,
            function="GW.M.SEND_COMMON_COMMAND",
            body_validator=lambda body: _valid_lock_window_body(body, expected_codes),
            token_required=True,
        )
    )
    valid_bean_tech = _valid_bean_tech_command_request(
        request,
        headers,
        command_kind=command_kind,
    )
    if not valid_auto_ai and not valid_bean_tech:
        raise ValueError("route_invalid")


def _validate_vehicle_control_command_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    variants: tuple[tuple[str, Literal["common", "engine_start", "refresh"]], ...] = (
        ("GW.M.SEND_COMMON_COMMAND", "common"),
        ("GW.M.SET_AND_OPEN_COMMAND", "engine_start"),
        ("GW.M.REFRESH_VEHICLE_STATE", "refresh"),
    )
    valid_auto_ai = (
        request.service == "auto_ai"
        and request.method == "GET"
        and request.body is None
        and set(headers) == _STATUS_HEADERS
        and _valid_auto_ai_headers(headers, token_required=True)
        and any(
            _valid_auto_ai_url(
                request.url,
                headers,
                origin=_AUTO_AI_ORIGIN,
                path=_AUTO_AI_PATH,
                function=function,
                body_validator=_vehicle_control_body_validator(variant),
                token_required=True,
            )
            for function, variant in variants
        )
    )
    valid_bean_tech = _valid_bean_tech_command_request(
        request,
        headers,
        command_kind="vehicle_control",
    )
    if not valid_auto_ai and not valid_bean_tech:
        raise ValueError("route_invalid")


def _valid_vehicle_control_body(
    body: Mapping[str, object],
    variant: Literal["common", "engine_start", "refresh"],
) -> bool:
    if variant == "refresh":
        return list(body) == ["vin"] and _VIN.fullmatch(str(body.get("vin", ""))) is not None
    common_prefix = (
        body.get("flag") == 1
        and _LOWER_HEX_32.fullmatch(str(body.get("signStr", ""))) is not None
        and _safe_wire_text(body.get("userId"), maximum=16 * 1024)
        and body.get("userType") == "0"
        and _VIN.fullmatch(str(body.get("vin", ""))) is not None
    )
    if not common_prefix:
        return False
    if variant == "engine_start":
        engine = body.get("engineParams")
        return (
            list(body)
            == [
                "flag",
                "signStr",
                "userId",
                "userType",
                "vin",
                "cmdCode",
                "engineParams",
            ]
            and body.get("cmdCode") == 15
            and isinstance(engine, Mapping)
            and list(engine) == ["runTime"]
            and isinstance(engine.get("runTime"), int)
            and not isinstance(engine.get("runTime"), bool)
            and 5 <= int(engine["runTime"]) <= 30
        )
    if body.get("cmdCode") == 29:
        return (
            list(body)
            == [
                "flag",
                "signStr",
                "userId",
                "userType",
                "vin",
                "cmdCode",
                "openAngle",
            ]
            and body.get("openAngle") in {5, 10, 11}
        )
    return (
        list(body) == ["flag", "signStr", "userId", "userType", "vin", "cmdCode"]
        and body.get("cmdCode") in {5, 16, 17, 18, 19, 20, 28, 34}
    )


def _vehicle_control_body_validator(
    variant: Literal["common", "engine_start", "refresh"],
) -> Callable[[Mapping[str, object]], bool]:
    def validate(body: Mapping[str, object]) -> bool:
        return _valid_vehicle_control_body(body, variant)

    return validate


def _valid_lock_window_body(
    body: Mapping[str, object], expected_codes: set[int]
) -> bool:
    return (
        list(body) == ["flag", "signStr", "userId", "userType", "vin", "cmdCode"]
        and body.get("flag") == 1
        and _LOWER_HEX_32.fullmatch(str(body.get("signStr", ""))) is not None
        and _safe_wire_text(body.get("userId"), maximum=16 * 1024)
        and body.get("userType") == "0"
        and _VIN.fullmatch(str(body.get("vin", ""))) is not None
        and body.get("cmdCode") in expected_codes
    )


def _valid_air_conditioner_start_body(cmd_body: object) -> bool:
    if not isinstance(cmd_body, Mapping):
        return False
    operation_time = cmd_body.get("operationTime")
    temperature = cmd_body.get("temperature")
    return (
        list(cmd_body) == ["allowStartEng", "operationTime", "temperature"]
        and cmd_body.get("allowStartEng") == 1
        and isinstance(operation_time, int)
        and not isinstance(operation_time, bool)
        and 300 <= operation_time <= 1800
        and operation_time % 60 == 0
        and isinstance(temperature, int)
        and not isinstance(temperature, bool)
        and 17 <= temperature <= 31
    )


_BEAN_TECH_VEHICLE_CONTROL_BODIES: dict[str, object] = {
    "ENGINE_STOP": None,
    "WHISTLE": None,
    "FLASH": None,
    "WHISTLE_FLASH": None,
    "SKYLIGNT_CLOSE": {"skyLight": 0},
    "SEAT_HEATING_START": (
        {"leftFront": 3, "operationTime": 600},
        {"rightFront": 3, "operationTime": 600},
    ),
    "SEAT_HEATING_STOP": (
        {"leftFront": 0, "operationMode": 1},
        {"rightFront": 0, "operationMode": 1},
    ),
    "SEAT_VENTILATION_START": (
        {"leftFront": 3, "operationTime": 600},
        {"rightFront": 3, "operationTime": 600},
    ),
    "SEAT_VENTILATION_STOP": (
        {"leftFront": 0, "operationMode": 2},
        {"rightFront": 0, "operationMode": 2},
    ),
    "STEERING_WHEEL_HEATING": {"operationTime": 600},
    "STEERING_WHEEL_HEATLESS": None,
    "DEFROST_FRONT_START": {"operationTime": 900},
    "DEFROST_FRONT_STOP": None,
    "DEFROST_BACK_START": {"operationTime": 900},
    "DEFROST_BACK_STOP": None,
    "CABIN_CLEANING_START": {"operationTime": 60},
    "BATTERY_GUN_HEAT_START": None,
    "BATTERY_GUN_HEAT_STOP": None,
    "BATTERY_INITIATIVE_HEAT_START": None,
    "BATTERY_INITIATIVE_HEAT_STOP": None,
}

_BEAN_TECH_COMFORT_MODE_BODIES: tuple[dict[str, object], ...] = (
    {"action": 1, "modeId": "4982234", "type": "1"},
    {"action": 1, "modeId": "4982235", "type": "2"},
)


def _bean_tech_vehicle_control_expects_body(control_type: str) -> bool:
    """Return whether ``control_type`` carries a non-null ``cmdBody``."""
    expected = _BEAN_TECH_VEHICLE_CONTROL_BODIES[control_type]
    return any(isinstance(body, Mapping) for body in expected) if isinstance(
        expected, tuple
    ) else expected is not None


def _bean_tech_vehicle_control_body_matches(
    control_type: str, cmd_body: object
) -> bool:
    """Return whether ``cmd_body`` is one of the accepted bodies for ``control_type``."""
    expected = _BEAN_TECH_VEHICLE_CONTROL_BODIES[control_type]
    if isinstance(expected, tuple):
        return cmd_body in expected
    return cmd_body == expected


def _valid_bean_tech_comfort_off_commands(commands: object) -> bool:
    """Return whether ``commands`` is the exact one-touch comfort-off sequence."""
    return commands == [
        {"controlType": "AIR_CONDITIONER_STOP"},
        {
            "controlType": "SEAT_HEATING_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 1, "rightFront": 0},
        },
        {
            "controlType": "SEAT_VENTILATION_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 2, "rightFront": 0},
        },
        {"controlType": "STEERING_WHEEL_HEATLESS"},
    ]


def _valid_bean_tech_command_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
    *,
    command_kind: Literal["lock", "windows", "vehicle_control", "climate"],
) -> bool:
    if request.url == _BEAN_TECH_TIMELY_URL:
        return _valid_bean_tech_timely_command_request(
            request,
            headers,
            command_kind=command_kind,
        )
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if not isinstance(body, Mapping):
        return False
    commands = body.get("commands")
    if (
        not isinstance(commands, list)
        or len(commands) != 1
        or not isinstance(commands[0], dict)
    ):
        return False
    command = commands[0]
    sequence = body.get("seqNo")
    valid_command_shape = list(command) == ["controlType", "cmdBody"]
    if command_kind == "lock":
        valid_command = (
            valid_command_shape
            and command.get("controlType") in {"VEHICLE_LOCK", "VEHICLE_UNLOCK"}
            and command.get("cmdBody") is None
        )
    elif command_kind == "windows":
        valid_command = (
            valid_command_shape
            and command.get("controlType") == "WINDOW_CLOSE"
            and command.get("cmdBody")
            == {"leftFront": 0, "leftBack": 0, "rightFront": 0, "rightBack": 0}
        )
    elif command_kind == "climate":
        control_type = command.get("controlType")
        if control_type == "AIR_CONDITIONER_START":
            valid_command = (
                valid_command_shape
                and _valid_air_conditioner_start_body(command.get("cmdBody"))
            )
        elif control_type == "AIR_CONDITIONER_STOP":
            valid_command = valid_command_shape and command.get("cmdBody") is None
        else:
            valid_command = False
    else:
        control_type = command.get("controlType")
        if control_type == "ENGINE_START":
            engine_body = command.get("cmdBody")
            valid_command = (
                valid_command_shape
                and isinstance(engine_body, Mapping)
                and list(engine_body) == ["operationTime"]
                and isinstance(engine_body.get("operationTime"), int)
                and not isinstance(engine_body.get("operationTime"), bool)
                and 300 <= int(engine_body["operationTime"]) <= 1800
                and int(engine_body["operationTime"]) % 60 == 0
            )
        else:
            if isinstance(control_type, str) and control_type in _BEAN_TECH_VEHICLE_CONTROL_BODIES:
                valid_command = (
                    valid_command_shape
                    and _bean_tech_vehicle_control_body_matches(
                        control_type, command.get("cmdBody")
                    )
                )
            elif control_type == "COMFORT_MODE_CTRL":
                valid_command = (
                    valid_command_shape
                    and command.get("cmdBody") in _BEAN_TECH_COMFORT_MODE_BODIES
                )
            else:
                valid_command = False
    return (
        valid_command
        and request.service == "bean_tech"
        and request.method == "POST"
        and request.url == _BEAN_TECH_SEND_URL
        and set(headers) == _BEAN_TECH_COMMAND_HEADERS
        and list(body) == ["vin", "seqNo", "sendType", "commands", "isSaveConfig"]
        and _VIN.fullmatch(str(body.get("vin", ""))) is not None
        and body.get("vin") == headers.get("vin")
        and isinstance(sequence, str)
        and _BEAN_TECH_SEQUENCE.fullmatch(sequence) is not None
        and body.get("sendType") == 0
        and body.get("isSaveConfig") is None
        and raw_body is not None
        and encode_dotnet_json(body) == raw_body
        and headers.get("Content-Type") == "application/json; charset=UTF-8"
        and _valid_bean_tech_authenticated_headers(headers)
        and headers.get("bt-auth-sign")
        == bean_tech_sign(
            "POST",
            _BEAN_TECH_SEND_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    )


def _valid_bean_tech_timely_command_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
    *,
    command_kind: Literal["lock", "windows", "vehicle_control", "climate"],
) -> bool:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if not isinstance(body, Mapping):
        return False
    commands = body.get("commands")
    if isinstance(commands, list) and body.get("sendType") == 1:
        return (
            command_kind == "vehicle_control"
            and _valid_bean_tech_comfort_off_commands(commands)
            and _valid_bean_tech_timely_envelope(
                request,
                headers,
                body=body,
                sequence=body.get("seqNo"),
                raw_body=raw_body,
                send_type=1,
            )
        )
    if (
        not isinstance(commands, list)
        or len(commands) != 1
        or not isinstance(commands[0], dict)
    ):
        return False
    command = commands[0]
    sequence = body.get("seqNo")
    has_cmd_body = "cmdBody" in command
    if command_kind == "lock":
        valid_command = (
            not has_cmd_body
            and list(command) == ["controlType"]
            and command.get("controlType") in {"VEHICLE_LOCK", "VEHICLE_UNLOCK"}
        )
    elif command_kind == "windows":
        valid_command = (
            has_cmd_body
            and list(command) == ["controlType", "cmdBody"]
            and command.get("controlType") == "WINDOW_CLOSE"
            and command.get("cmdBody")
            == {"leftFront": 0, "leftBack": 0, "rightFront": 0, "rightBack": 0}
        )
    elif command_kind == "climate":
        control_type = command.get("controlType")
        if control_type == "AIR_CONDITIONER_START":
            valid_command = (
                has_cmd_body
                and list(command) == ["controlType", "cmdBody"]
                and _valid_air_conditioner_start_body(command.get("cmdBody"))
            )
        elif control_type == "AIR_CONDITIONER_STOP":
            valid_command = (
                not has_cmd_body
                and list(command) == ["controlType"]
            )
        else:
            valid_command = False
    else:
        control_type = command.get("controlType")
        if control_type == "ENGINE_START":
            engine_body = command.get("cmdBody")
            valid_command = (
                has_cmd_body
                and list(command) == ["controlType", "cmdBody"]
                and isinstance(engine_body, Mapping)
                and list(engine_body) == ["operationTime"]
                and isinstance(engine_body.get("operationTime"), int)
                and not isinstance(engine_body.get("operationTime"), bool)
                and 300 <= int(engine_body["operationTime"]) <= 1800
                and int(engine_body["operationTime"]) % 60 == 0
            )
        else:
            if isinstance(control_type, str) and control_type in _BEAN_TECH_VEHICLE_CONTROL_BODIES:
                expects_body = _bean_tech_vehicle_control_expects_body(control_type)
                valid_command = (
                    has_cmd_body == expects_body
                    and list(command)
                    == (
                        ["controlType", "cmdBody"]
                        if expects_body
                        else ["controlType"]
                    )
                    and _bean_tech_vehicle_control_body_matches(
                        control_type, command.get("cmdBody")
                    )
                )
            elif control_type == "COMFORT_MODE_CTRL":
                valid_command = (
                    has_cmd_body
                    and list(command) == ["controlType", "cmdBody"]
                    and command.get("cmdBody") in _BEAN_TECH_COMFORT_MODE_BODIES
                )
            else:
                valid_command = False
    return valid_command and _valid_bean_tech_timely_envelope(
        request,
        headers,
        body=body,
        sequence=sequence,
        raw_body=raw_body,
        send_type=0,
    )


def _valid_bean_tech_timely_envelope(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
    *,
    body: Mapping[str, object],
    sequence: object,
    raw_body: str | None,
    send_type: object,
) -> bool:
    security_token = headers.get("securityToken")
    return (
        request.service == "bean_tech"
        and request.method == "POST"
        and request.url == _BEAN_TECH_TIMELY_URL
        and set(headers)
        == (
            _BEAN_TECH_TIMELY_TOKEN_HEADERS
            if security_token is not None
            else _BEAN_TECH_COMMAND_HEADERS
        )
        and (security_token is None or _safe_wire_text(security_token, maximum=4096))
        and list(body) == ["vin", "seqNo", "sendType", "commands"]
        and _VIN.fullmatch(str(body.get("vin", ""))) is not None
        and body.get("vin") == headers.get("vin")
        and isinstance(sequence, str)
        and _BEAN_TECH_SEQUENCE.fullmatch(sequence) is not None
        and body.get("sendType") == send_type
        and raw_body is not None
        and encode_dotnet_json(body) == raw_body
        and headers.get("Content-Type") == "application/json; charset=UTF-8"
        and _valid_bean_tech_authenticated_headers(headers)
        and headers.get("bt-auth-sign")
        == bean_tech_sign(
            "POST",
            _BEAN_TECH_TIMELY_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    )


def _validate_remote_command_result_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    if request.url.startswith(_BEAN_TECH_RESULT_URL + "?"):
        _validate_bean_tech_command_result_request(request, headers)
        return
    vin = headers.get("vin", "")
    try:
        parsed = urlsplit(request.url)
        tokens = parsed.query.split("&")
        if len(tokens) != 3:
            raise ValueError
        sequence_token, vin_token, message_token = tokens
        if not sequence_token.startswith("seqNo=") or not vin_token.startswith("vin="):
            raise ValueError
        sequence = unquote_to_bytes(sequence_token[6:]).decode("utf-8", errors="strict")
        query_vin = unquote_to_bytes(vin_token[4:]).decode("utf-8", errors="strict")
        if message_token not in {"msgType=remote", "msgType=charge"}:
            raise ValueError
        message_type = message_token[8:]
        canonical_url = (
            _NAVINFO_RESULT_URL
            + "?seqNo="
            + quote(sequence, safe="", encoding="utf-8", errors="strict")
            + "&vin="
            + quote(query_vin, safe="", encoding="utf-8", errors="strict")
            + "&"
            + message_token
        )
    except (UnicodeError, ValueError):
        raise ValueError("route_invalid") from None
    if (
        request.service != "bean_tech"
        or request.method != "GET"
        or request.body is not None
        or parsed.scheme != "https"
        or parsed.hostname != "gw-app-gateway.gwmapp-h.com"
        or parsed.port is not None
        or parsed.path != _NAVINFO_RESULT_PATH
        or request.url != canonical_url
        or query_vin != vin
        or not _safe_wire_text(sequence, maximum=512)
        or set(headers) != _BEAN_TECH_STATUS_HEADERS
        or _VIN.fullmatch(vin) is None
        or headers.get("bt-auth-appkey") != BEAN_TECH_APP_KEY
        or _LOWER_HEX_16.fullmatch(headers.get("bt-auth-nonce", "")) is None
        or not _epoch_milliseconds(headers.get("bt-auth-timestamp", ""))
        or headers.get("rs") != "2"
        or headers.get("appId") != "097a7099af30d960"
        or headers.get("brand") != "10"
        or headers.get("terminal") != "GW_APP_GWM"
        or headers.get("enterPriseId") != "CC01"
        or not _safe_wire_text(headers.get("accessToken"), maximum=16 * 1024)
        or not _safe_wire_text(headers.get("beanId"), maximum=16 * 1024)
        or headers.get("cVer") != "2.1.5"
        or headers.get("tenantId") != "1"
        or headers.get("operatorRole") != "0"
        or not _safe_wire_text(headers.get("tokenId"), maximum=16 * 1024)
        or headers.get("Accept-Encoding") != "gzip"
        or headers.get("User-Agent") != _OFFICIAL_USER_AGENT
        or headers.get("bt-auth-sign")
        not in {
            bean_tech_sign(
                "GET",
                _NAVINFO_RESULT_PATH,
                headers["bt-auth-nonce"],
                headers["bt-auth-timestamp"],
                "msgtype=" + message_type + "seqno=" + sequence + "vin=" + vin,
            ),
            bean_tech_sign(
                "GET",
                _NAVINFO_RESULT_PATH,
                headers["bt-auth-nonce"],
                headers["bt-auth-timestamp"],
                "seqNo="
                + quote(sequence, safe="", encoding="utf-8", errors="strict")
                + "&vin="
                + quote(query_vin, safe="", encoding="utf-8", errors="strict")
                + "&"
                + message_token,
            ),
        }
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_command_result_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    try:
        parsed = urlsplit(request.url)
        if not parsed.query.startswith("seqNo=") or "&" in parsed.query:
            raise ValueError
        sequence = unquote_to_bytes(parsed.query[6:]).decode("utf-8", errors="strict")
        canonical_url = (
            _BEAN_TECH_RESULT_URL
            + "?seqNo="
            + quote(
                sequence,
                safe="",
                encoding="utf-8",
                errors="strict",
            )
        )
    except (UnicodeError, ValueError):
        raise ValueError("route_invalid") from None
    if (
        request.service != "bean_tech"
        or request.method != "GET"
        or request.body is not None
        or request.url != canonical_url
        or parsed.scheme != "https"
        or parsed.hostname != "gw-app-gateway.gwmapp-h.com"
        or parsed.port is not None
        or parsed.path != _BEAN_TECH_RESULT_PATH
        or not _safe_wire_text(sequence, maximum=512)
        or set(headers) != _BEAN_TECH_STATUS_HEADERS
        or _VIN.fullmatch(headers.get("vin", "")) is None
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "GET",
            _BEAN_TECH_RESULT_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "seqno=" + sequence,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_security_token_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_SECURITY_TOKEN_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body) != ["securityPwd", "eventType", "version"]
        or not _safe_wire_text(body.get("securityPwd"), maximum=16 * 1024)
        or body.get("eventType") != 2
        or body.get("version") != 1
        or _VIN.fullmatch(headers.get("vin", "")) is None
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _BEAN_TECH_SECURITY_TOKEN_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_records_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    page_num = body.get("pageNum") if isinstance(body, Mapping) else None
    page_size = body.get("pageSize") if isinstance(body, Mapping) else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_RECORDS_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body) != ["vin", "type", "pageNum", "pageSize"]
        or body.get("type") != "SELF"
        or isinstance(page_num, bool)
        or not isinstance(page_num, int)
        or not 1 <= page_num <= 10_000
        or isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= 100
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or encode_dotnet_json(body) != raw_body
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _BEAN_TECH_RECORDS_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_charge_setting_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    vin = headers.get("vin", "")
    try:
        parsed = urlsplit(request.url)
        expected_path = _BEAN_TECH_CHARGE_SETTING_PATH + "/" + vin
        if parsed.path != expected_path or parsed.query != "strategy=5":
            raise ValueError
    except ValueError:
        raise ValueError("route_invalid") from None
    expected_url = (
        _BEAN_TECH_CHARGE_SETTING_URL
        + "/"
        + quote(vin, safe="", encoding="utf-8", errors="strict")
        + "?strategy=5"
    )
    if (
        request.service != "bean_tech"
        or request.method != "GET"
        or request.body is not None
        or request.url != expected_url
        or parsed.scheme != "https"
        or parsed.hostname != "gw-app-gateway.gwmapp-h.com"
        or parsed.port is not None
        or set(headers) != _BEAN_TECH_STATUS_HEADERS
        or _VIN.fullmatch(vin) is None
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "GET",
            _BEAN_TECH_CHARGE_SETTING_PATH + "/" + vin,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "strategy=5",
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_charge_setting_write_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    charging_mode = body.get("chargingMode") if isinstance(body, Mapping) else None
    charge_strategy = body.get("chargeStrategy") if isinstance(body, Mapping) else None
    charge_set_param = body.get("chargeSetParam") if isinstance(body, Mapping) else None
    sequence = body.get("seqNo") if isinstance(body, Mapping) else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_CHARGE_SETTING_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body)
        != ["vin", "chargingMode", "chargeStrategy", "chargeSetParam", "seqNo"]
        or charging_mode not in {0, 1}
        or isinstance(charge_strategy, bool)
        or not isinstance(charge_strategy, int)
        or not isinstance(charge_set_param, Mapping)
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or not isinstance(sequence, str)
        or _BEAN_TECH_SEQUENCE.fullmatch(sequence) is None
        or encode_dotnet_json(body) != raw_body
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _BEAN_TECH_CHARGE_SETTING_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_config_query_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    types = body.get("types") if isinstance(body, Mapping) else None
    user_id = body.get("userId") if isinstance(body, Mapping) else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_CONFIG_QUERY_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body) != ["sendType", "types", "userId", "vin"]
        or body.get("sendType") != 0
        or types != ["BATTERY_HEATING_APPOINTMENT"]
        or not isinstance(user_id, str)
        or not user_id
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or encode_dotnet_json(body) != raw_body
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _BEAN_TECH_CONFIG_QUERY_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_subscribe_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    commands = body.get("commands") if isinstance(body, Mapping) else None
    subscribe_time = body.get("time") if isinstance(body, Mapping) else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _BEAN_TECH_SUBSCRIBE_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body) != ["commands", "subscribeType", "time", "vin"]
        or body.get("subscribeType") != 0
        or commands
        != [
            {
                "controlType": "CABIN_CLEANING_START",
                "cmdBody": {"operationTime": 60},
            }
        ]
        or isinstance(subscribe_time, bool)
        or not isinstance(subscribe_time, int)
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or encode_dotnet_json(body) != raw_body
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _BEAN_TECH_SUBSCRIBE_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_config_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    configs = body.get("configs") if isinstance(body, Mapping) else None
    if (
        request.service != "bean_tech"
        or request.method != "POST"
        or request.url != _NAVINFO_CLIMATE_CONFIG_URL
        or raw_body is None
        or not isinstance(body, Mapping)
        or set(headers) != _BEAN_TECH_COMMAND_HEADERS
        or list(body) != ["configs", "vin"]
        or not isinstance(configs, list)
        or len(configs) != 1
        or not isinstance(configs[0], Mapping)
        or list(configs[0]) != ["controlType", "cmdBody"]
        or configs[0].get("controlType") != "AIR_CONDITIONER_START"
        or not _valid_air_conditioner_start_body(configs[0].get("cmdBody"))
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
        or body.get("vin") != headers.get("vin")
        or encode_dotnet_json(body) != raw_body
        or headers.get("Content-Type") != "application/json; charset=UTF-8"
        or not _valid_bean_tech_authenticated_headers(headers)
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "POST",
            _NAVINFO_CLIMATE_CONFIG_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "json=" + raw_body,
        )
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_battery_heating_appointment_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if not isinstance(body, Mapping):
        raise ValueError("route_invalid")
    commands = body.get("commands")
    if not isinstance(commands, list) or len(commands) != 1:
        raise ValueError("route_invalid")
    command = commands[0]
    if not isinstance(command, Mapping):
        raise ValueError("route_invalid")
    control_type = command.get("controlType")
    if control_type == "BATTERY_HEATING_APPOINTMENT":
        cmd_body = command.get("cmdBody")
        use_car_time = (
            cmd_body.get("useCarTime") if isinstance(cmd_body, Mapping) else None
        )
        valid_command = (
            list(command) == ["controlType", "cmdBody"]
            and isinstance(use_car_time, int)
            and not isinstance(use_car_time, bool)
            and use_car_time > 0
        )
    elif control_type == "BATTERY_TC_STOP":
        valid_command = list(command) == ["controlType"]
    else:
        valid_command = False
    if not valid_command or not _valid_bean_tech_timely_envelope(
        request,
        headers,
        body=body,
        sequence=body.get("seqNo"),
        raw_body=raw_body,
        send_type=0,
    ):
        raise ValueError("route_invalid")


def _validate_bean_tech_charge_soc_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    raw_body = _utf8_body(request.body)
    body = _decode_wire_object(raw_body) if raw_body is not None else None
    if not isinstance(body, Mapping):
        raise ValueError("route_invalid")
    commands = body.get("commands")
    if not isinstance(commands, list) or len(commands) != 1:
        raise ValueError("route_invalid")
    command = commands[0]
    if not isinstance(command, Mapping):
        raise ValueError("route_invalid")
    cmd_body = command.get("cmdBody")
    charge_soc = (
        cmd_body.get("chargeSoc") if isinstance(cmd_body, Mapping) else None
    )
    valid_command = (
        command.get("controlType") == "CTRL_CHARGE_SOC"
        and list(command) == ["controlType", "cmdBody"]
        and isinstance(charge_soc, int)
        and not isinstance(charge_soc, bool)
        and 50 <= charge_soc <= 100
        and charge_soc % 10 == 0
    )
    if not valid_command or not _valid_bean_tech_timely_envelope(
        request,
        headers,
        body=body,
        sequence=body.get("seqNo"),
        raw_body=raw_body,
        send_type=0,
    ):
        raise ValueError("route_invalid")


def _valid_bean_tech_authenticated_headers(headers: Mapping[str, str]) -> bool:
    return (
        headers.get("bt-auth-appkey") == BEAN_TECH_APP_KEY
        and _LOWER_HEX_16.fullmatch(headers.get("bt-auth-nonce", "")) is not None
        and _epoch_milliseconds(headers.get("bt-auth-timestamp", ""))
        and headers.get("rs") == "2"
        and headers.get("appId") == "097a7099af30d960"
        and headers.get("brand") == "10"
        and headers.get("terminal") == "GW_APP_GWM"
        and headers.get("enterPriseId") == "CC01"
        and _safe_wire_text(headers.get("accessToken"), maximum=16 * 1024)
        and _safe_wire_text(headers.get("beanId"), maximum=16 * 1024)
        and headers.get("cVer") == "2.1.5"
        and headers.get("tenantId") == "1"
        and headers.get("operatorRole") == "0"
        and _safe_wire_text(headers.get("tokenId"), maximum=16 * 1024)
        and headers.get("Accept-Encoding") == "gzip"
        and headers.get("User-Agent") == _OFFICIAL_USER_AGENT
    )


def _validate_bean_tech_status_request(
    request: _ChinaTransportRequest,
    headers: Mapping[str, str],
) -> None:
    vin = headers.get("vin", "")
    expected_url = (
        _BEAN_TECH_STATUS_URL
        + "?vin="
        + quote(
            vin,
            safe="",
            encoding="utf-8",
            errors="strict",
        )
    )
    if (
        request.service != "bean_tech"
        or request.method != "GET"
        or request.body is not None
        or request.url != expected_url
        or set(headers) != _BEAN_TECH_STATUS_HEADERS
        or _VIN.fullmatch(vin) is None
        or headers.get("bt-auth-appkey") != BEAN_TECH_APP_KEY
        or _LOWER_HEX_16.fullmatch(headers.get("bt-auth-nonce", "")) is None
        or not _epoch_milliseconds(headers.get("bt-auth-timestamp", ""))
        or headers.get("rs") != "2"
        or headers.get("appId") != "097a7099af30d960"
        or headers.get("brand") != "10"
        or headers.get("terminal") != "GW_APP_GWM"
        or headers.get("enterPriseId") != "CC01"
        or not _safe_wire_text(headers.get("accessToken"), maximum=16 * 1024)
        or not _safe_wire_text(headers.get("beanId"), maximum=16 * 1024)
        or headers.get("cVer") != "2.1.5"
        or headers.get("tenantId") != "1"
        or headers.get("operatorRole") != "0"
        or not _safe_wire_text(headers.get("tokenId"), maximum=16 * 1024)
        or headers.get("Accept-Encoding") != "gzip"
        or headers.get("User-Agent") != _OFFICIAL_USER_AGENT
        or headers.get("bt-auth-sign")
        != bean_tech_sign(
            "GET",
            _BEAN_TECH_STATUS_PATH,
            headers["bt-auth-nonce"],
            headers["bt-auth-timestamp"],
            "vin=" + vin,
        )
    ):
        raise ValueError("route_invalid")


def _valid_auto_ai_headers(headers: Mapping[str, str], *, token_required: bool) -> bool:
    token = headers.get("token")
    return (
        headers.get("v") == "1.0"
        and headers.get("client") == "phone"
        and headers.get("ckey") == AUTO_AI_CKEY
        and headers.get("protocolVer") == "2.1.2"
        and headers.get("brandType") == "GWM"
        and headers.get("Accept-Encoding") == "gzip"
        and headers.get("User-Agent") == _OFFICIAL_USER_AGENT
        and _DEVICE_ID.fullmatch(headers.get("cid", "")) is not None
        and _BASE64_SHA1.fullmatch(headers.get("sign", "")) is not None
        and _epoch_milliseconds(headers.get("time", ""))
        and headers.get("sign") == auto_ai_sign(headers["time"])
        and (
            _safe_wire_text(token, maximum=16 * 1024)
            if token_required
            else token is None
        )
    )


def _valid_status_body(body: Mapping[str, object]) -> bool:
    return list(body) == ["vin"] and _safe_wire_text(body.get("vin"), maximum=512)


def _valid_climate_body(body: Mapping[str, object], variant: str) -> bool:
    base_keys = ["flag", "signStr", "userId", "userType", "vin"]
    if (
        list(body)[:5] != base_keys
        or body.get("flag") != 1
        or _LOWER_HEX_32.fullmatch(str(body.get("signStr", ""))) is None
        or not _safe_wire_text(body.get("userId"), maximum=16 * 1024)
        or body.get("userType") != "0"
        or _VIN.fullmatch(str(body.get("vin", ""))) is None
    ):
        return False
    if variant == "off":
        return list(body) == [*base_keys, "cmdCode"] and body.get("cmdCode") == 7
    if variant != "start":
        return False
    expected_keys = [
        *base_keys,
        "cmdCode",
        "airParams",
    ]
    if list(body) != expected_keys or body.get("cmdCode") != 6:
        return False
    air = body.get("airParams")
    return (
        isinstance(air, dict)
        and list(air) == ["engineControl", "runTime", "temperature"]
        and air.get("engineControl") == 1
        and isinstance(air.get("runTime"), int)
        and not isinstance(air.get("runTime"), bool)
        and 5 <= air["runTime"] <= 30
        and isinstance(air.get("temperature"), int)
        and not isinstance(air.get("temperature"), bool)
        and 17 <= air["temperature"] <= 31
    )


def _climate_body_validator(
    variant: str,
) -> Callable[[Mapping[str, object]], bool]:
    def validate(body: Mapping[str, object]) -> bool:
        return _valid_climate_body(body, variant)

    return validate


def _valid_auto_ai_url(
    url: str,
    headers: Mapping[str, str],
    *,
    origin: str,
    path: str,
    function: str,
    body_validator: Callable[[Mapping[str, object]], bool],
    token_required: bool,
) -> bool:
    try:
        url.encode("ascii")
        if not url.startswith(origin + path + "?p="):
            return False
        if len(url) > _MAX_STATUS_URL_LENGTH:
            return False
        parsed = urlsplit(url)
        expected_origin = urlsplit(origin)
        if (
            parsed.scheme != expected_origin.scheme
            or parsed.hostname != expected_origin.hostname
            or parsed.port != expected_origin.port
            or parsed.path != path
            or not parsed.query.startswith("p=")
            or "&" in parsed.query
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "\\" in url
            or any(character.isspace() for character in url)
        ):
            return False
        encoded = parsed.query[2:]
        payload = unquote_to_bytes(encoded).decode("utf-8", errors="strict")
        if len(payload) > _MAX_STATUS_PAYLOAD_LENGTH:
            return False
        if quote(payload, safe="", encoding="utf-8", errors="strict") != encoded:
            return False
        wrapper = json.loads(
            payload,
            object_pairs_hook=_unique_wire_object,
            parse_constant=_reject_wire_constant,
        )
        _validate_wire_json_depth(wrapper)
        if encode_dotnet_json(wrapper) != payload:
            return False
    except (
        UnicodeDecodeError,
        UnicodeEncodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
    ):
        return False
    if not isinstance(wrapper, dict) or list(wrapper) != ["body", "header"]:
        return False
    body = wrapper.get("body")
    header = wrapper.get("header")
    if not isinstance(body, dict) or not body_validator(body):
        return False
    if not isinstance(header, dict) or list(header) != [
        "brandType",
        "cVer",
        "fn",
        "fv",
        "mobileId",
        "osType",
        "osVer",
        "rs",
        "ts",
        "tk",
        "v",
    ]:
        return False
    return (
        header.get("brandType") == "gwm"
        and header.get("cVer") == "2.1.5"
        and header.get("fn") == function
        and header.get("fv") == "0202"
        and header.get("mobileId") == headers.get("cid")
        and header.get("osType") == "Android"
        and header.get("osVer") == ""
        and header.get("rs") == "2"
        and _auto_ai_timestamp_matches(headers.get("time", ""), header.get("ts"))
        and (
            header.get("tk") == headers.get("token")
            if token_required
            else header.get("tk") == ""
        )
        and header.get("v") == "1.0"
    )


def _unique_wire_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    normalized: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in normalized:
            raise ValueError("duplicate_json_key")
        normalized.add(folded)
        result[key] = value
    return result


def _reject_wire_constant(_value: str) -> object:
    raise ValueError("invalid_json_number")


def _validate_wire_json_depth(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_WIRE_JSON_DEPTH:
        raise ValueError("json_too_deep")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_wire_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_wire_json_depth(child, depth=depth + 1)


def _safe_wire_text(value: object, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _epoch_milliseconds(value: str) -> bool:
    return 10 <= len(value) <= 17 and value.isdecimal()


def _auto_ai_timestamp_matches(
    epoch_milliseconds: str, local_timestamp: object
) -> bool:
    if not _epoch_milliseconds(epoch_milliseconds) or not isinstance(
        local_timestamp, str
    ):
        return False
    seconds, milliseconds = divmod(int(epoch_milliseconds), 1000)
    try:
        instant = datetime.fromtimestamp(seconds, tz=UTC).replace(
            microsecond=milliseconds * 1000
        )
    except (OSError, OverflowError, ValueError):
        return False
    return local_timestamp == format_china_timestamp(instant)


def _second_aligned_epoch(value: str) -> bool:
    return _epoch_milliseconds(value) and value.endswith("000")


def _validated_chunk(chunk: object, *, operation: str) -> bytes:
    if not isinstance(chunk, bytes | bytearray):
        raise GwmProtocolError(operation=operation)
    return bytes(chunk)


def _validated_content_length(value: object, *, operation: str) -> int | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.isdecimal()
        or len(value) > _MAX_DECIMAL_HEADER_LENGTH
    ):
        raise GwmProtocolError(operation=operation)
    return int(value)


def _single_response_header(
    headers: Mapping[str, Any],
    name: str,
    *,
    operation: str,
) -> str | None:
    getall = getattr(headers, "getall", None)
    if callable(getall):
        values = getall(name, [])
        if len(values) > 1:
            raise GwmProtocolError(operation=operation)
        if values:
            return str(values[0])
        return None
    value = headers.get(name)
    return None if value is None else str(value)


def _selected_headers(
    headers: Mapping[str, Any],
    *,
    operation: str,
) -> Mapping[str, str]:
    selected: dict[str, str] = {}
    for name in _SAFE_RESPONSE_HEADERS:
        value = _single_response_header(headers, name, operation=operation)
        if value is not None:
            selected[name] = value
    return selected


def _create_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    _validate_tls_context(context)
    return context


def _validate_tls_context(context: object) -> None:
    if (
        not isinstance(context, ssl.SSLContext)
        or not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.minimum_version < ssl.TLSVersion.TLSv1_2
        or context.security_level <= 0
    ):
        raise ValueError("tls_context_invalid")


def _validate_response_limit(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= _MAX_ALLOWED_RESPONSE_BYTES
    ):
        raise ValueError("response_limit_invalid")


def _valid_phase_timeout(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and math.isfinite(value)
        and value > 0
    )


__all__ = ["ChinaAiohttpTransport", "ChinaTransportCapabilities"]
