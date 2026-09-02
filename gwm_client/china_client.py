"""Production-structured, HA-independent mainland-China authentication and protocol.

The China app protocol spans three independently authenticated services.  This
module deliberately does not extend the overseas ``Region``/``GwmClient``
abstractions: its immutable state, bounded initialization, gzip transport, and
    platform-routed policy remain isolated until the later Home Assistant tasks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal, Self, cast
from urllib.parse import quote

from ._dotnet_json import encode_dotnet_json
from ._protocol import _Deadline
from .charging import ChargingPlanCommand, ChargingPlanInfo, ChargingPlanItem
from .china_crypto import (
    AUTO_AI_CKEY,
    BEAN_TECH_APP_KEY,
    DEFAULT_NOTE_ID,
    auto_ai_sign,
    bean_tech_sign,
    decrypt_g_app,
    default_sign,
    encrypt_g_app,
    format_china_timestamp,
    sha256_hex,
)
from .china_status import map_bean_tech_status, map_china_status
from .china_transport import (
    ChinaAiohttpTransport,
    _ChinaAsyncTransport,
    _ChinaTransportRequest,
    _ChinaTransportResponse,
)
from .commands import (
    BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS,
    NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    RemoteCommandAcceptance,
    RemoteCommandResultItem,
    parse_remote_command_results,
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
from .models import CloudVehicle, CloudVehicleStatus, VehicleIdentifier

# This persisted hash-domain value is a compatibility contract, not a vehicle-scope name.
_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-china-account-v1\0"

__all__ = [
    "ChinaAuthenticated",
    "ChinaAuthenticationResult",
    "ChinaAuthState",
    "ChinaClient",
    "ChinaClientConfig",
    "ChinaCredentials",
    "ChinaInitializationRequired",
    "ChinaRiskControlRequired",
    "ChinaVehicle",
    "ChinaVehicleStatus",
    "ChinaVerificationRequired",
    "ChinaVehicleControlCommand",
    "ChargingPlanCommand",
    "ChargingPlanInfo",
    "ChargingPlanItem",
    "CloseWindowsCommand",
    "ClimateCommand",
    "DoorLockCommand",
    "RemoteCommandAcceptance",
    "RemoteCommandResultItem",
]

type _ChinaService = Literal["bean_tech", "auto_ai"]

_G_APP_BASE = "https://gapp-api.gwmapp-h.com/"
_BEAN_TECH_BASE = "https://gw-app-gateway.gwmapp-h.com/"
_AUTO_AI_DIRECT = "https://ti.gwm.com.cn:8443/tsp/ead"
_SMS_REQUEST_URL = _G_APP_BASE + "api-guser/v5/user/login-sms/send"
_SMS_LOGIN_URL = _G_APP_BASE + "api-guser/v5/user/sms-login"
_REFRESH_URL = _G_APP_BASE + "api-guser/v5/token/refresh"
_BEAN_TECH_LOGIN_URL = _BEAN_TECH_BASE + "app-api/api/v1.0/userAuth/loginSSOAccount"
_BEAN_TECH_STATUS_PATH = "/app-api/api/v2.0/vehicle/getLastStatus"
_BEAN_TECH_STATUS_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_STATUS_PATH
_NAVINFO_RESULT_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/result"
_NAVINFO_RESULT_URL = _BEAN_TECH_BASE.rstrip("/") + _NAVINFO_RESULT_PATH
_NAVINFO_CLIMATE_CONFIG_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/config"
_NAVINFO_CLIMATE_CONFIG_URL = (
    _BEAN_TECH_BASE.rstrip("/") + _NAVINFO_CLIMATE_CONFIG_PATH
)
_BEAN_TECH_SEND_PATH = "/app-api/api/v1.0/vehicle/T5/sendCmd"
_BEAN_TECH_SEND_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_SEND_PATH
_BEAN_TECH_RESULT_PATH = "/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
_BEAN_TECH_RESULT_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_RESULT_PATH
_BEAN_TECH_SECURITY_TOKEN_PATH = "/app-api/api/v3.0/vehicle/security/generate-token"
_BEAN_TECH_SECURITY_TOKEN_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_SECURITY_TOKEN_PATH
_BEAN_TECH_TIMELY_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/timely"
_BEAN_TECH_TIMELY_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_TIMELY_PATH
_BEAN_TECH_TIMELY_RESULT_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/result"
_BEAN_TECH_TIMELY_RESULT_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_TIMELY_RESULT_PATH
_BEAN_TECH_RECORDS_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/records/query"
_BEAN_TECH_RECORDS_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_RECORDS_PATH
_BEAN_TECH_CHARGE_SETTING_PATH = "/app-api/api/v3.0/vehicle/charge/setting"
_BEAN_TECH_CHARGE_SETTING_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_CHARGE_SETTING_PATH
_BEAN_TECH_CONFIG_QUERY_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/config/query"
_BEAN_TECH_CONFIG_QUERY_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_CONFIG_QUERY_PATH
_BEAN_TECH_SUBSCRIBE_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/subscribe"
_BEAN_TECH_SUBSCRIBE_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_SUBSCRIBE_PATH
_BEAN_TECH_PIN_EXEMPT_CONTROL_TYPES = frozenset(
    {
        "FLASH",
        "WHISTLE",
        "WHISTLE_FLASH",
        "AIR_CONDITIONER_START",
        "AIR_CONDITIONER_STOP",
        "SEAT_HEATING_START",
        "SEAT_HEATING_STOP",
        "SEAT_VENTILATION_START",
        "SEAT_VENTILATION_STOP",
        "STEERING_WHEEL_HEATING",
        "STEERING_WHEEL_HEATLESS",
        "DEFROST_FRONT_START",
        "DEFROST_FRONT_STOP",
        "DEFROST_BACK_START",
        "DEFROST_BACK_STOP",
        "CABIN_CLEANING_START",
        "COMFORT_MODE_CTRL",
        "BATTERY_GUN_HEAT_START",
        "BATTERY_GUN_HEAT_STOP",
        "BATTERY_INITIATIVE_HEAT_START",
        "BATTERY_INITIATIVE_HEAT_STOP",
    }
)
_AUTO_AI_LOGIN_URL = _G_APP_BASE + "tsp/v1/proxy/navinfo/GW.M.APP_LOGIN"
_DISCOVERY_URL = _G_APP_BASE + "gcar/v1/app/android/vehicle/query-vehicle-list"
_SOURCE_APP_VERSION = "2.1.5"
_LOGGER = logging.getLogger(__name__)
_SOURCE_APP_CODE = "2150"
_OFFICIAL_USER_AGENT = "okhttp/4.2.2"
_DISCOVERY_BODY = b'{"vehicleVersion":13}'
_VERIFICATION_INTERVAL = timedelta(minutes=10)
_TRANSIENT_INIT_HTTP_STATUSES = frozenset({502, 503, 504})
_MAX_INIT_ATTEMPTS = 3
_INIT_RETRY_SECONDS = 1.0
_MAX_JSON_DEPTH = 64
_MAX_ALLOWED_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_SECRET_LENGTH = 16 * 1024
_MAX_ACCOUNT_BYTES = 64
_MAX_DEVICE_SOURCE_LENGTH = 128
_MAX_OPERATION_TIMEOUT = 24 * 60 * 60
_MAX_VERIFICATION_CODE_LENGTH = 64
_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")
_DEVICE_SOURCE = re.compile(r"[0-9A-Fa-f-]+")
_DEVICE_ID = re.compile(r"[0-9A-Fa-f]{32}")
_VIN = re.compile(r"[A-HJ-NPR-Z0-9]{17}", re.IGNORECASE)
_NONCE = re.compile(r"[0-9a-f]{16}")
_BEAN_TECH_SEQUENCE = re.compile(r"[0-9a-f]{32}[0-9]{4}")
_CLOCK_TIME = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])")
_CHINA_TIMEZONE = timezone(timedelta(hours=8))


@dataclass(frozen=True, slots=True)
class ChinaClientConfig:
    """Stable non-secret limits for one isolated China client."""

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
class ChinaCredentials:
    """A registered China phone and stable per-installation device identity."""

    phone: str = field(repr=False)
    device_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.phone, str) or not isinstance(self.device_id, str):
            raise ValueError("credentials_invalid")
        phone = self.phone.strip()
        try:
            encoded = phone.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ValueError("credentials_invalid") from None
        if (
            not phone
            or len(encoded) > _MAX_ACCOUNT_BYTES
            or any(not character.isprintable() or character.isspace() for character in phone)
        ):
            raise ValueError("credentials_invalid")
        try:
            device_id = _normalize_device_id(self.device_id)
        except (TypeError, ValueError):
            raise ValueError("credentials_invalid") from None
        object.__setattr__(self, "phone", phone)
        object.__setattr__(self, "device_id", device_id)

    @property
    def account_binding(self) -> str:
        digest = hashlib.sha256()
        digest.update(_LEGACY_ACCOUNT_BINDING_DOMAIN)
        digest.update(self.phone.encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ChinaAuthState:
    """Immutable complete-or-partial state for caller-owned persistence."""

    account_binding: str = field(repr=False)
    device_id: str = field(repr=False)
    g_token: str | None = field(default=None, repr=False)
    g_refresh_token: str | None = field(default=None, repr=False)
    sso_token: str | None = field(default=None, repr=False)
    pt_token: str | None = field(default=None, repr=False)
    user_id: str | None = field(default=None, repr=False)
    bean_id: str | None = field(default=None, repr=False)
    bean_tech_access_token: str | None = field(default=None, repr=False)
    bean_tech_refresh_token: str | None = field(default=None, repr=False)
    bean_tech_sso_token: str | None = field(default=None, repr=False)
    bean_tech_bean_id: str | None = field(default=None, repr=False)
    auto_ai_token_id: str | None = field(default=None, repr=False)
    auto_ai_user_id: str | None = field(default=None, repr=False)
    auto_ai_gw_id: str | None = field(default=None, repr=False)
    verification_requested_at: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.account_binding, str)
            or _ACCOUNT_BINDING.fullmatch(self.account_binding) is None
            or not isinstance(self.device_id, str)
            or _DEVICE_ID.fullmatch(self.device_id) is None
        ):
            raise ValueError("auth_state_invalid")
        token_values = (
            self.g_token,
            self.g_refresh_token,
            self.sso_token,
            self.pt_token,
            self.user_id,
            self.bean_id,
            self.bean_tech_access_token,
            self.bean_tech_refresh_token,
            self.bean_tech_sso_token,
            self.bean_tech_bean_id,
            self.auto_ai_token_id,
            self.auto_ai_user_id,
            self.auto_ai_gw_id,
        )
        if not all(_valid_optional_secret(value) for value in token_values):
            raise ValueError("auth_state_invalid")
        if self.verification_requested_at is not None and (
            not isinstance(self.verification_requested_at, datetime)
            or self.verification_requested_at.tzinfo is None
            or self.verification_requested_at.utcoffset() is None
        ):
            raise ValueError("auth_state_invalid")
        downstream = token_values[6:]
        if any(value is not None for value in downstream) and not self.complete:
            raise ValueError("auth_state_invalid")
        if self.bean_tech_access_token is None and any(
            value is not None
            for value in (
                self.bean_tech_refresh_token,
                self.bean_tech_sso_token,
                self.bean_tech_bean_id,
            )
        ):
            raise ValueError("auth_state_invalid")
        auto_pair = (self.auto_ai_token_id, self.auto_ai_user_id)
        if (auto_pair[0] is None) != (auto_pair[1] is None):
            raise ValueError("auth_state_invalid")
        if self.auto_ai_gw_id is not None and auto_pair[0] is None:
            raise ValueError("auth_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: ChinaCredentials) -> ChinaAuthState:
        if type(credentials) is not ChinaCredentials:
            raise ValueError("credentials_invalid")
        return cls(
            account_binding=credentials.account_binding,
            device_id=credentials.device_id,
        )

    @property
    def has_g_app(self) -> bool:
        return self.g_token is not None and self.g_refresh_token is not None and self.user_id is not None

    @property
    def complete(self) -> bool:
        return (
            self.has_g_app
            and self.bean_id is not None
            and self.bean_tech_access_token is not None
            and self.auto_ai_token_id is not None
            and self.auto_ai_user_id is not None
        )

    def matches(self, credentials: ChinaCredentials) -> bool:
        return type(credentials) is ChinaCredentials and (
            self.account_binding == credentials.account_binding
            and self.device_id == credentials.device_id
        )


@dataclass(frozen=True, slots=True)
class ChinaAuthenticated:
    """A complete state that passed an actual discovery validation."""

    state: ChinaAuthState = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.state) is not ChinaAuthState or not self.state.complete:
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class ChinaVerificationRequired:
    """A finite SMS continuation that never retains the submitted code."""

    state: ChinaAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.state) is not ChinaAuthState
            or type(self.code_requested) is not bool
            or type(self.code_rejected) is not bool
            or (self.code_requested and self.code_rejected)
        ):
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class ChinaInitializationRequired:
    """A retryable partial continuation with only secret-safe failure labels."""

    state: ChinaAuthState = field(repr=False)
    failures: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.state) is not ChinaAuthState
            or not self.state.has_g_app
            or self.state.complete
            or not isinstance(self.failures, tuple)
            or not self.failures
            or any(
                not isinstance(value, str)
                or not 0 < len(value) <= 80
                or re.fullmatch(r"[a-z0-9_:]+", value) is None
                for value in self.failures
            )
        ):
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class ChinaRiskControlRequired:
    """The official app must complete G-App risk-control challenge 1013."""

    state: ChinaAuthState = field(repr=False)
    api_code: str = "1013"

    def __post_init__(self) -> None:
        if type(self.state) is not ChinaAuthState or self.api_code != "1013":
            raise ValueError("authentication_result_invalid")


type ChinaAuthenticationResult = (
    ChinaAuthenticated
    | ChinaVerificationRequired
    | ChinaInitializationRequired
    | ChinaRiskControlRequired
)


@dataclass(frozen=True, slots=True)
class ChinaVehicle(CloudVehicle):
    """Safe China discovery fields plus the mapping/route metadata later tasks need."""

    network_type: int | None = field(default=None, repr=False)
    tank_capacity: float | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ChinaVehicleStatus(CloudVehicleStatus):
    """China translation in the shared pre-normalization status shape."""


class _ChinaRiskControlError(GwmApiError):
    pass


class ChinaClient:
    """Lifecycle-managed China SMS authentication and platform-routed client."""

    def __init__(
        self,
        config: ChinaClientConfig,
        *,
        authenticated_state: ChinaAuthState | None = None,
        bean_tech_security_password: str | None = None,
        transport: _ChinaAsyncTransport | None = None,
        clock: Callable[[], datetime] | None = None,
        salt_source: Callable[[], bytes] | None = None,
        nonce_source: Callable[[], str] | None = None,
        sequence_source: Callable[[], str] | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if type(config) is not ChinaClientConfig:
            raise GwmConfigurationError()
        for callback in (clock, salt_source, nonce_source, sequence_source, sleeper):
            if callback is not None and not callable(callback):
                raise GwmConfigurationError()
        if authenticated_state is not None and (
            type(authenticated_state) is not ChinaAuthState
            or not authenticated_state.complete
        ):
            raise GwmConfigurationError(operation="login")
        if bean_tech_security_password is not None and (
            not isinstance(bean_tech_security_password, str)
            or not bean_tech_security_password.strip()
        ):
            raise GwmConfigurationError(operation="login")
        self._bean_tech_security_password = bean_tech_security_password
        self._config = config
        self._clock = clock or _utc_now
        self._salt_source = salt_source or (lambda: secrets.token_bytes(8))
        self._nonce_source = nonce_source or _random_nonce
        self._sequence_source = sequence_source or _random_bean_tech_sequence
        self._sleeper = sleeper or asyncio.sleep
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
        # A caller may transfer a state that already passed this client's
        # authentication/discovery validation. This mirrors the overseas
        # client's validated-session handoff and avoids an implicit second
        # China login during Home Assistant entry setup.
        self._session: ChinaAuthState | None = authenticated_state
        self._session_revision = 1 if authenticated_state is not None else 0
        self._vehicles: dict[str, ChinaVehicle] = {}
        self._charging_plans: dict[str, ChargingPlanInfo] = {}
        self._written_charging_plan_vins: set[str] = set()
        self._consumed_verification_bindings: set[str] = set()
        self._closed = False
        self._closing = False
        self._close_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def authenticated(self) -> bool:
        return self._session is not None

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
                    self._session = None
                    self._vehicles = {}
                    self._charging_plans = {}
                    self._written_charging_plan_vins.clear()
                    self._consumed_verification_bindings.clear()
                    self._session_revision += 1
            except BaseException:
                self._closing = False
                raise
            self._closed = True
            self._closing = False

    async def authenticate(
        self,
        credentials: ChinaCredentials,
        *,
        state: ChinaAuthState | None = None,
        verification_code: str | None = None,
        allow_sms_login: bool = True,
        timeout: float | None = None,
    ) -> ChinaAuthenticationResult:
        """Run one serialized finite China authentication continuation."""

        operation = "login"
        if (
            type(credentials) is not ChinaCredentials
            or (state is not None and type(state) is not ChinaAuthState)
            or type(allow_sms_login) is not bool
            or (not allow_sms_login and verification_code is not None)
        ):
            raise GwmConfigurationError(operation=operation)
        code = _normalize_verification_code(verification_code)
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total)
        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    candidate = (
                        state
                        if state is not None and state.matches(credentials)
                        else ChinaAuthState.for_credentials(credentials)
                    )
                    reusable = self._session is not None and self._session == candidate
                    attempt_revision = self._session_revision
                    if not reusable:
                        self._revoke_session()
                        attempt_revision = self._session_revision
                    result, vehicles = await self._authenticate_locked(
                        credentials,
                        candidate,
                        verification_code=code,
                        allow_sms_login=allow_sms_login,
                        deadline=deadline,
                    )
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    if type(result) is ChinaAuthenticated:
                        if vehicles is None:
                            raise GwmProtocolError(operation=operation)
                        self._install_if_revision(
                            expected_revision=attempt_revision,
                            state=result.state,
                            vehicles=vehicles,
                        )
                    else:
                        self._clear_if_revision(expected_revision=attempt_revision)
                    return result
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None
        except GwmClientError as error:
            raise _sanitized_error(error) from None
        except Exception:
            raise GwmNetworkError(operation=operation) from None

    async def acquire_vehicles(
        self,
        *,
        timeout: float | None = None,
    ) -> tuple[ChinaVehicle, ...]:
        """Force a fresh corrected-route G-App discovery read."""

        operation = "acquire_vehicles"
        return await self._run_read(
            operation,
            timeout=timeout,
            action=self._acquire_current_vehicles_locked,
            commit=self._commit_vehicles,
        )

    async def get_last_status(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> ChinaVehicleStatus:
        """Read one discovered vehicle through its declared China platform."""

        operation = "get_last_status"
        if type(identifier) is not VehicleIdentifier:
            raise GwmRoutePolicyError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_last_status_locked(identifier, deadline=deadline),
        )

    async def send_climate_command(
        self,
        command: ClimateCommand,
        *,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a platform-routed China climate command."""

        operation: Literal["send_climate_command"] = "send_climate_command"
        if type(command) is not ClimateCommand:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._send_climate_command_locked(command, deadline=deadline),
        )

    async def send_lock_command(
        self,
        command: DoorLockCommand,
        *,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a platform-routed China lock or unlock command without a PIN."""

        operation: Literal["send_lock_command"] = "send_lock_command"
        if type(command) is not DoorLockCommand:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._send_lock_window_command_locked(
                command,
                operation=operation,
                command_code=2 if command.lock else 1,
                deadline=deadline,
            ),
        )

    async def send_close_windows_command(
        self,
        command: CloseWindowsCommand,
        *,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a platform-routed China close-all-windows command without a PIN."""

        operation: Literal["send_close_windows_command"] = "send_close_windows_command"
        if type(command) is not CloseWindowsCommand:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._send_lock_window_command_locked(
                command,
                operation=operation,
                command_code=3,
                deadline=deadline,
            ),
        )

    async def send_vehicle_control_command(
        self,
        command: ChinaVehicleControlCommand,
        *,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one platform-filtered extended China control without a PIN."""

        operation: Literal["send_vehicle_control_command"] = (
            "send_vehicle_control_command"
        )
        if type(command) is not ChinaVehicleControlCommand:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._send_vehicle_control_command_locked(
                command,
                deadline=deadline,
            ),
        )

    async def get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        msg_type: Literal["remote", "charge"] = "remote",
        timeout: float | None = None,
    ) -> tuple[RemoteCommandResultItem, ...]:
        """Poll the result stream through the signed BeanTech endpoint.

        Remote commands use ``msgType=remote``; BeanTech charging-setting writes
        use ``msgType=charge``. Both share the ``messageList`` result envelope.
        """

        operation = "get_remote_command_result"
        if (
            type(identifier) is not VehicleIdentifier
            or not isinstance(command_id, str)
            or not command_id
            or len(command_id) > 512
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in command_id)
            or msg_type not in {"remote", "charge"}
        ):
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_remote_command_results_locked(
                identifier,
                command_id,
                msg_type=msg_type,
                deadline=deadline,
            ),
        )

    async def get_remote_command_records(
        self,
        identifier: VehicleIdentifier,
        *,
        page_num: int = 1,
        page_size: int = 20,
        timeout: float | None = None,
    ) -> Mapping[str, object]:
        """Read one BeanTech vehicle's paged remote-control records.

        The endpoint returns the raw ``data`` mapping (``pageNum``/``total``/
        ``pages``/``list``); each ``list`` entry carries at least ``resultMsg``.
        """

        operation = "get_remote_command_records"
        if (
            type(identifier) is not VehicleIdentifier
            or isinstance(page_num, bool)
            or not isinstance(page_num, int)
            or not 1 <= page_num <= 10_000
            or isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 100
        ):
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_remote_command_records_locked(
                identifier,
                page_num=page_num,
                page_size=page_size,
                deadline=deadline,
            ),
        )

    async def get_bean_tech_charge_setting(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> Mapping[str, object]:
        """Read one BeanTech vehicle's smart-charge setting.

        The endpoint returns the raw ``data`` mapping carrying ``chargingMode``
        (0 = scheduled charging, 1 = plug-and-charge), ``chargeStrategy`` and
        ``chargeSetParam`` (``customTime`` / ``drivingPlanTimes``).
        """

        operation = "get_bean_tech_charge_setting"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_bean_tech_charge_setting_locked(
                identifier,
                deadline=deadline,
            ),
        )

    async def set_bean_tech_charging_mode(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        timeout: float | None = None,
    ) -> str:
        """Set one BeanTech smart-charge mode and return the seqNo to poll.

        The vehicle reports the setting with inverted ``chargingMode`` semantics
        (0 = scheduled, 1 = immediate). The current setting is always read first
        and only ``chargingMode`` is written back, preserving ``chargeSetParam``
        verbatim so the app-configured ``customTime`` window and
        ``drivingPlanTimes`` are never overwritten.
        """

        operation = "set_bean_tech_charging_mode"
        if type(identifier) is not VehicleIdentifier or type(enable) is not bool:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_bean_tech_charging_mode_locked(
                identifier,
                enable=enable,
                deadline=deadline,
            ),
        )

    async def get_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> bool:
        """Read whether BeanTech battery appointment heating is switched on.

        The ``remote-ctrl/config/query`` endpoint returns ``cmdContent.switchType``
        (1 = appointment heating armed, 0 = disarmed).
        """

        operation = "get_bean_tech_battery_heating_appointment"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_bean_tech_battery_heating_appointment_locked(
                identifier,
                deadline=deadline,
            ),
        )

    async def set_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        use_car_time_ms: int | None = None,
        timeout: float | None = None,
    ) -> str:
        """Arm or disarm BeanTech battery appointment heating, returning the seqNo.

        ``enable=True`` sends ``BATTERY_HEATING_APPOINTMENT`` with the departure
        time ``use_car_time_ms`` (epoch milliseconds); ``enable=False`` sends
        ``BATTERY_TC_STOP``. Both are PIN-exempt.
        """

        operation = "set_bean_tech_battery_heating_appointment"
        if type(identifier) is not VehicleIdentifier or type(enable) is not bool:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_bean_tech_battery_heating_appointment_locked(
                identifier,
                enable=enable,
                use_car_time_ms=use_car_time_ms,
                deadline=deadline,
            ),
        )

    async def set_bean_tech_charge_soc(
        self,
        identifier: VehicleIdentifier,
        *,
        percent: int,
        timeout: float | None = None,
    ) -> str:
        """Set the BeanTech charge limit (50-100, step 10), returning the seqNo.

        Sends ``CTRL_CHARGE_SOC`` with ``chargeSoc``. The vehicle does not report
        the current limit in the polled snapshot, so this is command-only.
        """

        operation = "set_bean_tech_charge_soc"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_bean_tech_charge_soc_locked(
                identifier,
                percent=percent,
                deadline=deadline,
            ),
        )

    async def set_bean_tech_cabin_clean_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        time_ms: int,
        timeout: float | None = None,
    ) -> None:
        """Schedule one BeanTech cabin-clean run at ``time_ms`` (epoch ms)."""

        operation = "set_bean_tech_cabin_clean_appointment"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_bean_tech_cabin_clean_appointment_locked(
                identifier,
                time_ms=time_ms,
                deadline=deadline,
            ),
        )

    async def set_bean_tech_charge_window(
        self,
        identifier: VehicleIdentifier,
        *,
        start_time: str,
        end_time: str,
        timeout: float | None = None,
    ) -> str:
        """Write the BeanTech smart-charge time window (HH:MM), returning seqNo."""

        operation = "set_bean_tech_charge_window"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_bean_tech_charge_window_locked(
                identifier,
                start_time=start_time,
                end_time=end_time,
                deadline=deadline,
            ),
        )

    async def get_charging_plan(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> ChargingPlanInfo:
        """Read or return the synthesized NavInfo weekly charging plan."""

        operation = "get_charging_plan"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        return await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._get_charging_plan_locked(
                identifier,
                deadline=deadline,
            ),
        )

    async def set_charging_plan(
        self,
        command: ChargingPlanCommand,
        *,
        timeout: float | None = None,
    ) -> None:
        """Set or clear one NavInfo weekly charging plan without a PIN."""

        operation = "set_charging_plan"
        if type(command) is not ChargingPlanCommand:
            raise GwmConfigurationError(operation=operation)
        await self._run_read(
            operation,
            timeout=timeout,
            action=lambda deadline: self._set_charging_plan_locked(
                command,
                deadline=deadline,
            ),
        )

    async def _authenticate_locked(
        self,
        credentials: ChinaCredentials,
        candidate: ChinaAuthState,
        *,
        verification_code: str | None,
        allow_sms_login: bool,
        deadline: _Deadline,
    ) -> tuple[ChinaAuthenticationResult, tuple[ChinaVehicle, ...] | None]:
        if candidate.complete:
            try:
                vehicles = await self._acquire_vehicles_for_state(candidate, deadline=deadline)
            except _ChinaRiskControlError:
                return ChinaRiskControlRequired(state=candidate), None
            except GwmAuthenticationError:
                self._session = None
                self._vehicles = {}
                self._charging_plans = {}
                self._written_charging_plan_vins.clear()
                return await self._refresh_or_sms(
                    credentials,
                    candidate,
                    verification_code=verification_code,
                    allow_sms_login=allow_sms_login,
                    deadline=deadline,
                )
            return ChinaAuthenticated(state=candidate), vehicles

        if candidate.has_g_app:
            return await self._initialize_and_validate(credentials, _without_downstream(candidate), deadline=deadline)

        if not allow_sms_login:
            raise GwmAuthenticationError(operation="login")
        return await self._sms_continuation(
            credentials,
            candidate,
            verification_code=verification_code,
            deadline=deadline,
        )

    async def _refresh_or_sms(
        self,
        credentials: ChinaCredentials,
        candidate: ChinaAuthState,
        *,
        verification_code: str | None,
        allow_sms_login: bool,
        deadline: _Deadline,
    ) -> tuple[ChinaAuthenticationResult, tuple[ChinaVehicle, ...] | None]:
        partial_candidate = _without_downstream(candidate)
        try:
            response = await self._send_locked(
                self._build_g_app_request(
                    operation="refresh_token",
                    url=_REFRESH_URL,
                    logical_body={
                        "token": candidate.g_token,
                        "refreshToken": candidate.g_refresh_token,
                    },
                    state=candidate,
                    encrypt_body=True,
                ),
                deadline=deadline,
            )
            data = _decode_g_app_envelope(response, operation="refresh_token")
            refreshed = _parse_g_app_state(
                data,
                base=candidate,
                credentials=credentials,
                allow_fallback=True,
                operation="refresh_token",
            )
        except _ChinaRiskControlError:
            return ChinaRiskControlRequired(state=partial_candidate), None
        except GwmAuthenticationError:
            if not allow_sms_login:
                raise
            empty = ChinaAuthState.for_credentials(credentials)
            return await self._sms_continuation(
                credentials,
                empty,
                verification_code=verification_code,
                deadline=deadline,
            )
        return await self._initialize_and_validate(credentials, refreshed, deadline=deadline)

    async def _sms_continuation(
        self,
        credentials: ChinaCredentials,
        candidate: ChinaAuthState,
        *,
        verification_code: str | None,
        deadline: _Deadline,
    ) -> tuple[ChinaAuthenticationResult, tuple[ChinaVehicle, ...] | None]:
        if verification_code is None:
            now = self._read_clock(operation="request_verification")
            requested_at = candidate.verification_requested_at
            throttled = (
                requested_at is not None
                and timedelta(0) <= now - requested_at < _VERIFICATION_INTERVAL
            )
            if throttled:
                return ChinaVerificationRequired(
                    state=candidate,
                    code_requested=False,
                ), None
            try:
                response = await self._send_locked(
                    self._build_g_app_request(
                        operation="request_verification",
                        url=_SMS_REQUEST_URL,
                        logical_body={"phone": credentials.phone, "flag": "LOGIN"},
                        state=candidate,
                        encrypt_body=True,
                    ),
                    deadline=deadline,
                )
                _decode_g_app_envelope(response, operation="request_verification")
            except _ChinaRiskControlError:
                return ChinaRiskControlRequired(state=candidate), None
            self._consumed_verification_bindings.discard(credentials.account_binding)
            return ChinaVerificationRequired(
                state=replace(candidate, verification_requested_at=now),
                code_requested=True,
            ), None

        if credentials.account_binding in self._consumed_verification_bindings:
            return ChinaVerificationRequired(
                state=candidate,
                code_requested=False,
            ), None
        request = self._build_g_app_request(
            operation="login",
            url=_SMS_LOGIN_URL,
            logical_body={
                "code": verification_code,
                "phone": credentials.phone,
                "deviceToken": "",
            },
            state=candidate,
            encrypt_body=True,
        )
        self._consumed_verification_bindings.add(credentials.account_binding)
        try:
            response = await self._send_locked(
                request,
                deadline=deadline,
            )
            data = _decode_g_app_envelope(response, operation="login")
            partial = _parse_g_app_state(
                data,
                base=ChinaAuthState.for_credentials(credentials),
                credentials=credentials,
                allow_fallback=False,
                operation="login",
            )
        except _ChinaRiskControlError:
            return ChinaRiskControlRequired(state=candidate), None
        except GwmAuthenticationError:
            return ChinaVerificationRequired(
                state=replace(candidate, verification_requested_at=None),
                code_requested=False,
                code_rejected=True,
            ), None
        return await self._initialize_and_validate(credentials, partial, deadline=deadline)

    async def _initialize_and_validate(
        self,
        credentials: ChinaCredentials,
        partial: ChinaAuthState,
        *,
        deadline: _Deadline,
    ) -> tuple[ChinaAuthenticationResult, tuple[ChinaVehicle, ...] | None]:
        partial = _without_downstream(partial)
        if not partial.has_g_app:
            raise GwmSchemaError(operation="login")
        missing: list[str] = []
        if partial.sso_token is None and partial.pt_token is None:
            missing.append("bean_tech:configuration_error")
        if partial.sso_token is None:
            missing.append("auto_ai:configuration_error")
        if missing:
            return ChinaInitializationRequired(state=partial, failures=tuple(missing)), None

        bean_result: Mapping[str, object] | None = None
        auto_result: Mapping[str, object] | None = None
        failures: list[str] = []
        risk_control = False
        try:
            async with asyncio.TaskGroup() as group:
                bean_task = group.create_task(
                    self._initialize_service(
                        "bean_tech",
                        credentials=credentials,
                        partial=partial,
                        deadline=deadline,
                    )
                )
                auto_task = group.create_task(
                    self._initialize_service(
                        "auto_ai",
                        credentials=credentials,
                        partial=partial,
                        deadline=deadline,
                    )
                )
        except* _ChinaRiskControlError:
            risk_control = True
        except* GwmClientError as group_error:
            failures.extend(_initialization_failure_labels(group_error))
        except* Exception:
            failures.append("initialization:network_error")
        if risk_control:
            return ChinaRiskControlRequired(state=partial), None
        if failures:
            return ChinaInitializationRequired(
                state=partial,
                failures=tuple(sorted(set(failures))),
            ), None
        bean_result = bean_task.result()
        auto_result = auto_task.result()
        try:
            complete = _apply_platform_results(
                partial,
                bean_result=bean_result,
                auto_result=auto_result,
            )
        except GwmClientError as error:
            return ChinaInitializationRequired(
                state=partial,
                failures=(_initialization_failure_label(error),),
            ), None
        try:
            vehicles = await self._acquire_vehicles_for_state(complete, deadline=deadline)
        except _ChinaRiskControlError:
            return ChinaRiskControlRequired(state=partial), None
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            return ChinaInitializationRequired(
                state=partial,
                failures=(_discovery_failure_label(error),),
            ), None
        except Exception:
            return ChinaInitializationRequired(
                state=partial,
                failures=("discovery:network_error",),
            ), None
        return ChinaAuthenticated(state=complete), vehicles

    async def _initialize_service(
        self,
        service: _ChinaService,
        *,
        credentials: ChinaCredentials,
        partial: ChinaAuthState,
        deadline: _Deadline,
    ) -> Mapping[str, object]:
        operation = "initialize_bean_tech" if service == "bean_tech" else "initialize_auto_ai"
        for attempt in range(1, _MAX_INIT_ATTEMPTS + 1):
            request = (
                self._build_bean_tech_login_request(credentials, partial)
                if service == "bean_tech"
                else self._build_auto_ai_login_request(credentials, partial)
            )
            try:
                response = await self._send_locked(request, deadline=deadline)
                data = (
                    _decode_g_app_envelope(response, operation=operation)
                    if service == "bean_tech"
                    else _decode_auto_ai_envelope(response, operation=operation)
                )
                if not isinstance(data, Mapping):
                    raise GwmSchemaError(operation=operation)
                return data
            except GwmClientError as error:
                if attempt >= _MAX_INIT_ATTEMPTS or not _retryable_initialization_error(error):
                    raise
                await self._sleep_before_retry(deadline, operation=operation)
        raise GwmProtocolError(operation=operation)  # pragma: no cover

    async def _sleep_before_retry(self, deadline: _Deadline, *, operation: str) -> None:
        loop = asyncio.get_running_loop()
        if deadline.remaining(loop.time()) <= _INIT_RETRY_SECONDS:
            raise GwmDeadlineExceededError(operation=operation)
        try:
            await self._sleeper(_INIT_RETRY_SECONDS)
        except asyncio.CancelledError:
            raise
        except GwmClientError:
            raise
        except Exception:
            raise GwmNetworkError(operation=operation) from None
        if deadline.remaining(loop.time()) <= 0:
            raise GwmDeadlineExceededError(operation=operation)

    async def _run_read[T](
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
        deadline = _Deadline(loop.time() + total)
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
        except GwmAuthenticationError as error:
            self._revoke_session()
            raise _sanitized_error(error) from None
        except GwmClientError as error:
            raise _sanitized_error(error) from None
        except Exception:
            raise GwmNetworkError(operation=operation) from None

    async def _acquire_current_vehicles_locked(
        self,
        deadline: _Deadline,
    ) -> tuple[ChinaVehicle, ...]:
        state = self._required_session(operation="acquire_vehicles")
        self._vehicles = {}
        return await self._acquire_vehicles_for_state(state, deadline=deadline)

    async def _acquire_vehicles_for_state(
        self,
        state: ChinaAuthState,
        *,
        deadline: _Deadline,
    ) -> tuple[ChinaVehicle, ...]:
        response = await self._send_locked(
            self._build_g_app_request(
                operation="acquire_vehicles",
                url=_DISCOVERY_URL,
                logical_body={"vehicleVersion": 13},
                state=state,
                encrypt_body=False,
            ),
            deadline=deadline,
        )
        try:
            data = _decode_g_app_envelope(response, operation="acquire_vehicles")
            value = _property(data, "acquireVehiclesList") if isinstance(data, Mapping) else None
            if value is None:
                value = data
            return _parse_vehicles(value)
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation="acquire_vehicles") from None

    async def _get_last_status_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        deadline: _Deadline,
    ) -> ChinaVehicleStatus:
        state = self._required_session(operation="get_last_status")
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation="get_last_status")
        platform = None if vehicle.platform is None else vehicle.platform.strip().casefold()
        if platform not in {"navinfo", "beantech"}:
            raise GwmRoutePolicyError(operation="get_last_status")
        request = (
            self._build_auto_ai_request(
                operation="get_last_status",
                state=state,
                function="GW.M.GET_VEHICLE_STATE",
                body={"vin": vehicle.identifier.value},
                url=_AUTO_AI_DIRECT,
                include_token=True,
            )
            if platform == "navinfo"
            else self._build_bean_tech_status_request(state, vehicle.identifier)
        )
        response = await self._send_locked(
            request,
            deadline=deadline,
        )
        try:
            if platform == "navinfo":
                body = _decode_auto_ai_envelope(response, operation="get_last_status")
                key = vehicle.identifier.value.casefold()
                if key not in self._written_charging_plan_vins:
                    self._charging_plans[key] = _parse_china_charging_plan(
                        body,
                        identifier=vehicle.identifier,
                        now=self._read_clock(operation="get_last_status"),
                    )
                mapped = map_china_status(
                    body,
                    identifier=vehicle.identifier,
                    vehicle_id=vehicle.vehicle_id,
                    network_type=vehicle.network_type,
                    tank_capacity=vehicle.tank_capacity,
                )
            else:
                body = _decode_g_app_envelope(response, operation="get_last_status")
                mapped = map_bean_tech_status(
                    body,
                    identifier=vehicle.identifier,
                    vehicle_id=vehicle.vehicle_id,
                )
            return ChinaVehicleStatus(
                device_id=mapped.device_id,
                acquisition_time_ms=mapped.acquisition_time_ms,
                update_time_ms=mapped.update_time_ms,
                latitude=mapped.latitude,
                longitude=mapped.longitude,
                items=mapped.items,
            )
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation="get_last_status") from None

    async def _get_charging_plan_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        deadline: _Deadline,
    ) -> ChargingPlanInfo:
        operation: Literal["get_charging_plan"] = "get_charging_plan"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "navinfo":
            raise GwmRoutePolicyError(operation=operation)
        cached = self._charging_plans.get(identifier.value.casefold())
        if cached is not None:
            return cached
        response = await self._send_locked(
            self._build_auto_ai_request(
                operation=operation,
                state=state,
                function="GW.M.GET_VEHICLE_STATE",
                body={"vin": identifier.value},
                url=_AUTO_AI_DIRECT,
                include_token=True,
            ),
            deadline=deadline,
        )
        try:
            body = _decode_auto_ai_envelope(response, operation=operation)
            result = _parse_china_charging_plan(
                body,
                identifier=identifier,
                now=self._read_clock(operation=operation),
            )
            self._charging_plans[identifier.value.casefold()] = result
            return result
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

    async def _set_charging_plan_locked(
        self,
        command: ChargingPlanCommand,
        *,
        deadline: _Deadline,
    ) -> None:
        operation: Literal["set_charging_plan"] = "set_charging_plan"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(command.identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "navinfo":
            raise GwmRoutePolicyError(operation=operation)
        if state.auto_ai_token_id is None or state.auto_ai_user_id is None:
            raise GwmAuthenticationError(operation=operation)
        body = {
            "flag": 1,
            "signStr": hashlib.md5(
                (command.identifier.value + state.auto_ai_token_id).encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest(),
            "userId": state.auto_ai_user_id,
            "userType": "0",
            "vin": command.identifier.value,
            "chargeingMode": "0" if command.enable else "1",
            "chargingStartTime": _china_clock_time(command.start_time_ms),
            "chargingEndTime": _china_clock_time(command.end_time_ms),
            "repeatTimes": _china_repeat_times(command),
        }
        response = await self._send_locked(
            self._build_auto_ai_request(
                operation=operation,
                state=state,
                function="GW.M.SEND_CHARGE_SETTINGS_WEEKLY",
                body=body,
                url=_AUTO_AI_DIRECT,
                include_token=True,
            ),
            deadline=deadline,
        )
        _decode_auto_ai_envelope(response, operation=operation)
        key = command.identifier.value.casefold()
        if command.enable:
            assert command.start_time_ms is not None
            assert command.end_time_ms is not None
            result = ChargingPlanInfo(
                (
                    ChargingPlanItem(
                        plan_id=_china_stable_plan_id(command.identifier),
                        plan_type="0",
                        start_time_ms=command.start_time_ms,
                        end_time_ms=command.end_time_ms,
                        weeks=_china_repeat_times(command),
                    ),
                )
            )
        else:
            result = ChargingPlanInfo()
        self._charging_plans[key] = result
        self._written_charging_plan_vins.add(key)

    async def _send_climate_command_locked(
        self,
        command: ClimateCommand,
        *,
        deadline: _Deadline,
    ) -> RemoteCommandAcceptance:
        operation: Literal["send_climate_command"] = "send_climate_command"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(command.identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation=operation)
        platform = None if vehicle.platform is None else vehicle.platform.strip().casefold()
        if platform == "beantech":
            if command.mode != "off" and not 17 <= command.temperature <= 31:
                raise GwmConfigurationError(operation=operation)
            control_type, command_body = _bean_tech_climate_control(command)
            return await self._send_bean_tech_control(
                state,
                command.identifier,
                operation=operation,
                commands=[(control_type, command_body)],
                deadline=deadline,
            )
        if platform != "navinfo":
            raise GwmRoutePolicyError(operation=operation)
        if state.auto_ai_token_id is None or state.auto_ai_user_id is None:
            raise GwmAuthenticationError(operation=operation)
        if command.mode != "off" and not 17 <= command.temperature <= 31:
            raise GwmConfigurationError(operation=operation)
        body: dict[str, object] = {
            "flag": 1,
            "signStr": hashlib.md5(
                (command.identifier.value + state.auto_ai_token_id).encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest(),
            "userId": state.auto_ai_user_id,
            "userType": "0",
            "vin": command.identifier.value,
        }
        if command.mode == "off":
            function = "GW.M.SEND_COMMON_COMMAND"
            body["cmdCode"] = 7
        else:
            function = "GW.M.SET_AND_OPEN_COMMAND"
            body["cmdCode"] = 6
            body["airParams"] = {
                "engineControl": 1,
                "runTime": command.operation_time_minutes,
                "temperature": command.temperature,
            }
        response = await self._send_locked(
            self._build_auto_ai_request(
                operation=operation,
                state=state,
                function=function,
                body=body,
                url=_AUTO_AI_DIRECT,
                include_token=True,
            ),
            deadline=deadline,
        )
        try:
            result = _decode_auto_ai_envelope(response, operation=operation)
            command_id = _scalar_text(_property(result, "transactionId"))
            if (
                command_id is None
                or not command_id
                or len(command_id) > 512
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in command_id)
            ):
                raise ValueError("command_acceptance_invalid")
            acceptance = RemoteCommandAcceptance(command_id)
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None
        if command.mode != "off":
            try:
                config_response = await self._send_locked(
                    self._build_navinfo_climate_config_request(
                        state,
                        command.identifier,
                        operation_time_minutes=command.operation_time_minutes,
                        temperature=command.temperature,
                    ),
                    deadline=deadline,
                )
                _decode_g_app_envelope(config_response, operation=operation)
            except GwmClientError as err:
                # The physical command already has a provider transaction ID. Do not
                # discard that ID, because the HA command journal must still poll it.
                _LOGGER.warning(
                    "NavInfo climate command was accepted but its companion "
                    "configuration request failed (%s)",
                    type(err).__name__,
                )
        return acceptance

    async def _send_lock_window_command_locked(
        self,
        command: DoorLockCommand | CloseWindowsCommand,
        *,
        operation: Literal["send_lock_command", "send_close_windows_command"],
        command_code: int,
        deadline: _Deadline,
    ) -> RemoteCommandAcceptance:
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(command.identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation=operation)
        platform = None if vehicle.platform is None else vehicle.platform.strip().casefold()
        if platform not in {"navinfo", "beantech"}:
            raise GwmRoutePolicyError(operation=operation)

        if platform == "beantech":
            control_type, command_body = _bean_tech_lock_window_control(command_code)
            return await self._send_bean_tech_control(
                state,
                command.identifier,
                operation=operation,
                commands=[(control_type, command_body)],
                deadline=deadline,
            )

        if state.auto_ai_token_id is None or state.auto_ai_user_id is None:
            raise GwmAuthenticationError(operation=operation)
        body = {
            "flag": 1,
            "signStr": hashlib.md5(
                (command.identifier.value + state.auto_ai_token_id).encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest(),
            "userId": state.auto_ai_user_id,
            "userType": "0",
            "vin": command.identifier.value,
            "cmdCode": command_code,
        }
        response = await self._send_locked(
            self._build_auto_ai_request(
                operation=operation,
                state=state,
                function="GW.M.SEND_COMMON_COMMAND",
                body=body,
                url=_AUTO_AI_DIRECT,
                include_token=True,
            ),
            deadline=deadline,
        )
        try:
            result = _decode_auto_ai_envelope(response, operation=operation)
            command_id = _scalar_text(_property(result, "transactionId"))
            if (
                command_id is None
                or not command_id
                or len(command_id) > 512
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in command_id)
            ):
                raise ValueError("command_acceptance_invalid")
            return RemoteCommandAcceptance(command_id)
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

    async def _send_bean_tech_control(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
            "send_climate_command",
            "set_bean_tech_battery_heating_appointment",
            "set_bean_tech_charge_soc",
        ],
        commands: Sequence[tuple[str, Mapping[str, object] | None]],
        send_type: int = 0,
        deadline: _Deadline,
    ) -> RemoteCommandAcceptance:
        try:
            sequence_number = self._sequence_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if (
            not isinstance(sequence_number, str)
            or _BEAN_TECH_SEQUENCE.fullmatch(sequence_number) is None
        ):
            raise GwmConfigurationError(operation=operation)

        if self._bean_tech_security_password is None:
            # The legacy T5 path carries exactly one command with sendType 0.
            # Multi-command requests (e.g. one-touch comfort off) require the
            # PIN-gated timely path, so fail closed when no PIN is configured.
            if send_type != 0 or len(commands) != 1:
                raise GwmConfigurationError(operation=operation)
            control_type, command_body = commands[0]
            request = self._build_bean_tech_command_request(
                state,
                identifier,
                sequence_number=sequence_number,
                operation=operation,
                control_type=control_type,
                command_body=command_body,
            )
        else:
            security_token: str | None = None
            if any(
                control_type not in _BEAN_TECH_PIN_EXEMPT_CONTROL_TYPES
                for control_type, _command_body in commands
            ):
                security_token = await self._generate_bean_tech_security_token(
                    state,
                    identifier,
                    operation=operation,
                    deadline=deadline,
                )
            request = self._build_bean_tech_timely_request_for_commands(
                state,
                identifier,
                sequence_number=sequence_number,
                operation=operation,
                commands=commands,
                send_type=send_type,
                security_token=security_token,
            )

        response = await self._send_locked(request, deadline=deadline)
        _decode_g_app_envelope(response, operation=operation)
        return RemoteCommandAcceptance(sequence_number)

    async def _send_vehicle_control_command_locked(
        self,
        command: ChinaVehicleControlCommand,
        *,
        deadline: _Deadline,
    ) -> RemoteCommandAcceptance:
        operation: Literal["send_vehicle_control_command"] = (
            "send_vehicle_control_command"
        )
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(command.identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation=operation)
        platform = (vehicle.platform or "").strip().casefold()
        if platform not in {"navinfo", "beantech"}:
            raise GwmRoutePolicyError(operation=operation)

        if platform == "beantech":
            if command.action not in BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS:
                raise GwmRoutePolicyError(operation=operation)
            if command.action == "comfort_off":
                return await self._send_bean_tech_control(
                    state,
                    command.identifier,
                    operation=operation,
                    commands=_bean_tech_comfort_off_commands(),
                    send_type=1,
                    deadline=deadline,
                )
            control_type, command_body = _bean_tech_vehicle_control(command)
            return await self._send_bean_tech_control(
                state,
                command.identifier,
                operation=operation,
                commands=[(control_type, command_body)],
                deadline=deadline,
            )

        if command.action not in NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS:
            raise GwmRoutePolicyError(operation=operation)

        if state.auto_ai_token_id is None or state.auto_ai_user_id is None:
            raise GwmAuthenticationError(operation=operation)
        command_code, function = _navinfo_vehicle_control(command)
        if command.action == "force_refresh":
            body: dict[str, object] = {"vin": command.identifier.value}
        else:
            body = {
                "flag": 1,
                "signStr": hashlib.md5(
                    (command.identifier.value + state.auto_ai_token_id).encode("utf-8"),
                    usedforsecurity=False,
                ).hexdigest(),
                "userId": state.auto_ai_user_id,
                "userType": "0",
                "vin": command.identifier.value,
            }
        if command_code is not None:
            body["cmdCode"] = command_code
        if command.action == "remote_start":
            body["engineParams"] = {
                "runTime": command.run_time_minutes or 15,
            }
        elif command.action in {"sunroof_full", "sunroof_half", "sunroof_tilt"}:
            body["openAngle"] = {
                "sunroof_full": 10,
                "sunroof_half": 5,
                "sunroof_tilt": 11,
            }[command.action]
        response = await self._send_locked(
            self._build_auto_ai_request(
                operation=operation,
                state=state,
                function=function,
                body=body,
                url=_AUTO_AI_DIRECT,
                include_token=True,
            ),
            deadline=deadline,
        )
        try:
            result = _decode_auto_ai_envelope(response, operation=operation)
            command_id = _scalar_text(_property(result, "transactionId"))
            if (
                command_id is None
                or not command_id
                or len(command_id) > 512
                or any(
                    ord(character) < 0x21 or ord(character) > 0x7E
                    for character in command_id
                )
            ):
                raise ValueError("command_acceptance_invalid")
            return RemoteCommandAcceptance(command_id)
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

    async def _get_remote_command_results_locked(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        msg_type: Literal["remote", "charge"],
        deadline: _Deadline,
    ) -> tuple[RemoteCommandResultItem, ...]:
        operation = "get_remote_command_result"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None:
            raise GwmRoutePolicyError(operation=operation)
        platform = (vehicle.platform or "").strip().casefold()
        if platform not in {"navinfo", "beantech"}:
            raise GwmRoutePolicyError(operation=operation)
        request = (
            self._build_navinfo_result_request(state, identifier, command_id)
            if platform == "navinfo"
            else self._build_bean_tech_result_request(
                state, identifier, command_id, msg_type=msg_type
            )
        )
        response = await self._send_locked(
            request,
            deadline=deadline,
        )
        try:
            data = _decode_g_app_envelope(response, operation=operation)
            return (
                _parse_navinfo_command_results(data, command_id=command_id)
                if platform == "navinfo"
                else _parse_bean_tech_command_results(data, command_id=command_id)
            )
        except GwmClientError:
            raise
        except (RecursionError, OverflowError, TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

    async def _get_remote_command_records_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        page_num: int,
        page_size: int,
        deadline: _Deadline,
    ) -> Mapping[str, object]:
        operation = "get_remote_command_records"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_records_request(
                state,
                identifier,
                page_num=page_num,
                page_size=page_size,
            ),
            deadline=deadline,
        )
        data = _decode_g_app_envelope(response, operation=operation)
        if not isinstance(data, Mapping):
            raise GwmSchemaError(operation=operation)
        return cast(Mapping[str, object], data)

    async def _get_bean_tech_charge_setting_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        deadline: _Deadline,
    ) -> Mapping[str, object]:
        operation = "get_bean_tech_charge_setting"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_charge_setting_request(state, identifier),
            deadline=deadline,
        )
        data = _decode_g_app_envelope(response, operation=operation)
        if not isinstance(data, Mapping):
            raise GwmSchemaError(operation=operation)
        return cast(Mapping[str, object], data)

    async def _set_bean_tech_charging_mode_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        deadline: _Deadline,
    ) -> str:
        operation = "set_bean_tech_charging_mode"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)

        current = await self._get_bean_tech_charge_setting_locked(
            identifier, deadline=deadline
        )
        charge_set_param = _property(current, "chargeSetParam")
        if not isinstance(charge_set_param, Mapping):
            raise GwmSchemaError(operation=operation)
        try:
            charge_strategy = _bean_tech_charge_strategy(current)
        except (TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

        try:
            sequence_number = self._sequence_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if (
            not isinstance(sequence_number, str)
            or _BEAN_TECH_SEQUENCE.fullmatch(sequence_number) is None
        ):
            raise GwmConfigurationError(operation=operation)

        response = await self._send_locked(
            self._build_bean_tech_charge_setting_write_request(
                state,
                identifier,
                sequence_number=sequence_number,
                charge_strategy=charge_strategy,
                charge_set_param=charge_set_param,
                charging_mode=0 if enable else 1,
            ),
            deadline=deadline,
        )
        _decode_g_app_envelope(response, operation=operation)
        return sequence_number

    async def _get_bean_tech_battery_heating_appointment_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        deadline: _Deadline,
    ) -> bool:
        operation = "get_bean_tech_battery_heating_appointment"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_config_query_request(state, identifier),
            deadline=deadline,
        )
        data = _decode_g_app_envelope(response, operation=operation)
        if not isinstance(data, list) or not data or not isinstance(data[0], Mapping):
            raise GwmSchemaError(operation=operation)
        cmd_content = data[0].get("cmdContent")
        if not isinstance(cmd_content, Mapping):
            raise GwmSchemaError(operation=operation)
        switch_type = cmd_content.get("switchType")
        if switch_type not in {0, 1} and switch_type not in {"0", "1"}:
            raise GwmSchemaError(operation=operation)
        return int(switch_type) == 1

    async def _set_bean_tech_battery_heating_appointment_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        use_car_time_ms: int | None,
        deadline: _Deadline,
    ) -> str:
        operation = "set_bean_tech_battery_heating_appointment"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        if enable and (
            isinstance(use_car_time_ms, bool)
            or not isinstance(use_car_time_ms, int)
            or use_car_time_ms <= 0
        ):
            raise GwmConfigurationError(operation=operation)
        sequence_number = self._bean_tech_sequence(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_battery_heating_appointment_request(
                state,
                identifier,
                sequence_number=sequence_number,
                enable=enable,
                use_car_time_ms=use_car_time_ms,
            ),
            deadline=deadline,
        )
        _decode_g_app_envelope(response, operation=operation)
        return sequence_number

    async def _set_bean_tech_charge_soc_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        percent: int,
        deadline: _Deadline,
    ) -> str:
        operation = "set_bean_tech_charge_soc"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        if (
            isinstance(percent, bool)
            or not isinstance(percent, int)
            or not 50 <= percent <= 100
            or percent % 10 != 0
        ):
            raise GwmConfigurationError(operation=operation)
        sequence_number = self._bean_tech_sequence(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_charge_soc_request(
                state,
                identifier,
                sequence_number=sequence_number,
                percent=percent,
            ),
            deadline=deadline,
        )
        _decode_g_app_envelope(response, operation=operation)
        return sequence_number

    async def _set_bean_tech_cabin_clean_appointment_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        time_ms: int,
        deadline: _Deadline,
    ) -> None:
        operation = "set_bean_tech_cabin_clean_appointment"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        if isinstance(time_ms, bool) or not isinstance(time_ms, int) or time_ms <= 0:
            raise GwmConfigurationError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_subscribe_request(state, identifier, time_ms=time_ms),
            deadline=deadline,
        )
        _decode_g_app_envelope(response, operation=operation)

    async def _set_bean_tech_charge_window_locked(
        self,
        identifier: VehicleIdentifier,
        *,
        start_time: str,
        end_time: str,
        deadline: _Deadline,
    ) -> str:
        operation = "set_bean_tech_charge_window"
        state = self._required_session(operation=operation)
        vehicle = self._vehicles.get(identifier.value.casefold())
        if vehicle is None or (vehicle.platform or "").strip().casefold() != "beantech":
            raise GwmRoutePolicyError(operation=operation)
        if _CLOCK_TIME.fullmatch(start_time) is None or _CLOCK_TIME.fullmatch(end_time) is None:
            raise GwmConfigurationError(operation=operation)

        current = await self._get_bean_tech_charge_setting_locked(
            identifier, deadline=deadline
        )
        charge_set_param = _property(current, "chargeSetParam")
        if not isinstance(charge_set_param, Mapping):
            raise GwmSchemaError(operation=operation)
        try:
            charge_strategy = _bean_tech_charge_strategy(current)
            charging_mode = _bean_tech_charging_mode(current)
        except (TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None

        new_param = dict(charge_set_param)
        custom_time = new_param.get("customTime")
        new_custom_time = dict(custom_time) if isinstance(custom_time, Mapping) else {}
        new_custom_time["startTime"] = start_time
        new_custom_time["endTime"] = end_time
        new_param["customTime"] = new_custom_time

        sequence_number = self._bean_tech_sequence(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_charge_setting_write_request(
                state,
                identifier,
                sequence_number=sequence_number,
                charge_strategy=charge_strategy,
                charge_set_param=new_param,
                charging_mode=charging_mode,
                operation="set_bean_tech_charge_window",
            ),
            deadline=deadline,
        )
        _decode_g_app_envelope(response, operation=operation)
        return sequence_number

    def _bean_tech_sequence(self, *, operation: str) -> str:
        try:
            sequence_number = self._sequence_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if (
            not isinstance(sequence_number, str)
            or _BEAN_TECH_SEQUENCE.fullmatch(sequence_number) is None
        ):
            raise GwmConfigurationError(operation=operation)
        return sequence_number

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

    def _build_g_app_request(
        self,
        *,
        operation: Literal["request_verification", "login", "refresh_token", "acquire_vehicles"],
        url: str,
        logical_body: Mapping[str, object],
        state: ChinaAuthState,
        encrypt_body: bool,
    ) -> _ChinaTransportRequest:
        logical_json = encode_dotnet_json(dict(logical_body))
        if encrypt_body:
            try:
                salt = self._salt_source()
                raw_body = encrypt_g_app(logical_json, salt=salt)
            except (TypeError, ValueError):
                raise GwmConfigurationError(operation=operation) from None
        else:
            raw_body = logical_json
        instant = self._read_clock(operation=operation)
        timestamp = str(_epoch_milliseconds(instant) // 1000 * 1000)
        authorization = state.bean_tech_access_token or ""
        signing_headers = {
            "Authorization": authorization,
            "SourceApp": "GWM",
            "SourceType": "ANDROID",
            "SourceAppVer": _SOURCE_APP_VERSION,
            "Timestamp": timestamp,
            "DeviceId": state.device_id,
            "AppId": "GWM-APP-ANDROID-1100018",
            "NoteId": DEFAULT_NOTE_ID,
        }
        headers: dict[str, str] = {}
        if state.g_token is not None:
            headers["G-TOKEN"] = state.g_token
        headers["Authorization"] = authorization
        if state.user_id is not None:
            headers["ssoId"] = state.user_id
        headers.update(
            {
                "SourceApp": "GWM",
                "SourceType": "ANDROID",
                "SourceAppVer": _SOURCE_APP_VERSION,
                "SourceAppCode": _SOURCE_APP_CODE,
                "Timestamp": timestamp,
                "DeviceId": state.device_id,
                "AppId": "GWM-APP-ANDROID-1100018",
            }
        )
        if state.bean_id is not None:
            headers["beanId"] = state.bean_id
        headers.update(
            {
                "NoteId": DEFAULT_NOTE_ID,
                "Sign": default_sign("POST", url, raw_body, signing_headers),
                "Accept-Encoding": "gzip",
                "User-Agent": _OFFICIAL_USER_AGENT,
                "Content-Type": "application/json; charset=UTF-8",
            }
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="g_app",
            method="POST",
            url=url,
            headers=headers,
            body=raw_body.encode("utf-8"),
        )

    def _build_bean_tech_login_request(
        self,
        credentials: ChinaCredentials,
        state: ChinaAuthState,
    ) -> _ChinaTransportRequest:
        operation: Literal["initialize_bean_tech"] = "initialize_bean_tech"
        raw_body = encode_dotnet_json(
            {
                "appType": 0,
                "deviceId": state.device_id,
                "phone": credentials.phone,
                "ssoId": state.user_id,
                "ssoToken": state.sso_token or state.pt_token,
            }
        )
        instant = self._read_clock(operation=operation)
        timestamp = str(_epoch_milliseconds(instant))
        try:
            nonce = self._nonce_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise GwmConfigurationError(operation=operation)
        path = "/app-api/api/v1.0/userAuth/loginSSOAccount"
        headers: dict[str, str] = {
            "bt-auth-appkey": BEAN_TECH_APP_KEY,
            "bt-auth-nonce": nonce,
            "bt-auth-timestamp": timestamp,
            "bt-auth-sign": bean_tech_sign(
                "POST",
                path,
                nonce,
                timestamp,
                "json=" + raw_body,
            ),
            "rs": "2",
            "appId": "097a7099af30d960",
            "brand": "10",
            "terminal": "GW_APP_GWM",
            "enterPriseId": "CC01",
        }
        if state.bean_id is not None:
            headers["beanId"] = state.bean_id
        headers.update(
            {
                "cVer": _SOURCE_APP_VERSION,
                "tenantId": "1",
                "operatorRole": "0",
                "Accept-Encoding": "gzip",
                "User-Agent": _OFFICIAL_USER_AGENT,
                "Content-Type": "application/json; charset=UTF-8",
            }
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_LOGIN_URL,
            headers=headers,
            body=raw_body.encode("utf-8"),
        )

    def _build_auto_ai_login_request(
        self,
        credentials: ChinaCredentials,
        state: ChinaAuthState,
    ) -> _ChinaTransportRequest:
        return self._build_auto_ai_request(
            operation="initialize_auto_ai",
            state=state,
            function="GW.M.APP_LOGIN",
            body={
                "appType": 0,
                "phone": credentials.phone,
                "pushId": "0",
                "pushKey": "0",
                "ssoid": state.user_id,
                "ssoTk": state.sso_token,
            },
            url=_AUTO_AI_LOGIN_URL,
            include_token=False,
        )

    def _build_bean_tech_status_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
    ) -> _ChinaTransportRequest:
        operation: Literal["get_last_status"] = "get_last_status"
        instant = self._read_clock(operation=operation)
        timestamp = str(_epoch_milliseconds(instant))
        try:
            nonce = self._nonce_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise GwmConfigurationError(operation=operation)
        bean_id = state.bean_tech_bean_id or state.bean_id
        if state.bean_tech_access_token is None or bean_id is None or state.auto_ai_token_id is None:
            raise GwmAuthenticationError(operation=operation)
        headers = {
            "bt-auth-appkey": BEAN_TECH_APP_KEY,
            "bt-auth-nonce": nonce,
            "bt-auth-timestamp": timestamp,
            "bt-auth-sign": bean_tech_sign(
                "GET",
                _BEAN_TECH_STATUS_PATH,
                nonce,
                timestamp,
                "vin=" + identifier.value,
            ),
            "rs": "2",
            "appId": "097a7099af30d960",
            "brand": "10",
            "terminal": "GW_APP_GWM",
            "enterPriseId": "CC01",
            "accessToken": state.bean_tech_access_token,
            "beanId": bean_id,
            "cVer": _SOURCE_APP_VERSION,
            "vin": identifier.value,
            "tenantId": "1",
            "operatorRole": "0",
            "tokenId": state.auto_ai_token_id,
            "Accept-Encoding": "gzip",
            "User-Agent": _OFFICIAL_USER_AGENT,
        }
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="GET",
            url=_BEAN_TECH_STATUS_URL + "?vin=" + identifier.encoded,
            headers=headers,
            body=None,
        )

    def _build_navinfo_result_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        command_id: str,
    ) -> _ChinaTransportRequest:
        operation: Literal["get_remote_command_result"] = "get_remote_command_result"
        instant = self._read_clock(operation=operation)
        timestamp = str(_epoch_milliseconds(instant))
        try:
            nonce = self._nonce_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise GwmConfigurationError(operation=operation)
        bean_id = state.bean_tech_bean_id or state.bean_id
        if state.bean_tech_access_token is None or bean_id is None or state.auto_ai_token_id is None:
            raise GwmAuthenticationError(operation=operation)
        query = (
            "seqNo="
            + quote(command_id, safe="", encoding="utf-8", errors="strict")
            + "&vin="
            + identifier.encoded
            + "&msgType=remote"
        )
        parameter = "msgtype=remote" + "seqno=" + command_id + "vin=" + identifier.value
        headers = {
            "bt-auth-appkey": BEAN_TECH_APP_KEY,
            "bt-auth-nonce": nonce,
            "bt-auth-timestamp": timestamp,
            "bt-auth-sign": bean_tech_sign(
                "GET",
                _NAVINFO_RESULT_PATH,
                nonce,
                timestamp,
                parameter,
            ),
            "rs": "2",
            "appId": "097a7099af30d960",
            "brand": "10",
            "terminal": "GW_APP_GWM",
            "enterPriseId": "CC01",
            "accessToken": state.bean_tech_access_token,
            "beanId": bean_id,
            "cVer": _SOURCE_APP_VERSION,
            "vin": identifier.value,
            "tenantId": "1",
            "operatorRole": "0",
            "tokenId": state.auto_ai_token_id,
            "Accept-Encoding": "gzip",
            "User-Agent": _OFFICIAL_USER_AGENT,
        }
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="GET",
            url=_NAVINFO_RESULT_URL + "?" + query,
            headers=headers,
            body=None,
        )

    def _build_bean_tech_command_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
            "send_climate_command",
            "set_bean_tech_battery_heating_appointment",
            "set_bean_tech_charge_soc",
        ],
        control_type: str,
        command_body: Mapping[str, object] | None,
    ) -> _ChinaTransportRequest:
        body = encode_dotnet_json(
            {
                "vin": identifier.value,
                "seqNo": sequence_number,
                "sendType": 0,
                "commands": [
                    {
                        "controlType": control_type,
                        "cmdBody": None if command_body is None else dict(command_body),
                    }
                ],
                "isSaveConfig": None,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_SEND_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_SEND_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_navinfo_climate_config_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation_time_minutes: int,
        temperature: int,
    ) -> _ChinaTransportRequest:
        operation: Literal["save_climate_config"] = "save_climate_config"
        body = encode_dotnet_json(
            {
                "configs": {
                    "cmdBody": {
                        "allowStartEng": 1,
                        "operationTime": operation_time_minutes * 60,
                        "temperature": temperature,
                    },
                    "controlType": "AIR_CONDITIONER_START",
                },
                "vin": identifier.value,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_NAVINFO_CLIMATE_CONFIG_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_NAVINFO_CLIMATE_CONFIG_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_timely_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
            "send_climate_command",
            "set_bean_tech_battery_heating_appointment",
            "set_bean_tech_charge_soc",
        ],
        control_type: str,
        command_body: Mapping[str, object] | None,
        security_token: str | None,
    ) -> _ChinaTransportRequest:
        return self._build_bean_tech_timely_request_for_commands(
            state,
            identifier,
            sequence_number=sequence_number,
            operation=operation,
            commands=[(control_type, command_body)],
            send_type=0,
            security_token=security_token,
        )

    def _build_bean_tech_timely_request_for_commands(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
            "send_climate_command",
            "set_bean_tech_battery_heating_appointment",
            "set_bean_tech_charge_soc",
        ],
        commands: Sequence[tuple[str, Mapping[str, object] | None]],
        send_type: int,
        security_token: str | None,
    ) -> _ChinaTransportRequest:
        command_list: list[dict[str, object]] = []
        for control_type, command_body in commands:
            command: dict[str, object] = {"controlType": control_type}
            if command_body is not None:
                command["cmdBody"] = dict(command_body)
            command_list.append(command)
        body = encode_dotnet_json(
            {
                "vin": identifier.value,
                "seqNo": sequence_number,
                "sendType": send_type,
                "commands": command_list,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_TIMELY_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        if security_token is not None:
            headers["securityToken"] = security_token
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_TIMELY_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_result_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        msg_type: Literal["remote", "charge"] = "remote",
    ) -> _ChinaTransportRequest:
        operation: Literal["get_remote_command_result"] = "get_remote_command_result"
        encoded_sequence = quote(command_id, safe="", encoding="utf-8", errors="strict")
        if self._bean_tech_security_password is None:
            headers = self._bean_tech_authenticated_headers(
                state,
                identifier,
                operation=operation,
                method="GET",
                path=_BEAN_TECH_RESULT_PATH,
                parameter="seqno=" + command_id,
            )
            return _ChinaTransportRequest(
                operation=operation,
                service="bean_tech",
                method="GET",
                url=_BEAN_TECH_RESULT_URL + "?seqNo=" + encoded_sequence,
                headers=headers,
                body=None,
            )

        encoded_vin = quote(identifier.value, safe="", encoding="utf-8", errors="strict")
        query = "seqNo=" + encoded_sequence + "&vin=" + encoded_vin + "&msgType=" + msg_type
        # The bt-auth-sign canonical string sorts query keys, lowercases them and
        # concatenates without separators (matches the retired add-on's
        # SendBeanTechGetAsync and the NavInfo result request).
        parameter = "msgtype=" + msg_type + "seqno=" + command_id + "vin=" + identifier.value
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="GET",
            path=_BEAN_TECH_TIMELY_RESULT_PATH,
            parameter=parameter,
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="GET",
            url=_BEAN_TECH_TIMELY_RESULT_URL + "?" + query,
            headers=headers,
            body=None,
        )

    def _build_bean_tech_security_token_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: str,
        security_password: str,
    ) -> _ChinaTransportRequest:
        body = encode_dotnet_json(
            {
                "securityPwd": security_password,
                "eventType": 2,
                "version": 1,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_SECURITY_TOKEN_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation="generate_security_token",
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_SECURITY_TOKEN_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_records_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        page_num: int,
        page_size: int,
    ) -> _ChinaTransportRequest:
        operation: Literal["get_remote_command_records"] = "get_remote_command_records"
        body = encode_dotnet_json(
            {
                "vin": identifier.value,
                "type": "SELF",
                "pageNum": page_num,
                "pageSize": page_size,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_RECORDS_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_RECORDS_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_charge_setting_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
    ) -> _ChinaTransportRequest:
        operation: Literal["get_bean_tech_charge_setting"] = "get_bean_tech_charge_setting"
        # Unlike the status endpoint (vin in the query), the charge/setting route
        # carries the VIN in the URL path, so the signed path includes it and the
        # canonical sign parameter is just ``strategy=5``.
        path = _BEAN_TECH_CHARGE_SETTING_PATH + "/" + identifier.value
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="GET",
            path=path,
            parameter="strategy=5",
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="GET",
            url=_BEAN_TECH_CHARGE_SETTING_URL + "/" + identifier.encoded + "?strategy=5",
            headers=headers,
            body=None,
        )

    def _build_bean_tech_charge_setting_write_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        charge_strategy: int,
        charge_set_param: Mapping[str, object],
        charging_mode: int,
        operation: Literal[
            "set_bean_tech_charging_mode", "set_bean_tech_charge_window"
        ] = "set_bean_tech_charging_mode",
    ) -> _ChinaTransportRequest:
        body = encode_dotnet_json(
            {
                "vin": identifier.value,
                "chargingMode": charging_mode,
                "chargeStrategy": charge_strategy,
                "chargeSetParam": dict(charge_set_param),
                "seqNo": sequence_number,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_CHARGE_SETTING_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_CHARGE_SETTING_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_config_query_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
    ) -> _ChinaTransportRequest:
        operation: Literal["get_bean_tech_battery_heating_appointment"] = (
            "get_bean_tech_battery_heating_appointment"
        )
        if state.auto_ai_user_id is None:
            raise GwmAuthenticationError(operation=operation)
        body = encode_dotnet_json(
            {
                "sendType": 0,
                "types": ["BATTERY_HEATING_APPOINTMENT"],
                "userId": state.auto_ai_user_id,
                "vin": identifier.value,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_CONFIG_QUERY_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_CONFIG_QUERY_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    def _build_bean_tech_battery_heating_appointment_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        enable: bool,
        use_car_time_ms: int | None,
    ) -> _ChinaTransportRequest:
        operation: Literal["set_bean_tech_battery_heating_appointment"] = (
            "set_bean_tech_battery_heating_appointment"
        )
        if enable:
            control_type = "BATTERY_HEATING_APPOINTMENT"
            command_body: Mapping[str, object] | None = {
                "useCarTime": use_car_time_ms
            }
        else:
            control_type = "BATTERY_TC_STOP"
            command_body = None
        return self._build_bean_tech_timely_request_for_commands(
            state,
            identifier,
            sequence_number=sequence_number,
            operation=operation,
            commands=[(control_type, command_body)],
            send_type=0,
            security_token=None,
        )

    def _build_bean_tech_charge_soc_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        percent: int,
    ) -> _ChinaTransportRequest:
        operation: Literal["set_bean_tech_charge_soc"] = "set_bean_tech_charge_soc"
        return self._build_bean_tech_timely_request_for_commands(
            state,
            identifier,
            sequence_number=sequence_number,
            operation=operation,
            commands=[("CTRL_CHARGE_SOC", {"chargeSoc": percent})],
            send_type=0,
            security_token=None,
        )

    def _build_bean_tech_subscribe_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        time_ms: int,
    ) -> _ChinaTransportRequest:
        operation: Literal["set_bean_tech_cabin_clean_appointment"] = (
            "set_bean_tech_cabin_clean_appointment"
        )
        body = encode_dotnet_json(
            {
                "commands": [
                    {
                        "controlType": "CABIN_CLEANING_START",
                        "cmdBody": {"operationTime": 60},
                    }
                ],
                "subscribeType": 0,
                "time": time_ms,
                "vin": identifier.value,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_SUBSCRIBE_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_SUBSCRIBE_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    async def _generate_bean_tech_security_token(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: str,
        deadline: _Deadline,
    ) -> str:
        password = self._bean_tech_security_password
        if password is None:
            raise GwmConfigurationError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_security_token_request(
                state,
                identifier,
                operation=operation,
                security_password=password,
            ),
            deadline=deadline,
        )
        result = _decode_g_app_envelope(response, operation=operation)
        # 服务器把 JWT 直接放在 data 上，不是 {"securityToken": ...} 对象。
        try:
            token = _scalar_text(result)
        except (TypeError, ValueError):
            raise GwmSchemaError(operation=operation) from None
        if token is None or not token or len(token) > 4096:
            raise GwmSchemaError(operation=operation)
        return token

    def _bean_tech_authenticated_headers(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: str,
        method: Literal["GET", "POST"],
        path: str,
        parameter: str,
    ) -> dict[str, str]:
        timestamp = str(_epoch_milliseconds(self._read_clock(operation=operation)))
        try:
            nonce = self._nonce_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise GwmConfigurationError(operation=operation)
        bean_id = state.bean_tech_bean_id or state.bean_id
        if state.bean_tech_access_token is None or bean_id is None or state.auto_ai_token_id is None:
            raise GwmAuthenticationError(operation=operation)
        return {
            "bt-auth-appkey": BEAN_TECH_APP_KEY,
            "bt-auth-nonce": nonce,
            "bt-auth-timestamp": timestamp,
            "bt-auth-sign": bean_tech_sign(method, path, nonce, timestamp, parameter),
            "rs": "2",
            "appId": "097a7099af30d960",
            "brand": "10",
            "terminal": "GW_APP_GWM",
            "enterPriseId": "CC01",
            "accessToken": state.bean_tech_access_token,
            "beanId": bean_id,
            "cVer": _SOURCE_APP_VERSION,
            "vin": identifier.value,
            "tenantId": "1",
            "operatorRole": "0",
            "tokenId": state.auto_ai_token_id,
            "Accept-Encoding": "gzip",
            "User-Agent": _OFFICIAL_USER_AGENT,
        }

    def _build_auto_ai_request(
        self,
        *,
        operation: Literal[
            "initialize_auto_ai",
            "get_last_status",
            "get_charging_plan",
            "set_charging_plan",
            "send_climate_command",
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
        ],
        state: ChinaAuthState,
        function: str,
        body: Mapping[str, object],
        url: str,
        include_token: bool,
    ) -> _ChinaTransportRequest:
        instant = self._read_clock(operation=operation)
        timestamp = str(_epoch_milliseconds(instant))
        token = state.auto_ai_token_id or ""
        wrapper = {
            "body": dict(body),
            "header": {
                "brandType": "gwm",
                "cVer": _SOURCE_APP_VERSION,
                "fn": function,
                "fv": "0202",
                "mobileId": state.device_id,
                "osType": "Android",
                "osVer": "",
                "rs": "2",
                "ts": format_china_timestamp(instant),
                "tk": token,
                "v": "1.0",
            },
        }
        payload = encode_dotnet_json(wrapper)
        full_url = url + "?p=" + quote(payload, safe="", encoding="utf-8", errors="strict")
        headers = {
            "v": "1.0",
            "cid": state.device_id,
            "client": "phone",
            "sign": auto_ai_sign(timestamp),
            "time": timestamp,
            "ckey": AUTO_AI_CKEY,
            "protocolVer": "2.1.2",
        }
        if include_token:
            headers["token"] = token
        headers.update(
            {
                "brandType": "GWM",
                "Accept-Encoding": "gzip",
                "User-Agent": _OFFICIAL_USER_AGENT,
            }
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="auto_ai",
            method="GET",
            url=full_url,
            headers=headers,
            body=None,
        )

    def _required_session(self, *, operation: str) -> ChinaAuthState:
        state = self._session
        if state is None or not state.complete:
            raise GwmAuthenticationError(operation=operation)
        return state

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

    def _install_if_revision(
        self,
        *,
        expected_revision: int,
        state: ChinaAuthState,
        vehicles: tuple[ChinaVehicle, ...],
    ) -> None:
        if self._session_revision == expected_revision:
            self._session = state
            self._vehicles = {vehicle.identifier.value.casefold(): vehicle for vehicle in vehicles}
            self._charging_plans = {}
            self._written_charging_plan_vins.clear()
            self._session_revision += 1

    def _clear_if_revision(self, *, expected_revision: int) -> None:
        if self._session_revision == expected_revision:
            self._revoke_session()

    def _revoke_session(self) -> None:
        self._session = None
        self._vehicles = {}
        self._charging_plans = {}
        self._written_charging_plan_vins.clear()
        self._session_revision += 1

    def _commit_vehicles(self, vehicles: tuple[ChinaVehicle, ...]) -> None:
        self._vehicles = {vehicle.identifier.value.casefold(): vehicle for vehicle in vehicles}
        discovered = set(self._vehicles)
        self._charging_plans = {
            key: value for key, value in self._charging_plans.items() if key in discovered
        }
        self._written_charging_plan_vins.intersection_update(discovered)


def _normalize_device_id(value: str) -> str:
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


def _valid_optional_secret(value: object) -> bool:
    return value is None or (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_SECRET_LENGTH
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _normalize_verification_code(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise GwmConfigurationError(operation="login")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > _MAX_VERIFICATION_CODE_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in normalized)
    ):
        raise GwmConfigurationError(operation="login")
    return normalized


def _without_downstream(state: ChinaAuthState) -> ChinaAuthState:
    return replace(
        state,
        bean_tech_access_token=None,
        bean_tech_refresh_token=None,
        bean_tech_sso_token=None,
        bean_tech_bean_id=None,
        auto_ai_token_id=None,
        auto_ai_user_id=None,
        auto_ai_gw_id=None,
    )


def _parse_g_app_state(
    data: object,
    *,
    base: ChinaAuthState,
    credentials: ChinaCredentials,
    allow_fallback: bool,
    operation: str,
) -> ChinaAuthState:
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation=operation)

    def selected(name: str, fallback: str | None, *refresh_aliases: str) -> str | None:
        value = _optional_session_text(_property(data, name))
        if value is None and allow_fallback:
            for alias in refresh_aliases:
                value = _optional_session_text(_property(data, alias))
                if value is not None:
                    break
        return fallback if value is None and allow_fallback else value

    try:
        result = replace(
            _without_downstream(base),
            account_binding=credentials.account_binding,
            device_id=credentials.device_id,
            g_token=selected("gToken", base.g_token, "token"),
            g_refresh_token=selected("gRefreshToken", base.g_refresh_token, "refreshToken"),
            sso_token=selected("ssoToken", base.sso_token),
            pt_token=selected("ptToken", base.pt_token),
            user_id=selected("userId", base.user_id),
            bean_id=selected("beanId", base.bean_id),
            verification_requested_at=None,
        )
    except (TypeError, ValueError):
        raise GwmSchemaError(operation=operation) from None
    if not result.has_g_app or result.sso_token is None or result.bean_id is None:
        raise GwmSchemaError(operation=operation)
    return result


def _apply_platform_results(
    partial: ChinaAuthState,
    *,
    bean_result: Mapping[str, object],
    auto_result: Mapping[str, object],
) -> ChinaAuthState:
    try:
        bean_tech_access_token = _required_session_text(
            bean_result,
            "accessToken",
            "initialize_bean_tech",
        )
        bean_tech_refresh_token = _optional_session_text(_property(bean_result, "refreshToken"))
        bean_tech_sso_token = _optional_session_text(_property(bean_result, "ssoToken"))
        bean_tech_bean_id = (
            _optional_session_text(_property(bean_result, "beanId")) or partial.bean_id
        )
    except (TypeError, ValueError):
        raise GwmSchemaError(operation="initialize_bean_tech") from None
    try:
        auto_ai_token_id = _required_session_text(auto_result, "tokenId", "initialize_auto_ai")
        auto_ai_user_id = _required_session_text(auto_result, "userId", "initialize_auto_ai")
        auto_ai_gw_id = (
            _optional_session_text(_property(auto_result, "gwid"))
            or _optional_session_text(_property(auto_result, "gwId"))
        )
    except (TypeError, ValueError):
        raise GwmSchemaError(operation="initialize_auto_ai") from None
    state = replace(
        partial,
        bean_tech_access_token=bean_tech_access_token,
        bean_tech_refresh_token=bean_tech_refresh_token,
        bean_tech_sso_token=bean_tech_sso_token,
        bean_tech_bean_id=bean_tech_bean_id,
        auto_ai_token_id=auto_ai_token_id,
        auto_ai_user_id=auto_ai_user_id,
        auto_ai_gw_id=auto_ai_gw_id,
    )
    if not state.complete:
        raise GwmSchemaError(operation="login")
    return state


def _required_session_text(data: object, name: str, operation: str) -> str:
    value = _optional_session_text(_property(data, name))
    if value is None:
        raise GwmSchemaError(operation=operation)
    return value


def _optional_session_text(value: object) -> str | None:
    if value is None:
        return None
    text = _scalar_text(value)
    if text is None or not _valid_optional_secret(text):
        raise ValueError("session_value_invalid")
    return text


def _parse_vehicles(value: object) -> tuple[ChinaVehicle, ...]:
    if not isinstance(value, list):
        raise ValueError("vehicle_schema_invalid")
    vehicles: list[ChinaVehicle] = []
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
            ChinaVehicle(
                identifier=VehicleIdentifier(vin),
                default_vehicle=_optional_bool(_property(item, "defaultVehicle"), default=False),
                app_show_series_name=_optional_vehicle_text(_property(item, "appShowSeriesName")),
                vehicle_nickname=_optional_vehicle_text(_property(item, "vehicleNick")),
                model_name=_optional_vehicle_text(_property(item, "modelName")),
                brand_name=_optional_vehicle_text(_property(item, "brandName")),
                other_brand_name=_optional_vehicle_text(_property(item, "otBrandName")),
                vehicle_type=_optional_vehicle_text(_property(item, "vtype")),
                vehicle_type_name=_optional_vehicle_text(_property(item, "vTypeName")),
                vehicle_id=_optional_vehicle_text(_property(item, "vehicleId")),
                platform=_optional_vehicle_text(_property(item, "belongPlatform")),
                network_type=_optional_int32(_property(item, "vehicleNetworkType")),
                tank_capacity=_optional_nonnegative_number(_property(item, "tankCapacity")),
            )
        )
    return tuple(vehicles)


def _parse_china_charging_plan(
    value: object,
    *,
    identifier: VehicleIdentifier,
    now: datetime,
) -> ChargingPlanInfo:
    """Synthesize AutoAI's weekly schedule as the shared charging-plan shape."""

    try:
        vehicle_status = _property(value, "vehicleSts")
        if vehicle_status is None:
            vehicle_status = value
        settings = _property(vehicle_status, "chargeSettings")
        mode = _scalar_text(_property(settings, "mode"))
        if not isinstance(settings, Mapping) or mode is None or not mode.strip() or mode == "1":
            return ChargingPlanInfo()
        start_text = _first_nonempty_scalar(
            _property(settings, "phoneStrtHourMin"),
            _property(settings, "discountStartTime"),
        )
        end_text = _first_nonempty_scalar(
            _property(settings, "phoneEndHourMin"),
            _property(settings, "discountEndTime"),
        )
        start_match = _CLOCK_TIME.fullmatch(start_text)
        end_match = _CLOCK_TIME.fullmatch(end_text)
        if start_match is None or end_match is None:
            return ChargingPlanInfo()
        local_now = now.astimezone(_CHINA_TIMEZONE)
        start_local = local_now.replace(
            hour=int(start_match.group(1)),
            minute=int(start_match.group(2)),
            second=0,
            microsecond=0,
        )
        end_local = local_now.replace(
            hour=int(end_match.group(1)),
            minute=int(end_match.group(2)),
            second=0,
            microsecond=0,
        )
        if end_local <= start_local:
            end_local += timedelta(days=1)
        repeat = _scalar_text(_property(settings, "repeatTimes"))
        if repeat is None or not repeat.strip():
            repeat = "".join(
                _china_day_enabled(settings, name)
                for name in (
                    "sundayUseTime",
                    "saturdayUseTime",
                    "fridayUseTime",
                    "thurdayUseTime",
                    "wednesdayUseTime",
                    "tuesdayUseTime",
                    "mondayUseTime",
                )
            )
        if len(repeat) > 64 or any(ord(character) < 0x20 for character in repeat):
            return ChargingPlanInfo()
        return ChargingPlanInfo(
            (
                ChargingPlanItem(
                    plan_id=_china_stable_plan_id(identifier),
                    plan_type="0",
                    start_time_ms=_epoch_milliseconds(start_local),
                    end_time_ms=_epoch_milliseconds(end_local),
                    weeks=repeat,
                ),
            )
        )
    except (OverflowError, TypeError, ValueError):
        return ChargingPlanInfo()


def _first_nonempty_scalar(*values: object) -> str:
    for value in values:
        text = _scalar_text(value)
        if text is not None and text.strip():
            return text
    return ""


def _china_day_enabled(settings: Mapping[object, object], name: str) -> str:
    raw = _property(settings, name)
    if type(raw) is bool:
        return "1" if raw else "0"
    value = _scalar_text(raw)
    return "0" if value is None or not value.strip() or value == "0" else "1"


def _china_stable_plan_id(identifier: VehicleIdentifier) -> int:
    return int(sha256_hex(identifier.value)[:15], 16)


def _china_clock_time(milliseconds: int | None) -> str:
    if milliseconds is None or milliseconds <= 0:
        return "00:00"
    instant = datetime.fromtimestamp(milliseconds / 1000, tz=UTC)
    return instant.astimezone(_CHINA_TIMEZONE).strftime("%H:%M")


def _china_repeat_times(command: ChargingPlanCommand) -> str:
    if not command.enable:
        return "0000000"
    if command.weeks is not None and len(command.weeks) == 7:
        return command.weeks
    if command.start_time_ms is None or command.start_time_ms <= 0:
        return "0000000"
    local = datetime.fromtimestamp(command.start_time_ms / 1000, tz=UTC).astimezone(
        _CHINA_TIMEZONE
    )
    auto_ai_index = {6: 0, 5: 1, 4: 2, 3: 3, 2: 4, 1: 5, 0: 6}[
        local.weekday()
    ]
    days = list("0000000")
    days[auto_ai_index] = "1"
    return "".join(days)


def _parse_navinfo_command_results(
    value: object,
    *,
    command_id: str,
) -> tuple[RemoteCommandResultItem, ...]:
    messages = _property(value, "messageList")
    if messages is None:
        return ()
    if not isinstance(messages, list):
        raise ValueError("command_result_invalid")
    results: list[RemoteCommandResultItem] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        message_data = _property(message, "messageData")
        if message_data is None:
            message_data = message
        if isinstance(message_data, str):
            if not message_data.strip():
                continue
            try:
                message_data = _decode_json_bytes(message_data.encode("utf-8"))
            except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
                continue
        if not isinstance(message_data, Mapping):
            continue
        transaction = _scalar_text(_property(message_data, "transactionId"))
        if transaction and transaction.casefold() != command_id.casefold():
            continue
        result_code = _scalar_text(_property(message_data, "resultCode"))
        if not result_code:
            continue
        normalized_code = "2000" if result_code in {"2", "3"} else result_code
        result_message = _scalar_text(_property(message_data, "resultMessage"))
        if not result_message and normalized_code == "2000":
            result_message = "Command is still running"
        results.append(
            RemoteCommandResultItem(
                command_id=command_id,
                remote_type=_scalar_text(_property(message, "messageType")),
                result_code=normalized_code,
                result_message=result_message,
            )
        )
    return tuple(results)


def _parse_bean_tech_command_results(
    value: object,
    *,
    command_id: str,
) -> tuple[RemoteCommandResultItem, ...]:
    # PIN-configured path hits the v3.0 result endpoint, which answers with
    # messageList[].messageData = {resultCode, resultMessage, transactionId, ...}.
    # resultCode "2"/"3" = still running, "0" = success. The seqNo query already
    # scopes the list to one command, so no transactionId correlation is applied.
    if isinstance(value, Mapping) and _property(value, "messageList") is not None:
        messages = _property(value, "messageList")
        if not isinstance(messages, list):
            raise ValueError("command_result_invalid")
        results: list[RemoteCommandResultItem] = []
        for message in messages:
            if not isinstance(message, Mapping):
                continue
            message_data = _property(message, "messageData")
            if message_data is None:
                message_data = message
            if isinstance(message_data, str):
                if not message_data.strip():
                    continue
                try:
                    message_data = _decode_json_bytes(message_data.encode("utf-8"))
                except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
                    continue
            if not isinstance(message_data, Mapping):
                continue
            result_code = _scalar_text(_property(message_data, "resultCode"))
            if not result_code:
                continue
            normalized_code = "2000" if result_code in {"2", "3"} else result_code
            result_message = _scalar_text(_property(message_data, "resultMessage"))
            if not result_message and normalized_code == "2000":
                result_message = "Command is still running"
            results.append(
                RemoteCommandResultItem(
                    command_id=command_id,
                    remote_type=_scalar_text(_property(message, "messageType")),
                    result_code=normalized_code,
                    result_message=result_message,
                )
            )
        return tuple(results)

    # No-PIN path still hits the legacy T5 result endpoint: a flat list (or a
    # resultList/list key) of {remoteType, resultCode, resultMsg}.
    candidates = value
    if isinstance(value, Mapping):
        candidates = _property(value, "resultList")
        if candidates is None:
            candidates = _property(value, "list")
    if candidates is None:
        return ()
    parsed = parse_remote_command_results(candidates, allow_integer_strings=True)
    return tuple(
        item
        if item.command_id
        else RemoteCommandResultItem(
            command_id=command_id,
            remote_type=item.remote_type,
            result_code=item.result_code,
            result_message=item.result_message,
        )
        for item in parsed
    )


def _bean_tech_lock_window_control(
    command_code: int,
) -> tuple[str, Mapping[str, object] | None]:
    if command_code == 1:
        return "VEHICLE_UNLOCK", None
    if command_code == 2:
        return "VEHICLE_LOCK", None
    if command_code == 3:
        return (
            "WINDOW_CLOSE",
            {
                "leftFront": 0,
                "leftBack": 0,
                "rightFront": 0,
                "rightBack": 0,
            },
        )
    raise ValueError("command_code_invalid")


def _navinfo_vehicle_control(
    command: ChinaVehicleControlCommand,
) -> tuple[int | None, str]:
    command_codes = {
        "remote_start": 15,
        "remote_stop": 16,
        "horn": 19,
        "flash_lights": 20,
        "horn_and_lights": 5,
        "tailgate_open": 17,
        "tailgate_close": 18,
        "sunroof_close": 28,
        "sunroof_tilt": 29,
        "sunroof_half": 29,
        "sunroof_full": 29,
        "cabin_purge": 34,
        "force_refresh": None,
    }
    return (
        command_codes[command.action],
        (
            "GW.M.SET_AND_OPEN_COMMAND"
            if command.action == "remote_start"
            else (
                "GW.M.REFRESH_VEHICLE_STATE"
                if command.action == "force_refresh"
                else "GW.M.SEND_COMMON_COMMAND"
            )
        ),
    )


def _bean_tech_vehicle_control(
    command: ChinaVehicleControlCommand,
) -> tuple[str, Mapping[str, object] | None]:
    if command.action == "remote_start":
        return (
            "ENGINE_START",
            {"operationTime": (command.run_time_minutes or 15) * 60},
        )
    if command.action == "remote_stop":
        return "ENGINE_STOP", None
    if command.action == "horn":
        return "WHISTLE", None
    if command.action == "flash_lights":
        return "FLASH", None
    if command.action == "horn_and_lights":
        return "WHISTLE_FLASH", None
    if command.action == "sunroof_close":
        return "SKYLIGNT_CLOSE", {"skyLight": 0}
    if command.action == "seat_heating_start":
        return (
            "SEAT_HEATING_START",
            {"leftFront": 3, "operationTime": 600},
        )
    if command.action == "seat_heating_stop":
        return (
            "SEAT_HEATING_STOP",
            {"leftFront": 0, "operationMode": 1},
        )
    if command.action == "seat_heating_start_passenger":
        return (
            "SEAT_HEATING_START",
            {"rightFront": 3, "operationTime": 600},
        )
    if command.action == "seat_heating_stop_passenger":
        return (
            "SEAT_HEATING_STOP",
            {"rightFront": 0, "operationMode": 1},
        )
    if command.action == "seat_ventilation_start":
        return (
            "SEAT_VENTILATION_START",
            {"leftFront": 3, "operationTime": 600},
        )
    if command.action == "seat_ventilation_stop":
        return (
            "SEAT_VENTILATION_STOP",
            {"leftFront": 0, "operationMode": 2},
        )
    if command.action == "seat_ventilation_start_passenger":
        return (
            "SEAT_VENTILATION_START",
            {"rightFront": 3, "operationTime": 600},
        )
    if command.action == "seat_ventilation_stop_passenger":
        return (
            "SEAT_VENTILATION_STOP",
            {"rightFront": 0, "operationMode": 2},
        )
    if command.action == "steering_wheel_heating":
        return "STEERING_WHEEL_HEATING", {"operationTime": 600}
    if command.action == "steering_wheel_heatless":
        return "STEERING_WHEEL_HEATLESS", None
    if command.action == "defrost_front_start":
        return "DEFROST_FRONT_START", {"operationTime": 900}
    if command.action == "defrost_front_stop":
        return "DEFROST_FRONT_STOP", None
    if command.action == "defrost_back_start":
        return "DEFROST_BACK_START", {"operationTime": 900}
    if command.action == "defrost_back_stop":
        return "DEFROST_BACK_STOP", None
    if command.action == "cabin_clean":
        return "CABIN_CLEANING_START", {"operationTime": 60}
    if command.action == "comfort_warm":
        return "COMFORT_MODE_CTRL", {"action": 1, "modeId": "4982234", "type": "1"}
    if command.action == "comfort_cool":
        return "COMFORT_MODE_CTRL", {"action": 1, "modeId": "4982235", "type": "2"}
    if command.action == "battery_gun_heat":
        return "BATTERY_GUN_HEAT_START", None
    if command.action == "battery_gun_heat_stop":
        return "BATTERY_GUN_HEAT_STOP", None
    if command.action == "battery_initiative_heat":
        return "BATTERY_INITIATIVE_HEAT_START", None
    if command.action == "battery_initiative_heat_stop":
        return "BATTERY_INITIATIVE_HEAT_STOP", None
    raise ValueError("vehicle_control_action_invalid")


def _bean_tech_comfort_off_commands() -> tuple[
    tuple[str, Mapping[str, object] | None], ...
]:
    """The multi-command BeanTech one-touch comfort off sequence.

    ``sendType=1`` tells the vehicle to treat the commands as one atomic
    operation. The retired add-on's ``SendBeanTechComfortOffAsync`` sent these
    exact four commands: air conditioning off, seat heating off, seat
    ventilation off, and steering-wheel heating off.
    """
    return (
        ("AIR_CONDITIONER_STOP", None),
        (
            "SEAT_HEATING_STOP",
            {"leftFront": 0, "operationMode": 1, "rightFront": 0},
        ),
        (
            "SEAT_VENTILATION_STOP",
            {"leftFront": 0, "operationMode": 2, "rightFront": 0},
        ),
        ("STEERING_WHEEL_HEATLESS", None),
    )


def _bean_tech_climate_control(
    command: ClimateCommand,
) -> tuple[str, Mapping[str, object] | None]:
    if command.mode == "off":
        return "AIR_CONDITIONER_STOP", None
    # BeanTech has no separate heat/cool distinction: "cool", "heat" and "auto"
    # all map to the automatic AIR_CONDITIONER_START command. ``allowStartEng``
    # is always 1 for BeanTech because its "auto" mode doubles as the app's
    # linked hybrid-engine-heating switch (the retired add-on's ``heatSwitch``).
    return (
        "AIR_CONDITIONER_START",
        {
            "allowStartEng": 1,
            "operationTime": command.operation_time_minutes * 60,
            "temperature": command.temperature,
        },
    )


def _bean_tech_charge_strategy(data: Mapping[str, object]) -> int:
    """Return the BeanTech ``chargeStrategy`` integer from a charge setting.

    The read must be complete before a write is attempted; a missing or
    non-numeric value raises so the caller aborts instead of guessing.
    """

    raw = _property(data, "chargeStrategy")
    if isinstance(raw, bool):
        raise ValueError("charge_strategy_invalid")
    if isinstance(raw, int):
        return raw
    text = _scalar_text(raw)
    if text is None or not text.strip():
        raise ValueError("charge_strategy_invalid")
    return int(text)


def _bean_tech_charging_mode(data: Mapping[str, object]) -> int:
    """Return the BeanTech ``chargingMode`` integer from a charge setting."""
    raw = _property(data, "chargingMode")
    if isinstance(raw, bool):
        raise ValueError("charging_mode_invalid")
    if isinstance(raw, int):
        return raw
    text = _scalar_text(raw)
    if text is None or not text.strip():
        raise ValueError("charging_mode_invalid")
    return int(text)


def _optional_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError("vehicle_schema_invalid")
    return value


def _optional_vehicle_text(value: object) -> str | None:
    if value is None:
        return None
    result = _scalar_text(value)
    if result is None or not result or len(result) > 512:
        raise ValueError("vehicle_schema_invalid")
    return result


def _optional_int32(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        digits = value[1:] if value[:1] in {"+", "-"} else value
        if not digits or not digits.isdecimal():
            raise ValueError("vehicle_schema_invalid")
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not -(1 << 31) <= value < 1 << 31:
        raise ValueError("vehicle_schema_invalid")
    return value


def _optional_nonnegative_number(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        result = float(value)
    except OverflowError:
        return None
    if not math.isfinite(result) or result < 0:
        return None
    return result


def _decode_g_app_envelope(response: _ChinaTransportResponse, *, operation: str) -> object:
    root = _decode_json_response(response, operation=operation)
    try:
        code = _scalar_text(_property(root, "code"))
    except (TypeError, ValueError):
        raise GwmSchemaError(operation=operation) from None
    if code is not None and code not in {"0", "000000", "200"}:
        if code == "1013":
            raise _ChinaRiskControlError(operation=operation, api_code=code)
        raise GwmApiError(operation=operation, api_code=code)
    data = _property(root, "data")
    if data is None:
        data = root
    if isinstance(data, str) and data.startswith("G_A("):
        try:
            data = _decode_json_bytes(decrypt_g_app(data).encode("utf-8"))
        except (RecursionError, OverflowError, UnicodeError, ValueError):
            raise GwmSchemaError(operation=operation) from None
    return data


def _decode_auto_ai_envelope(response: _ChinaTransportResponse, *, operation: str) -> object:
    root = _decode_json_response(response, operation=operation)
    if _property(root, "header") is None:
        unwrapped = _decode_g_app_envelope(response, operation=operation)
        if not isinstance(unwrapped, Mapping):
            raise GwmSchemaError(operation=operation)
        root = unwrapped
    header = _property(root, "header")
    if header is not None and not isinstance(header, Mapping):
        raise GwmSchemaError(operation=operation)
    try:
        code = _scalar_text(_property(header, "c")) if header is not None else None
    except (TypeError, ValueError):
        raise GwmSchemaError(operation=operation) from None
    if code is not None and code != "0":
        if code == "1013":
            raise _ChinaRiskControlError(operation=operation, api_code=code)
        raise GwmApiError(operation=operation, api_code=code)
    body = _property(root, "body")
    return root if body is None else body


def _decode_json_response(
    response: _ChinaTransportResponse,
    *,
    operation: str,
) -> Mapping[str, object]:
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


def _epoch_milliseconds(instant: datetime) -> int:
    utc = instant.astimezone(UTC)
    delta = utc - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 24 * 60 * 60) + delta.seconds) * 1000 + delta.microseconds // 1000


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _random_nonce() -> str:
    return sha256_hex(secrets.token_bytes(16).hex().upper())[:16]


def _random_bean_tech_sequence() -> str:
    return secrets.token_hex(16) + str(secrets.randbelow(9000) + 1000)


def _retryable_initialization_error(error: GwmClientError) -> bool:
    if type(error) is GwmNetworkError:
        return True
    if type(error) is not GwmHttpError:
        return False
    status = error.status
    return status is not None and status in _TRANSIENT_INIT_HTTP_STATUSES


def _initialization_failure_labels(group: BaseExceptionGroup[GwmClientError]) -> list[str]:
    return [_initialization_failure_label(error) for error in _flatten_client_errors(group)]


def _initialization_failure_label(error: GwmClientError) -> str:
    service = "bean_tech" if error.operation == "initialize_bean_tech" else "auto_ai"
    return _failure_label(service, error)


def _discovery_failure_label(error: GwmClientError) -> str:
    return _failure_label("discovery", error)


def _failure_label(prefix: str, error: GwmClientError) -> str:
    label = f"{prefix}:{error.category}"
    if type(error) is GwmApiError and error.api_code is not None:
        label += ":" + error.api_code
    elif type(error) is GwmHttpError and error.status is not None:
        label += ":" + str(error.status)
    return label


def _flatten_client_errors(group: BaseExceptionGroup[GwmClientError]) -> list[GwmClientError]:
    result: list[GwmClientError] = []
    for error in group.exceptions:
        if isinstance(error, BaseExceptionGroup):
            result.extend(_flatten_client_errors(error))
        elif isinstance(error, GwmClientError):
            result.append(error)
    return result


def _sanitized_error(error: GwmClientError) -> GwmClientError:
    operation = error.operation
    error_type = type(error)
    if isinstance(error, _ChinaRiskControlError):
        return GwmApiError(operation=operation, api_code="1013")
    if error_type is GwmHttpError:
        return GwmHttpError(operation=operation, status=cast(GwmHttpError, error).status)
    if error_type is GwmRateLimitError:
        rate = cast(GwmRateLimitError, error)
        return GwmRateLimitError(
            operation=operation,
            api_code=rate.api_code,
            retry_after_seconds=rate.retry_after_seconds,
        )
    if error_type is GwmAuthenticationError:
        return GwmAuthenticationError(
            operation=operation,
            api_code=cast(GwmAuthenticationError, error).api_code,
        )
    if error_type is GwmApiError:
        return GwmApiError(operation=operation, api_code=cast(GwmApiError, error).api_code)
    if error_type is GwmClosedError:
        return GwmClosedError(operation=operation)
    if error_type is GwmConfigurationError:
        return GwmConfigurationError(operation=operation)
    if error_type is GwmDeadlineExceededError:
        return GwmDeadlineExceededError(operation=operation)
    if error_type is GwmNetworkError:
        return GwmNetworkError(operation=operation)
    if error_type is GwmTlsError:
        return GwmTlsError(operation=operation)
    if error_type is GwmRedirectError:
        return GwmRedirectError(operation=operation)
    if error_type is GwmResponseTooLargeError:
        return GwmResponseTooLargeError(operation=operation)
    if error_type is GwmRoutePolicyError:
        return GwmRoutePolicyError(operation=operation)
    if error_type is GwmSchemaError:
        return GwmSchemaError(operation=operation)
    if error_type is GwmProtocolError:
        return GwmProtocolError(operation=operation)
    return GwmClientError(operation=operation)
