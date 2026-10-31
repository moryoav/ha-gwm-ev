"""GWM cloud runtime and bounded config-flow handoff.

A successful config, reauth, or reconfigure flow stages one validated regional
session for immediate entry setup. The bounded handoff is only an in-process
optimization; private account-bound storage owns restart recovery.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, cast

from homeassistant.core import HomeAssistant

from .cloud_auth import (
    CloudAuthenticationResult,
    CloudAuthState,
    GwmCloudCredentials,
    cloud_unique_id,
)
from .cloud_storage import async_finish_apac_state_save
from .const import (
    CONF_ACCOUNT,
    CONF_AUTHENTICATION_METHOD,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    REGION_ANZ,
    REGION_APAC,
    REGION_CHINA,
    REGION_EU,
    REGION_RUSSIA,
)
from .gwm_client import (
    AnzAuthenticated,
    AnzAuthenticationMethod,
    AnzAuthState,
    AnzCredentials,
    CabinCleanCommand,
    ChargingPlanCommand,
    ChargingPlanInfo,
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaClient,
    ChinaClientConfig,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    CloudClimateConfiguration,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    DoorLockCommand,
    EuAuthenticated,
    EuAuthState,
    EuCredentials,
    FrontDefrosterCommand,
    GwmApiError,
    GwmAuthenticationError,
    GwmClient,
    GwmClientConfig,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmNetworkError,
    GwmOptionalEndpointError,
    GwmProtocolError,
    GwmRoutePolicyError,
    GwmSession,
    Region,
    RemoteCommandAcceptance,
    RemoteCommandResultItem,
    RussiaAuthenticated,
    RussiaAuthState,
    RussiaCredentials,
    VehicleIdentifier,
    is_overseas_session_expired,
    map_vehicle_snapshot,
)
from .gwm_client.apac_auth import ApacCredentials
from .gwm_client.apac_flow import ApacAuthenticated
from .gwm_client.apac_identity import _is_validated_context
from .gwm_client.apac_material import ApacMaterial
from .gwm_client.apac_read import ApacReadClient, ApacReadSession
from .gwm_client.apac_restore import ApacRestored, restore_apac_session
from .gwm_client.apac_state import ApacAuthState
from .gwm_client.commands import ChinaRemoteCommandAction
from .gwm_client.regions import TlsMode
from .gwm_client.transport import AiohttpTransport

_HANDOFF_TTL_SECONDS = 5 * 60
_HANDOFF_DATA_KEY = f"{DOMAIN}_cloud_handoffs"
_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")
_APAC_TLS_SETUP_TIMEOUT = 30.0


class _OverseasReadClient(Protocol):
    @property
    def authenticated(self) -> bool: ...

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]: ...

    async def get_last_status(self, identifier: VehicleIdentifier) -> CloudVehicleStatus: ...

    async def get_vehicle_basics(
        self,
        identifier: VehicleIdentifier,
    ) -> CloudVehicleBasics: ...

    async def refresh_current_anz_session(
        self,
        credentials: AnzCredentials,
        state: AnzAuthState,
    ) -> AnzAuthenticated: ...

    async def refresh_legacy_anz_session(
        self,
        credentials: AnzCredentials,
        state: AnzAuthState,
    ) -> AnzAuthenticated: ...

    async def refresh_eu_session(
        self,
        credentials: EuCredentials,
        state: EuAuthState,
    ) -> EuAuthenticated: ...

    async def refresh_russia_session(
        self,
        credentials: RussiaCredentials,
        state: RussiaAuthState,
    ) -> RussiaAuthenticated: ...

    async def get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo: ...

    async def set_charging_plan(self, command: ChargingPlanCommand) -> None: ...

    async def update_climate_defaults(
        self,
        identifier: VehicleIdentifier,
        *,
        temperature: int,
        operation_time_minutes: int,
    ) -> None: ...

    async def send_climate_command(
        self,
        command: ClimateCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance: ...

    async def send_lock_command(
        self,
        command: DoorLockCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance: ...

    async def send_close_windows_command(
        self,
        command: CloseWindowsCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance: ...

    async def send_front_defroster_command(
        self,
        command: FrontDefrosterCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance: ...

    async def send_cabin_clean_command(
        self,
        command: CabinCleanCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance: ...

    async def get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
    ) -> tuple[RemoteCommandResultItem, ...]: ...

    async def aclose(self) -> None: ...


class _ChinaReadClient(Protocol):
    @property
    def authenticated(self) -> bool: ...

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]: ...

    async def get_last_status(self, identifier: VehicleIdentifier) -> CloudVehicleStatus: ...

    async def get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo: ...

    async def set_charging_plan(self, command: ChargingPlanCommand) -> None: ...

    async def send_climate_command(
        self,
        command: ClimateCommand,
    ) -> RemoteCommandAcceptance: ...

    async def send_lock_command(
        self,
        command: DoorLockCommand,
    ) -> RemoteCommandAcceptance: ...

    async def send_close_windows_command(
        self,
        command: CloseWindowsCommand,
    ) -> RemoteCommandAcceptance: ...

    async def send_vehicle_control_command(
        self,
        command: ChinaVehicleControlCommand,
    ) -> RemoteCommandAcceptance: ...

    async def get_bean_tech_comfort_modes(
        self,
        identifier: VehicleIdentifier,
    ) -> tuple[Mapping[str, object], ...]: ...

    async def set_bean_tech_comfort_mode(
        self,
        identifier: VehicleIdentifier,
        *,
        mode_type: str,
    ) -> str: ...

    async def set_bean_tech_cabin_clean_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        time_ms: int,
    ) -> None: ...

    async def get_bean_tech_cabin_clean_appointment(
        self,
        identifier: VehicleIdentifier,
    ) -> int | None: ...

    async def get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        control_action: ChinaRemoteCommandAction | None = None,
    ) -> tuple[RemoteCommandResultItem, ...]: ...

    async def aclose(self) -> None: ...


    async def get_bean_tech_charge_setting(
        self,
        identifier: VehicleIdentifier,
    ) -> Mapping[str, object]: ...

    async def get_bean_tech_switch_status(
        self,
        identifier: VehicleIdentifier,
    ) -> Mapping[str, object]: ...

    async def get_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
    ) -> bool | None: ...

    async def set_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        use_car_time_ms: int | None,
    ) -> str: ...

    async def set_bean_tech_charge_soc(
        self,
        identifier: VehicleIdentifier,
        *,
        percent: int,
    ) -> str: ...

    async def set_bean_tech_charge_window(
        self,
        identifier: VehicleIdentifier,
        *,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> str: ...

    async def set_bean_tech_charging_mode(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
    ) -> str: ...


class _AuthStateStore(Protocol):
    async def async_save_auth_state(
        self,
        credentials: GwmCloudCredentials,
        auth_state: EuAuthState | AnzAuthState | RussiaAuthState | ChinaAuthState,
    ) -> None: ...

    async def async_clear_auth_state(
        self,
        entry_data: dict[str, object],
    ) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class GwmClimateContext:
    """Fresh regional prerequisites used to resolve one climate request."""

    vehicle: CloudVehicle = field(repr=False)
    basics: CloudVehicleBasics = field(repr=False)
    status: CloudVehicleStatus | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class GwmCloudBootstrap:
    """One validated, memory-only regional session handoff."""

    region: str
    account_binding: str = field(repr=False)
    state: CloudAuthState = field(repr=False)
    session: GwmSession | ApacReadSession | None = field(repr=False)
    apac_material: ApacMaterial | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject bootstrap handoffs with mismatched regional state or private material."""
        if (
            self.region not in {REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA, REGION_APAC}
            or (self.region == REGION_APAC) != (type(self.apac_material) is ApacMaterial)
            or (self.region != REGION_APAC and self.apac_material is not None)
            or not isinstance(self.account_binding, str)
            or _ACCOUNT_BINDING.fullmatch(self.account_binding) is None
            or not _bootstrap_state_matches(
                self.region,
                self.account_binding,
                self.state,
                self.session,
            )
        ):
            raise GwmConfigurationError(operation="login")

    @classmethod
    def from_authentication(
        cls,
        credentials: GwmCloudCredentials,
        result: CloudAuthenticationResult,
    ) -> GwmCloudBootstrap:
        """Create a handoff only from a complete regional authentication."""

        if credentials.region == REGION_APAC:
            if (
                type(result) is not ApacAuthenticated
                or not result.state.matches(credentials.client_credentials())
            ):
                raise GwmConfigurationError(operation="login")
            return cls(
                region=credentials.region,
                account_binding=credentials.account_binding,
                state=result.state,
                session=result.session,
                apac_material=result.material,
            )
        if credentials.region == REGION_CHINA:
            if type(result) is not ChinaAuthenticated:
                raise GwmConfigurationError(operation="login")
            if (
                result.state.account_binding != credentials.account_binding
                or result.state.device_id != credentials.device_id
            ):
                raise GwmConfigurationError(operation="login")
            return cls(
                region=credentials.region,
                account_binding=credentials.account_binding,
                state=result.state,
                session=None,
            )

        valid_result = (
            (credentials.region == REGION_EU and type(result) is EuAuthenticated)
            or (credentials.region == REGION_ANZ and type(result) is AnzAuthenticated)
            or (credentials.region == REGION_RUSSIA and type(result) is RussiaAuthenticated)
        )
        if not valid_result or not isinstance(
            result,
            (EuAuthenticated, AnzAuthenticated, RussiaAuthenticated),
        ):
            raise GwmConfigurationError(operation="login")
        if result.session.device_id != credentials.device_id or result.session.country != credentials.country:
            raise GwmConfigurationError(operation="login")
        return cls(
            region=credentials.region,
            account_binding=credentials.account_binding,
            state=result.state,
            session=result.session,
        )


@dataclass(slots=True)
class _PendingBootstrap:
    bootstrap: GwmCloudBootstrap
    expiry: asyncio.TimerHandle


def stage_cloud_bootstrap(
    hass: HomeAssistant,
    unique_id: str,
    bootstrap: GwmCloudBootstrap,
) -> None:
    """Stage one bounded, replaceable handoff for config-entry setup."""

    if not isinstance(unique_id, str) or not unique_id.startswith("cloud:"):
        raise GwmConfigurationError(operation="login")
    store = hass.data.setdefault(_HANDOFF_DATA_KEY, {})
    if not isinstance(store, dict):
        raise GwmConfigurationError(operation="login")
    previous = store.pop(unique_id, None)
    if isinstance(previous, _PendingBootstrap):
        previous.expiry.cancel()

    pending: _PendingBootstrap

    def expire() -> None:
        if store.get(unique_id) is pending:
            store.pop(unique_id, None)

    pending = _PendingBootstrap(
        bootstrap=bootstrap,
        expiry=asyncio.get_running_loop().call_later(_HANDOFF_TTL_SECONDS, expire),
    )
    store[unique_id] = pending


def consume_cloud_bootstrap(
    hass: HomeAssistant,
    unique_id: str | None,
) -> GwmCloudBootstrap | None:
    """Consume exactly one staged handoff."""

    if not isinstance(unique_id, str):
        return None
    store = hass.data.get(_HANDOFF_DATA_KEY)
    if not isinstance(store, dict):
        return None
    pending = store.pop(unique_id, None)
    if not isinstance(pending, _PendingBootstrap):
        return None
    pending.expiry.cancel()
    return pending.bootstrap


class GwmCloudClient:
    """Own one authenticated regional client and normalize account reads."""

    def __init__(
        self,
        region: str,
        client: _OverseasReadClient | _ChinaReadClient,
        *,
        clock: Callable[[], datetime] | None = None,
        bootstrap: GwmCloudBootstrap | None = None,
        credentials: GwmCloudCredentials | None = None,
        state_store: _AuthStateStore | None = None,
        entry_data: dict[str, object] | None = None,
        climate_commands_enabled: bool = False,
        apac_climate_enabled: bool = False,
        apac_remote_enabled: bool = False,
        apac_charging_enabled: bool = False,
        lock_window_commands_enabled: bool = False,
        charging_control_enabled: bool = False,
    ) -> None:
        """Bind the regional reader, persistence, and explicitly enabled command capabilities."""
        if region not in {REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA, REGION_APAC}:
            raise GwmConfigurationError(operation="request")
        self.region = region
        self._client = client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bootstrap = bootstrap
        self._credentials = credentials
        self._state_store = state_store
        self._entry_data = dict(entry_data or {})
        self._session_renewal_lock = asyncio.Lock()
        self._apac_close_lock = asyncio.Lock()
        self._apac_closing = False
        self._apac_closed = False
        self._apac_validation_pending = False
        self._pending_auth_state: CloudAuthState | None = None
        if credentials is not None and (
            type(credentials) is not GwmCloudCredentials
            or bootstrap is None
            or bootstrap.region != credentials.region
            or bootstrap.account_binding != credentials.account_binding
        ):
            raise GwmConfigurationError(operation="login")
        if (
            type(climate_commands_enabled) is not bool
            or type(apac_climate_enabled) is not bool
            or type(apac_remote_enabled) is not bool
            or type(apac_charging_enabled) is not bool
            or type(lock_window_commands_enabled) is not bool
            or type(charging_control_enabled) is not bool
        ):
            raise GwmConfigurationError(operation="request")
        self._climate_commands_enabled = apac_climate_enabled if region == REGION_APAC else climate_commands_enabled
        self._apac_remote_enabled = apac_remote_enabled and region == REGION_APAC
        self._apac_charging_enabled = apac_charging_enabled and region == REGION_APAC
        self._lock_window_commands_enabled = apac_remote_enabled if region == REGION_APAC else lock_window_commands_enabled
        self._charging_control_enabled = charging_control_enabled and region != REGION_APAC
        self._vehicles: dict[str, CloudVehicle] = {}
        self._china_climate_defaults: dict[str, CloudClimateConfiguration] = {}

    @classmethod
    def from_entry_data(
        cls,
        data: dict[str, object],
        unique_id: str | None,
        bootstrap: GwmCloudBootstrap,
        *,
        state_store: _AuthStateStore | None = None,
        climate_commands_enabled: bool = False,
        apac_climate_enabled: bool = False,
        apac_remote_enabled: bool = False,
        apac_charging_enabled: bool = False,
        lock_window_commands_enabled: bool = False,
        charging_control_enabled: bool = False,
    ) -> GwmCloudClient:
        """Validate a staged handoff against the current config entry."""

        if not isinstance(unique_id, str):
            raise GwmConfigurationError(operation="login")
        credentials = GwmCloudCredentials(
            region=str(data.get(CONF_REGION, "")),
            country=str(data.get(CONF_COUNTRY, "")),
            account=str(data.get(CONF_ACCOUNT, "")),
            password=(str(data[CONF_PASSWORD]) if isinstance(data.get(CONF_PASSWORD), str) else None),
            device_id=bootstrap.state.device_id,
            authentication_method=(
                str(data[CONF_AUTHENTICATION_METHOD]) if isinstance(data.get(CONF_AUTHENTICATION_METHOD), str) else None
            ),
        )
        if (
            bootstrap.region != credentials.region
            or bootstrap.account_binding != credentials.account_binding
            or unique_id != cloud_unique_id(credentials)
        ):
            raise GwmConfigurationError(operation="login")

        if credentials.region == REGION_APAC:
            if type(bootstrap.session) is not ApacReadSession or type(bootstrap.apac_material) is not ApacMaterial:
                raise GwmConfigurationError(operation="login")
            apac_client = ApacReadClient(
                material=bootstrap.apac_material,
                session=bootstrap.session,
                transport=AiohttpTransport.create_owned(max_response_bytes=4 * 1024 * 1024),
                owns_transport=True,
            )
            return cls(
                credentials.region,
                cast(_OverseasReadClient, apac_client),
                bootstrap=bootstrap,
                credentials=credentials,
                state_store=state_store,
                entry_data=data,
                climate_commands_enabled=climate_commands_enabled,
                apac_climate_enabled=apac_climate_enabled,
                apac_remote_enabled=apac_remote_enabled,
                apac_charging_enabled=apac_charging_enabled,
                lock_window_commands_enabled=lock_window_commands_enabled,
                charging_control_enabled=charging_control_enabled,
            )

        if credentials.region == REGION_CHINA:
            if type(bootstrap.state) is not ChinaAuthState or bootstrap.session is not None:
                raise GwmConfigurationError(operation="login")
            client = ChinaClient(
                ChinaClientConfig(),
                authenticated_state=bootstrap.state,
            )
            return cls(
                credentials.region,
                client,
                bootstrap=bootstrap,
                credentials=credentials,
                state_store=state_store,
                entry_data=data,
                climate_commands_enabled=climate_commands_enabled,
                lock_window_commands_enabled=lock_window_commands_enabled,
                charging_control_enabled=charging_control_enabled,
            )

        if type(bootstrap.session) is not GwmSession or bootstrap.session.country != credentials.country:
            raise GwmConfigurationError(operation="login")
        try:
            region = Region(credentials.region)
        except ValueError:
            raise GwmConfigurationError(operation="login") from None
        client = GwmClient(
            GwmClientConfig(
                region,
                anz_authentication_method=(
                    credentials.authentication_method if credentials.region == REGION_ANZ else None
                ),
            ),
            session=bootstrap.session,
        )
        return cls(
            credentials.region,
            client,
            bootstrap=bootstrap,
            credentials=credentials,
            state_store=state_store,
            entry_data=data,
            climate_commands_enabled=climate_commands_enabled,
            lock_window_commands_enabled=lock_window_commands_enabled,
            charging_control_enabled=charging_control_enabled,
        )

    @property
    def reusable_bootstrap(self) -> GwmCloudBootstrap | None:
        """Return the current in-process handoff if authentication still holds."""

        if self.region == REGION_APAC and (
            self._apac_closing
            or self._apac_closed
            or self._apac_validation_pending
            or self._session_renewal_lock.locked()
        ):
            return None
        return self._bootstrap if self._client.authenticated else None

    async def async_get_vehicle_data(self) -> dict[str, object]:
        """Perform one atomic account discovery/status/basics refresh."""

        return await self._async_with_session_renewal(self._async_get_vehicle_data_once)

    async def _async_get_vehicle_data_once(self) -> dict[str, object]:
        """Perform one account refresh without a session-renewal retry."""

        vehicles = await self._client.acquire_vehicles()
        records: list[tuple[CloudVehicle, CloudVehicleStatus, CloudVehicleBasics]] = []
        for vehicle in vehicles:
            status = await self._client.get_last_status(vehicle.identifier)
            if self.region == REGION_CHINA:
                basics = self._china_vehicle_basics(vehicle.identifier)
            else:
                overseas_client = cast(_OverseasReadClient, self._client)
                try:
                    basics = await overseas_client.get_vehicle_basics(vehicle.identifier)
                except GwmOptionalEndpointError:
                    if self.region != REGION_ANZ:
                        raise
                    basics = CloudVehicleBasics()
            records.append((vehicle, status, basics))

        refreshed_at = self._clock()
        try:
            snapshots = []
            for vehicle, status, basics in records:
                platform = (vehicle.platform or "").strip().casefold()
                china_supported = self.region == REGION_CHINA and platform in {
                    "navinfo",
                    "beantech",
                }
                china_navinfo = self.region == REGION_CHINA and platform == "navinfo"
                remote_commands_available = self._lock_window_commands_enabled and china_supported
                charging_control_available = self._charging_control_enabled and (
                    self.region != REGION_CHINA or china_navinfo
                )
                snapshot = map_vehicle_snapshot(
                    vehicle,
                    status,
                    basics,
                    refreshed_at=refreshed_at,
                    remote_commands_available=remote_commands_available,
                    charging_control_available=charging_control_available,
                ).as_dict()
                capability_data = snapshot.get("capabilities")
                if not isinstance(capability_data, dict):
                    raise TypeError("capabilities_invalid")
                capabilities = dict(capability_data)
                if self.region == REGION_APAC:
                    apac_supported = platform in {"beantech", "navinfo"}
                    capabilities["apac_remote_controls"] = self._apac_remote_enabled and apac_supported
                    capabilities["apac_direct_charging"] = self._apac_charging_enabled and apac_supported
                    capabilities["apac_seat_controls"] = (
                        self._apac_remote_enabled and platform == "beantech" and vehicle.rudder in {"1", "2"}
                    )
                capabilities["climate_commands"] = self._climate_commands_enabled and (
                    platform in {"beantech", "navinfo"} if self.region == REGION_APAC
                    else self.region != REGION_CHINA or china_supported
                )
                capabilities["lock_window_commands"] = self._lock_window_commands_enabled and (
                    platform in {"beantech", "navinfo"} if self.region == REGION_APAC
                    else self.region != REGION_CHINA or china_supported
                )
                capabilities["charging_control"] = charging_control_available
                if self.region == REGION_CHINA and platform == "beantech":
                    capabilities["beantech_charging_commands"] = self._charging_control_enabled
                capabilities["china_vehicle_commands"] = self._lock_window_commands_enabled and china_supported
                raw_items = snapshot.get("raw_items")
                overseas_status_codes = (
                    raw_items if self.region != REGION_CHINA and isinstance(raw_items, dict) else {}
                )
                capabilities["front_defroster_commands"] = (
                    (capabilities["apac_remote_controls"] if self.region == REGION_APAC else self._climate_commands_enabled)
                    and "2222001" in overseas_status_codes
                )
                capabilities["cabin_clean_commands"] = (
                    (capabilities["apac_remote_controls"] if self.region == REGION_APAC else self._climate_commands_enabled)
                    and "2078020" in overseas_status_codes
                )
                snapshot["capabilities"] = capabilities
                snapshots.append(snapshot)
        except (TypeError, ValueError):
            raise GwmProtocolError(operation="request") from None

        self._vehicles = {vehicle.identifier.value: vehicle for vehicle, _status, _basics in records}

        return {
            "region": self.region,
            "remote_commands_enabled": (self._climate_commands_enabled or self._lock_window_commands_enabled),
            "charging_control_enabled": self._charging_control_enabled,
            "vehicles": snapshots,
        }

    async def async_get_climate_context(
        self,
        identifier: VehicleIdentifier,
        *,
        include_status: bool,
    ) -> GwmClimateContext:
        """Fetch current prerequisites without allowing an undiscovered VIN route."""

        return await self._async_with_session_renewal(
            lambda: self._async_get_climate_context_once(
                identifier,
                include_status=include_status,
            )
        )

    async def _async_get_climate_context_once(
        self,
        identifier: VehicleIdentifier,
        *,
        include_status: bool,
    ) -> GwmClimateContext:
        """Fetch climate prerequisites without a session-renewal retry."""

        if type(identifier) is not VehicleIdentifier or type(include_status) is not bool:
            raise GwmRoutePolicyError(operation="send_climate_command")
        vehicle = self._vehicles.get(identifier.value)
        if vehicle is None:
            raise GwmRoutePolicyError(operation="send_climate_command")
        if self.region == REGION_CHINA:
            if (vehicle.platform or "").strip().casefold() not in {"navinfo", "beantech"}:
                raise GwmRoutePolicyError(operation="send_climate_command")
            basics = self._china_vehicle_basics(identifier)
        else:
            overseas_client = cast(_OverseasReadClient, self._client)
            try:
                basics = await overseas_client.get_vehicle_basics(identifier)
            except GwmOptionalEndpointError:
                if self.region != REGION_ANZ:
                    raise
                basics = CloudVehicleBasics()
        status = await self._client.get_last_status(identifier) if include_status else None
        return GwmClimateContext(vehicle=vehicle, basics=basics, status=status)

    async def async_update_climate_defaults(
        self,
        identifier: VehicleIdentifier,
        *,
        temperature: int,
        operation_time_minutes: int,
    ) -> None:
        """Update supported regional climate defaults without replaying APAC writes."""
        if self.region == REGION_APAC:
            if not self._climate_commands_enabled or type(identifier) is not VehicleIdentifier or identifier.value not in self._vehicles or type(self._client) is not ApacReadClient:
                raise GwmRoutePolicyError(operation="update_climate_defaults")
            self._apac_control_vehicle(identifier, operation="update_climate_defaults")
            async with self._session_renewal_lock:
                await self._async_apac_write_once(
                    "update_climate_defaults",
                    lambda: self._client.update_climate_defaults(identifier, temperature=temperature, operation_time_minutes=operation_time_minutes),
                    identifier=identifier,
                )
            return
        if self.region == REGION_CHINA:
            vehicle = self._vehicles.get(identifier.value)
            if vehicle is None or (vehicle.platform or "").strip().casefold() not in {"navinfo", "beantech"}:
                raise GwmRoutePolicyError(operation="send_climate_command")
            self._china_climate_defaults[identifier.value] = CloudClimateConfiguration(
                temperature=str(temperature),
                operation_time=str(operation_time_minutes * 60),
            )
            return
        await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).update_climate_defaults(
                identifier,
                temperature=temperature,
                operation_time_minutes=operation_time_minutes,
            )
        )

    async def async_get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo:
        """Read the current charging plan through the authenticated client."""

        self._ensure_apac_read_only("get_charging_plan")

        return await self._async_with_session_renewal(lambda: self._client.get_charging_plan(identifier))

    async def async_set_charging_plan(self, command: ChargingPlanCommand) -> None:
        """Set or clear the charging plan through the authenticated client."""

        self._ensure_apac_read_only("set_charging_plan")

        await self._async_with_session_renewal(lambda: self._client.set_charging_plan(command))

    async def async_send_climate_command(
        self,
        command: ClimateCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a regional climate command without replaying uncertain APAC writes."""
        if self.region == REGION_APAC:
            if (
                not self._climate_commands_enabled
                or type(command) is not ClimateCommand
                or command.identifier.value not in self._vehicles
                or not isinstance(security_password_hash, str)
                or type(self._client) is not ApacReadClient
            ):
                raise GwmRoutePolicyError(operation="send_climate_command")
            self._apac_control_vehicle(command.identifier, operation="send_climate_command")
            async with self._session_renewal_lock:
                return await self._async_apac_write_once(
                    "send_climate_command",
                    lambda: self._client.send_climate_command(command, security_password_hash=security_password_hash),
                    identifier=command.identifier,
                )
        if self.region == REGION_CHINA:
            return await self._async_with_session_renewal(
                lambda: cast(_ChinaReadClient, self._client).send_climate_command(command)
            )
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_climate_command")
        return await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).send_climate_command(
                command,
                security_password_hash=security_password_hash,
            )
        )

    async def async_send_apac_control(
        self, identifier: VehicleIdentifier, action: str, *, security_password_hash: str,
    ) -> RemoteCommandAcceptance:
        """Send an explicitly enabled APAC control once after session validation."""
        if not isinstance(action, str):
            raise GwmRoutePolicyError(operation="send_apac_control")
        is_charging = action in {"charge_now", "charge_off"}
        allowed = self._apac_charging_enabled if is_charging else self._apac_remote_enabled
        if (
            self.region != REGION_APAC or not allowed or type(identifier) is not VehicleIdentifier
            or identifier.value not in self._vehicles or type(self._client) is not ApacReadClient
        ):
            raise GwmRoutePolicyError(operation="send_apac_control")
        async def send_control() -> RemoteCommandAcceptance:
            """Build the command with metadata from the completed account validation."""
            vehicle = self._apac_control_vehicle(
                identifier, operation="send_apac_control",
                bean_tech_only=action.startswith(("seat_", "steering_wheel_")),
            )
            driver_right = None
            if action.startswith(("seat_heating_", "seat_ventilation_")):
                if vehicle.rudder not in {"1", "2"}:
                    raise GwmRoutePolicyError(operation="send_apac_control")
                driver_right = vehicle.rudder == "2"
            return await self._client.send_apac_control(identifier, action, security_password_hash=security_password_hash, driver_right=driver_right)

        async with self._session_renewal_lock:
            return await self._async_apac_write_once(
                "send_apac_control", send_control, identifier=identifier,
            )

    def _apac_control_vehicle(
        self, identifier: VehicleIdentifier, *, operation: str, bean_tech_only: bool = False,
    ) -> CloudVehicle:
        """Limit APAC writes to a discovered vehicle with the supported platform."""
        vehicle = self._vehicles.get(identifier.value)
        supported = {"beantech"} if bean_tech_only else {"beantech", "navinfo"}
        if vehicle is None or (vehicle.platform or "").strip().casefold() not in supported:
            raise GwmRoutePolicyError(operation=operation)
        return vehicle

    async def _async_apac_write_once[T](
        self, operation: str, action: Callable[[], Awaitable[T]], *, identifier: VehicleIdentifier,
    ) -> T:
        """Validate account state and retire rejected sessions, without replaying writes.

        The caller holds the APAC session lock, which also lets shutdown drain the operation.
        """
        if self._apac_closing or self._apac_closed:
            raise GwmRoutePolicyError(operation=operation)
        await self._async_flush_pending_auth_state()
        try:
            if self._credentials is not None:
                await self._async_validate_apac_session(force_refresh=False)
            elif self._apac_validation_pending:
                raise GwmAuthenticationError(operation=operation)
            self._apac_control_vehicle(identifier, operation=operation)
            return await action()
        except GwmApiError as error:
            if not is_overseas_session_expired(error):
                raise
            with suppress(Exception):
                await self.async_authentication_rejected()
            raise GwmAuthenticationError(operation=error.operation, api_code=error.api_code) from None

    async def async_send_lock_command(
        self,
        command: DoorLockCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a supported regional lock command with bounded session recovery."""
        if self.region == REGION_APAC:
            if type(command) is not DoorLockCommand or not isinstance(security_password_hash, str):
                raise GwmRoutePolicyError(operation="send_lock_command")
            return await self.async_send_apac_control(command.identifier, "lock" if command.lock else "unlock", security_password_hash=security_password_hash)
        if self.region == REGION_CHINA:
            return await self._async_with_session_renewal(
                lambda: cast(_ChinaReadClient, self._client).send_lock_command(command)
            )
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_lock_command")
        return await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).send_lock_command(
                command,
                security_password_hash=security_password_hash,
            )
        )

    async def async_send_close_windows_command(
        self,
        command: CloseWindowsCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        """Send a supported regional window command with bounded session recovery."""
        if self.region == REGION_APAC:
            if type(command) is not CloseWindowsCommand or not isinstance(security_password_hash, str):
                raise GwmRoutePolicyError(operation="send_close_windows_command")
            return await self.async_send_apac_control(command.identifier, "close_windows", security_password_hash=security_password_hash)
        if self.region == REGION_CHINA:
            return await self._async_with_session_renewal(
                lambda: cast(_ChinaReadClient, self._client).send_close_windows_command(command)
            )
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_close_windows_command")
        return await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).send_close_windows_command(
                command,
                security_password_hash=security_password_hash,
            )
        )

    async def async_send_front_defroster_command(
        self,
        command: FrontDefrosterCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one overseas front-defroster operation."""

        if self.region == REGION_APAC:
            if type(command) is not FrontDefrosterCommand or not isinstance(security_password_hash, str):
                raise GwmRoutePolicyError(operation="send_front_defroster_command")
            return await self.async_send_apac_control(command.identifier, "defrost_front_start" if command.enabled else "defrost_front_stop", security_password_hash=security_password_hash)

        if self.region == REGION_CHINA:
            raise GwmRoutePolicyError(operation="send_front_defroster_command")
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_front_defroster_command")
        return await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).send_front_defroster_command(
                command,
                security_password_hash=security_password_hash,
            )
        )

    async def async_send_cabin_clean_command(
        self,
        command: CabinCleanCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one overseas fixed-duration cabin-clean operation."""

        if self.region == REGION_APAC:
            if type(command) is not CabinCleanCommand or not isinstance(security_password_hash, str):
                raise GwmRoutePolicyError(operation="send_cabin_clean_command")
            return await self.async_send_apac_control(command.identifier, "cabin_clean", security_password_hash=security_password_hash)

        if self.region == REGION_CHINA:
            raise GwmRoutePolicyError(operation="send_cabin_clean_command")
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_cabin_clean_command")
        return await self._async_with_session_renewal(
            lambda: cast(_OverseasReadClient, self._client).send_cabin_clean_command(
                command,
                security_password_hash=security_password_hash,
            )
        )

    def _ensure_apac_read_only(self, operation: str) -> None:
        """Deny unsupported APAC operations before any client invocation."""
        if self.region == REGION_APAC:
            raise GwmRoutePolicyError(operation=operation)

    async def async_send_vehicle_control_command(
        self,
        command: ChinaVehicleControlCommand,
    ) -> RemoteCommandAcceptance:
        """Send one platform-filtered mainland-China vehicle command."""

        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="send_vehicle_control_command")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).send_vehicle_control_command(command)
        )

    async def async_get_bean_tech_comfort_modes(
        self,
        identifier: VehicleIdentifier,
    ) -> tuple[Mapping[str, object], ...]:
        """Read the BeanTech one-touch comfort modes through the client."""
        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="get_bean_tech_comfort_modes")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).get_bean_tech_comfort_modes(
                identifier
            )
        )

    async def async_set_bean_tech_comfort_mode(
        self,
        identifier: VehicleIdentifier,
        *,
        mode_type: str,
    ) -> str:
        """Execute a BeanTech one-touch comfort mode through the client."""
        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="set_bean_tech_comfort_mode")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).set_bean_tech_comfort_mode(
                identifier,
                mode_type=mode_type,
            )
        )

    async def async_set_bean_tech_cabin_clean_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        time_ms: int,
    ) -> None:
        """Schedule one BeanTech cabin-clean run through the client."""
        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="set_bean_tech_cabin_clean_appointment")
        await self._async_with_session_renewal(
            lambda: cast(
                _ChinaReadClient, self._client
            ).set_bean_tech_cabin_clean_appointment(identifier, time_ms=time_ms)
        )

    async def async_get_bean_tech_cabin_clean_appointment(
        self,
        identifier: VehicleIdentifier,
    ) -> int | None:
        """Read the scheduled BeanTech cabin-clean epoch-ms through the client."""
        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="get_bean_tech_cabin_clean_appointment")
        return await self._async_with_session_renewal(
            lambda: cast(
                _ChinaReadClient, self._client
            ).get_bean_tech_cabin_clean_appointment(identifier)
        )

    async def async_get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        control_action: ChinaRemoteCommandAction | None = None,
    ) -> tuple[RemoteCommandResultItem, ...]:
        if self.region == REGION_CHINA and control_action is not None:
            return await self._async_with_session_renewal(
                lambda: cast(_ChinaReadClient, self._client).get_remote_command_results(
                    identifier, command_id, control_action=control_action
                )
            )
        return await self._async_with_session_renewal(
            lambda: self._client.get_remote_command_results(identifier, command_id)
        )

    async def _async_with_session_renewal[T](
        self,
        action: Callable[[], Awaitable[T]],
    ) -> T:
        """Retry one overseas operation after one serialized token rotation."""

        if self.region == REGION_APAC:
            return await self._async_with_apac_session_renewal(action)

        async with self._session_renewal_lock:
            await self._async_flush_pending_auth_state()
            observed_state = self._current_overseas_auth_state()
        observed_access_token = observed_state.access_token if observed_state is not None else None
        try:
            return await action()
        except (GwmAuthenticationError, GwmApiError) as error:
            if observed_state is None or not is_overseas_session_expired(error):
                raise
            trigger = error

        try:
            async with self._session_renewal_lock:
                await self._async_flush_pending_auth_state()
                current_state = self._current_overseas_auth_state()
                if current_state is None:
                    raise GwmAuthenticationError(
                        operation=trigger.operation,
                        api_code=trigger.api_code,
                    )
                if current_state.access_token == observed_access_token:
                    await self._async_renew_overseas_session(
                        current_state,
                        trigger=trigger,
                    )
            try:
                return await action()
            except (GwmAuthenticationError, GwmApiError) as retry_error:
                if not is_overseas_session_expired(retry_error):
                    raise
                raise GwmAuthenticationError(
                    operation=retry_error.operation,
                    api_code=retry_error.api_code,
                ) from None
        except GwmAuthenticationError:
            with suppress(Exception):
                await self.async_authentication_rejected()
            raise

    async def _async_with_apac_session_renewal[T](self, action: Callable[[], Awaitable[T]]) -> T:
        """Serialize APAC reads and retry once after safe token restoration."""
        if self._apac_closing or self._apac_closed:
            raise GwmClosedError(operation="request")
        async with self._session_renewal_lock:
            if self._apac_closing or self._apac_closed:
                raise GwmClosedError(operation="request")
            if self._credentials is not None and self._bootstrap is None:
                raise GwmAuthenticationError(operation="request")
            await self._async_flush_pending_auth_state()
            validation_pending = self._apac_validation_pending
            if not validation_pending:
                try:
                    return await action()
                except (GwmAuthenticationError, GwmApiError) as error:
                    if not is_overseas_session_expired(error):
                        raise
            try:
                await self._async_validate_apac_session(force_refresh=not validation_pending)
                try:
                    return await action()
                except GwmApiError as retry_error:
                    if is_overseas_session_expired(retry_error):
                        raise GwmAuthenticationError(
                            operation=retry_error.operation, api_code=retry_error.api_code
                        ) from None
                    raise
            except GwmAuthenticationError:
                with suppress(Exception):
                    await self.async_authentication_rejected()
                raise

    async def _async_validate_apac_session(self, *, force_refresh: bool) -> None:
        """Retain replacement tokens privately until profile and discovery validate."""
        bootstrap = self._bootstrap
        credentials = self._credentials
        client = self._client
        if (
            bootstrap is None
            or type(bootstrap.state) is not ApacAuthState
            or type(bootstrap.apac_material) is not ApacMaterial
            or credentials is None
            or type(client) is not ApacReadClient
        ):
            raise GwmAuthenticationError(operation="refresh_token")
        regional_credentials = credentials.client_credentials()
        if type(regional_credentials) is not ApacCredentials:
            raise GwmAuthenticationError(operation="refresh_token")

        async def retain_session_update(restored: ApacRestored) -> None:
            """Retain rotated tokens without exporting an unverified handoff."""
            self._apac_validation_pending = True
            current = self._bootstrap
            replacement = GwmCloudBootstrap(
                region=REGION_APAC,
                account_binding=credentials.account_binding,
                state=restored.state,
                session=restored.session,
                apac_material=bootstrap.apac_material,
            )
            client.replace_session(restored.session)
            self._bootstrap = replacement
            if current is None or restored.state != current.state:
                self._pending_auth_state = restored.state
                await self._async_flush_pending_auth_state()

        try:
            async with asyncio.timeout(_APAC_TLS_SETUP_TIMEOUT):
                h5_context = await asyncio.to_thread(ssl.create_default_context)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation="refresh_token") from None
        restored = await restore_apac_session(
            credentials=regional_credentials,
            material=bootstrap.apac_material,
            state=bootstrap.state,
            h5_context=h5_context,
            transport=client._transport,
            on_session_updated=retain_session_update,
            force_refresh=force_refresh,
        )
        await retain_session_update(restored)
        if restored.vehicles is not None:
            self._vehicles = {vehicle.identifier.value: vehicle for vehicle in restored.vehicles}
        self._apac_validation_pending = False

    async def _async_renew_overseas_session(
        self,
        state: EuAuthState | AnzAuthState | RussiaAuthState,
        *,
        trigger: GwmAuthenticationError | GwmApiError,
    ) -> None:
        credentials = self._credentials
        if (
            state.refresh_token is None
            or credentials is None
            or credentials.region != self.region
        ):
            raise GwmAuthenticationError(
                operation=trigger.operation,
                api_code=trigger.api_code,
            )
        regional_credentials = credentials.client_credentials()
        client = cast(_OverseasReadClient, self._client)
        if self.region == REGION_EU and type(state) is EuAuthState:
            if type(regional_credentials) is not EuCredentials:
                raise GwmAuthenticationError(
                    operation=trigger.operation,
                    api_code=trigger.api_code,
                )
            result = await client.refresh_eu_session(regional_credentials, state)
        elif self.region == REGION_ANZ and type(state) is AnzAuthState:
            if type(regional_credentials) is not AnzCredentials:
                raise GwmAuthenticationError(
                    operation=trigger.operation,
                    api_code=trigger.api_code,
                )
            if state.authentication_method is AnzAuthenticationMethod.CURRENT:
                result = await client.refresh_current_anz_session(
                    regional_credentials,
                    state,
                )
            else:
                result = await client.refresh_legacy_anz_session(
                    regional_credentials,
                    state,
                )
        elif self.region == REGION_RUSSIA and type(state) is RussiaAuthState:
            if type(regional_credentials) is not RussiaCredentials:
                raise GwmAuthenticationError(
                    operation=trigger.operation,
                    api_code=trigger.api_code,
                )
            result = await client.refresh_russia_session(regional_credentials, state)
        else:
            raise GwmAuthenticationError(
                operation=trigger.operation,
                api_code=trigger.api_code,
            )
        bootstrap = GwmCloudBootstrap.from_authentication(credentials, result)
        self._bootstrap = bootstrap
        self._pending_auth_state = result.state
        await self._async_flush_pending_auth_state()

    async def _async_flush_pending_auth_state(self) -> None:
        """Save pending tokens, finishing APAC persistence before cancellation."""
        state = self._pending_auth_state
        if state is None:
            return
        credentials = self._credentials
        if credentials is None:
            raise GwmNetworkError(operation="refresh_token")
        state_store = self._state_store
        if state_store is None:
            self._pending_auth_state = None
            return

        async def save_state() -> None:
            """Clear the pending revision only after its private save completes."""
            await state_store.async_save_auth_state(credentials, state)
            if self._pending_auth_state is state:
                self._pending_auth_state = None

        try:
            if self.region == REGION_APAC:
                await async_finish_apac_state_save(save_state())
            else:
                await save_state()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise GwmNetworkError(operation="refresh_token") from None

    def _current_overseas_auth_state(
        self,
    ) -> EuAuthState | AnzAuthState | RussiaAuthState | None:
        bootstrap = self._bootstrap
        if bootstrap is None:
            return None
        state = bootstrap.state
        if self.region == REGION_EU and type(state) is EuAuthState:
            return state
        if self.region == REGION_ANZ and type(state) is AnzAuthState:
            return state
        if self.region == REGION_RUSSIA and type(state) is RussiaAuthState:
            return state
        return None

    async def aclose(self) -> None:
        """Drain APAC recovery before closing the owned regional transport."""

        if self.region != REGION_APAC:
            await self._client.aclose()
            return
        async with self._apac_close_lock:
            self._apac_closing = True
            try:
                async with self._session_renewal_lock:
                    try:
                        await self._async_flush_pending_auth_state()
                    finally:
                        if not self._apac_closed:
                            await self._client.aclose()
                            self._apac_closed = True
            except BaseException:
                self._apac_closing = False
                raise
            self._apac_closing = False

    async def async_authentication_rejected(self) -> None:
        """Retire a rejected durable revision without logging its contents."""

        self._bootstrap = None
        self._pending_auth_state = None
        if self.region == REGION_APAC:
            self._apac_validation_pending = False
        if self._state_store is not None:
            await self._state_store.async_clear_auth_state(self._entry_data)

    def _china_vehicle_basics(
        self,
        identifier: VehicleIdentifier,
    ) -> CloudVehicleBasics:
        climate = self._china_climate_defaults.setdefault(
            identifier.value,
            CloudClimateConfiguration(
                temperature="22",
                operation_time="900",
            ),
        )
        return CloudVehicleBasics(climate=climate)


    async def async_get_bean_tech_charge_setting(
        self,
        identifier: VehicleIdentifier,
    ) -> Mapping[str, object]:
        """Read one BeanTech vehicle's smart-charge setting through the client."""

        self._require_bean_tech_charging_vehicle(identifier, operation="get_bean_tech_charge_setting")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).get_bean_tech_charge_setting(
                identifier
            )
        )

    async def async_set_bean_tech_charging_mode(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
    ) -> str:
        """Set one BeanTech smart-charge mode and return the pollable seqNo."""

        self._require_bean_tech_charging_vehicle(identifier, operation="set_bean_tech_charging_mode")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).set_bean_tech_charging_mode(
                identifier,
                enable=enable,
            )
        )

    async def async_get_bean_tech_switch_status(
        self,
        identifier: VehicleIdentifier,
    ) -> Mapping[str, object]:
        """Read the BeanTech switch/status block through the client."""
        self._require_bean_tech_charging_vehicle(identifier, operation="get_bean_tech_switch_status")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).get_bean_tech_switch_status(
                identifier
            )
        )

    async def async_get_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
    ) -> bool | None:
        """Read whether BeanTech battery appointment heating is armed."""
        self._require_bean_tech_charging_vehicle(identifier, operation="get_bean_tech_battery_heating_appointment")
        return await self._async_with_session_renewal(
            lambda: cast(
                _ChinaReadClient, self._client
            ).get_bean_tech_battery_heating_appointment(identifier)
        )

    async def async_set_bean_tech_battery_heating_appointment(
        self,
        identifier: VehicleIdentifier,
        *,
        enable: bool,
        use_car_time_ms: int | None = None,
    ) -> str:
        """Arm or disarm BeanTech battery appointment heating and return seqNo."""
        self._require_bean_tech_charging_vehicle(identifier, operation="set_bean_tech_battery_heating_appointment")
        return await self._async_with_session_renewal(
            lambda: cast(
                _ChinaReadClient, self._client
            ).set_bean_tech_battery_heating_appointment(
                identifier,
                enable=enable,
                use_car_time_ms=use_car_time_ms,
            )
        )

    async def async_set_bean_tech_charge_soc(
        self,
        identifier: VehicleIdentifier,
        *,
        percent: int,
    ) -> str:
        """Set the BeanTech charge limit and return the pollable seqNo."""
        self._require_bean_tech_charging_vehicle(identifier, operation="set_bean_tech_charge_soc")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).set_bean_tech_charge_soc(
                identifier,
                percent=percent,
            )
        )

    async def async_set_bean_tech_charge_window(
        self,
        identifier: VehicleIdentifier,
        *,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> str:
        """Write the BeanTech smart-charge window and return the pollable seqNo."""
        self._require_bean_tech_charging_vehicle(identifier, operation="set_bean_tech_charge_window")
        return await self._async_with_session_renewal(
            lambda: cast(_ChinaReadClient, self._client).set_bean_tech_charge_window(
                identifier,
                start_time=start_time,
                end_time=end_time,
            )
        )


    def _require_bean_tech_charging_vehicle(self, identifier: VehicleIdentifier, *, operation: str) -> None:
        """Reject an unrelated platform before authentication renewal or transport."""
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        vehicle = self._vehicles.get(identifier.value)
        if (
            self.region != REGION_CHINA or vehicle is None
            or str(vehicle.platform or "").strip().casefold() != "beantech"
        ):
            raise GwmRoutePolicyError(operation=operation)


def _bootstrap_state_matches(
    region: str,
    account_binding: str,
    state: object,
    session: GwmSession | ApacReadSession | None,
) -> bool:
    """Check that private state and its session belong to the same regional account."""
    if region == REGION_APAC:
        return (
            type(state) is ApacAuthState
            and type(session) is ApacReadSession
            and state.account_binding == account_binding
            and state.country == session.country
            and state.device_id == session.device_id
            and state.tokens is not None
            and state.issued_identity is not None
            and state.tokens.access_token == session.access_token
            and _is_validated_context(session.app_ssl_context, TlsMode.APAC_ISSUED_MTLS)
        )
    if region == REGION_CHINA:
        return (
            type(state) is ChinaAuthState
            and session is None
            and state.account_binding == account_binding
            and state.complete
        )
    if type(session) is not GwmSession:
        return False
    expected = {
        REGION_EU: EuAuthState,
        REGION_ANZ: AnzAuthState,
        REGION_RUSSIA: RussiaAuthState,
    }.get(region)
    if expected is None or type(state) is not expected:
        return False
    return (
        state.account_binding == account_binding
        and state.country == session.country
        and state.device_id == session.device_id
        and state.access_token is not None
        and state.access_token == session.access_token
    )


__all__ = [
    "GwmCloudBootstrap",
    "GwmCloudClient",
    "consume_cloud_bootstrap",
    "stage_cloud_bootstrap",
]
