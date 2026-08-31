"""GWM cloud runtime and bounded config-flow handoff.

A successful config, reauth, or reconfigure flow stages one validated regional
session for immediate entry setup. The bounded handoff is only an in-process
optimization; private account-bound storage owns restart recovery.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, cast

from homeassistant.core import HomeAssistant

from gwm_client import (
    AnzAuthenticated,
    AnzAuthState,
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
    GwmClient,
    GwmClientConfig,
    GwmConfigurationError,
    GwmOptionalEndpointError,
    GwmProtocolError,
    GwmRoutePolicyError,
    GwmSession,
    Region,
    RemoteCommandAcceptance,
    RemoteCommandResultItem,
    RussiaAuthenticated,
    RussiaAuthState,
    VehicleIdentifier,
    map_vehicle_snapshot,
)

from .cloud_auth import (
    CloudAuthenticationResult,
    GwmCloudCredentials,
    cloud_unique_id,
)
from .const import (
    CONF_ACCOUNT,
    CONF_AUTHENTICATION_METHOD,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    REGION_ANZ,
    REGION_CHINA,
    REGION_EU,
    REGION_RUSSIA,
)

_HANDOFF_TTL_SECONDS = 5 * 60
_HANDOFF_DATA_KEY = f"{DOMAIN}_cloud_handoffs"
_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")


class _OverseasReadClient(Protocol):
    @property
    def authenticated(self) -> bool: ...

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]: ...

    async def get_last_status(self, identifier: VehicleIdentifier) -> CloudVehicleStatus: ...

    async def get_vehicle_basics(
        self,
        identifier: VehicleIdentifier,
    ) -> CloudVehicleBasics: ...

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

    async def get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
    ) -> tuple[RemoteCommandResultItem, ...]: ...

    async def aclose(self) -> None: ...


class _AuthStateStore(Protocol):
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
    state: EuAuthState | AnzAuthState | RussiaAuthState | ChinaAuthState = field(repr=False)
    session: GwmSession | None = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.region not in {REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA}
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
        state_store: _AuthStateStore | None = None,
        entry_data: dict[str, object] | None = None,
        climate_commands_enabled: bool = False,
        lock_window_commands_enabled: bool = False,
        charging_control_enabled: bool = False,
    ) -> None:
        if region not in {REGION_EU, REGION_ANZ, REGION_RUSSIA, REGION_CHINA}:
            raise GwmConfigurationError(operation="request")
        self.region = region
        self._client = client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bootstrap = bootstrap
        self._state_store = state_store
        self._entry_data = dict(entry_data or {})
        if (
            type(climate_commands_enabled) is not bool
            or type(lock_window_commands_enabled) is not bool
            or type(charging_control_enabled) is not bool
        ):
            raise GwmConfigurationError(operation="request")
        self._climate_commands_enabled = climate_commands_enabled
        self._lock_window_commands_enabled = lock_window_commands_enabled
        self._charging_control_enabled = charging_control_enabled
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
            state_store=state_store,
            entry_data=data,
            climate_commands_enabled=climate_commands_enabled,
            lock_window_commands_enabled=lock_window_commands_enabled,
            charging_control_enabled=charging_control_enabled,
        )

    @property
    def reusable_bootstrap(self) -> GwmCloudBootstrap | None:
        """Return the current in-process handoff if authentication still holds."""

        return self._bootstrap if self._client.authenticated else None

    async def async_get_vehicle_data(self) -> dict[str, object]:
        """Perform one atomic account discovery/status/basics refresh."""

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
                capabilities["climate_commands"] = self._climate_commands_enabled and (
                    self.region != REGION_CHINA or china_navinfo
                )
                capabilities["lock_window_commands"] = self._lock_window_commands_enabled and (
                    self.region != REGION_CHINA or china_supported
                )
                capabilities["charging_control"] = charging_control_available
                capabilities["china_vehicle_commands"] = self._lock_window_commands_enabled and china_supported
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

        if type(identifier) is not VehicleIdentifier or type(include_status) is not bool:
            raise GwmRoutePolicyError(operation="send_climate_command")
        vehicle = self._vehicles.get(identifier.value)
        if vehicle is None:
            raise GwmRoutePolicyError(operation="send_climate_command")
        if self.region == REGION_CHINA:
            if (vehicle.platform or "").strip().casefold() != "navinfo":
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
        if self.region == REGION_CHINA:
            vehicle = self._vehicles.get(identifier.value)
            if vehicle is None or (vehicle.platform or "").strip().casefold() != "navinfo":
                raise GwmRoutePolicyError(operation="send_climate_command")
            self._china_climate_defaults[identifier.value] = CloudClimateConfiguration(
                temperature=str(temperature),
                operation_time=str(operation_time_minutes * 60),
            )
            return
        await cast(_OverseasReadClient, self._client).update_climate_defaults(
            identifier,
            temperature=temperature,
            operation_time_minutes=operation_time_minutes,
        )

    async def async_get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo:
        """Read the current charging plan through the authenticated client."""

        return await self._client.get_charging_plan(identifier)

    async def async_set_charging_plan(self, command: ChargingPlanCommand) -> None:
        """Set or clear the charging plan through the authenticated client."""

        await self._client.set_charging_plan(command)

    async def async_send_climate_command(
        self,
        command: ClimateCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.region == REGION_CHINA:
            return await cast(_ChinaReadClient, self._client).send_climate_command(command)
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_climate_command")
        return await cast(_OverseasReadClient, self._client).send_climate_command(
            command,
            security_password_hash=security_password_hash,
        )

    async def async_send_lock_command(
        self,
        command: DoorLockCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.region == REGION_CHINA:
            return await cast(_ChinaReadClient, self._client).send_lock_command(command)
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_lock_command")
        return await cast(_OverseasReadClient, self._client).send_lock_command(
            command,
            security_password_hash=security_password_hash,
        )

    async def async_send_close_windows_command(
        self,
        command: CloseWindowsCommand,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.region == REGION_CHINA:
            return await cast(_ChinaReadClient, self._client).send_close_windows_command(command)
        if not isinstance(security_password_hash, str):
            raise GwmConfigurationError(operation="send_close_windows_command")
        return await cast(_OverseasReadClient, self._client).send_close_windows_command(
            command,
            security_password_hash=security_password_hash,
        )

    async def async_send_vehicle_control_command(
        self,
        command: ChinaVehicleControlCommand,
    ) -> RemoteCommandAcceptance:
        """Send one platform-filtered mainland-China vehicle command."""

        if self.region != REGION_CHINA:
            raise GwmRoutePolicyError(operation="send_vehicle_control_command")
        return await cast(_ChinaReadClient, self._client).send_vehicle_control_command(command)

    async def async_get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
    ) -> tuple[RemoteCommandResultItem, ...]:
        return await self._client.get_remote_command_results(identifier, command_id)

    async def aclose(self) -> None:
        """Close the owned regional transport."""

        await self._client.aclose()

    async def async_authentication_rejected(self) -> None:
        """Retire a rejected durable revision without logging its contents."""

        self._bootstrap = None
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


def _bootstrap_state_matches(
    region: str,
    account_binding: str,
    state: object,
    session: GwmSession | None,
) -> bool:
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
