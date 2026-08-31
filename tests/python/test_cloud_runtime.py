"""Offline tests for the GWM cloud read runtime and bounded handoff."""

from __future__ import annotations

import ssl
from dataclasses import replace
from datetime import UTC, datetime

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora import cloud_runtime
from custom_components.gwm_ora.cloud_auth import (
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_runtime import (
    GwmCloudBootstrap,
    GwmCloudClient,
    consume_cloud_bootstrap,
    stage_cloud_bootstrap,
)
from custom_components.gwm_ora.const import ANZ_AUTHENTICATION_METHOD_CURRENT
from gwm_client import (
    AnzAuthenticated,
    AnzAuthState,
    ChargingPlanCommand,
    ChargingPlanInfo,
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaVehicle,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    CloudClimateConfiguration,
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    DoorLockCommand,
    GwmConfigurationError,
    GwmNetworkError,
    GwmOptionalEndpointError,
    GwmRoutePolicyError,
    GwmSession,
    RemoteCommandAcceptance,
    VehicleIdentifier,
)

_DEVICE_ID = "0123456789abcdef0123456789abcdef"
_REFRESHED_AT = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def _bootstrap() -> tuple[GwmCloudCredentials, GwmCloudBootstrap]:
    credentials = GwmCloudCredentials(
        "aus",
        "AU",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
        ANZ_AUTHENTICATION_METHOD_CURRENT,
    )
    regional = credentials.client_credentials()
    state = replace(
        AnzAuthState.for_credentials(regional),
        access_token="synthetic-access-token",
    )
    session = GwmSession(
        "AU",
        _DEVICE_ID,
        "synthetic-access-token",
        ssl.create_default_context(),
    )
    return credentials, GwmCloudBootstrap.from_authentication(
        credentials,
        AnzAuthenticated(state, session),
    )


class _ReadClient:
    def __init__(self) -> None:
        self.authenticated = True
        self.closed = False
        self.vehicles = (
            CloudVehicle(
                identifier=VehicleIdentifier("SYNTHETIC-VEHICLE-A"),
                app_show_series_name="Synthetic One",
                brand_name="GWM",
                vehicle_type="ORA",
            ),
            CloudVehicle(
                identifier=VehicleIdentifier("SYNTHETIC-VEHICLE-B"),
                vehicle_nickname="Synthetic Two",
                brand_name="GWM",
                vehicle_type="HAVAL",
            ),
        )
        self.statuses = {
            "SYNTHETIC-VEHICLE-A": CloudVehicleStatus(
                device_id="SYNTHETIC-SERIAL-A",
                items=(CloudStatusItem("2013021", 80, "%"),),
            ),
            "SYNTHETIC-VEHICLE-B": CloudVehicleStatus(
                device_id="SYNTHETIC-SERIAL-B",
                items=(CloudStatusItem("2013021", 55, "%"),),
            ),
        }
        self.basics: dict[str, CloudVehicleBasics | Exception] = {
            "SYNTHETIC-VEHICLE-A": CloudVehicleBasics(
                CloudClimateConfiguration(temperature="23", operation_time="15")
            ),
            "SYNTHETIC-VEHICLE-B": GwmOptionalEndpointError(
                operation="vehicle_basics",
                api_code="607099",
            ),
        }
        self.calls: list[tuple[str, str | None]] = []
        self.charging_commands: list[ChargingPlanCommand] = []

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
        self.calls.append(("vehicles", None))
        return self.vehicles

    async def get_last_status(self, identifier: VehicleIdentifier) -> CloudVehicleStatus:
        self.calls.append(("status", identifier.value))
        return self.statuses[identifier.value]

    async def get_vehicle_basics(self, identifier: VehicleIdentifier) -> CloudVehicleBasics:
        self.calls.append(("basics", identifier.value))
        value = self.basics[identifier.value]
        if isinstance(value, Exception):
            raise value
        return value

    async def get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo:
        self.calls.append(("charging", identifier.value))
        return ChargingPlanInfo()

    async def set_charging_plan(self, command: ChargingPlanCommand) -> None:
        self.charging_commands.append(command)

    async def aclose(self) -> None:
        self.closed = True
        self.authenticated = False


@pytest.mark.asyncio
async def test_handoff_is_one_shot_and_validates_entry_identity() -> None:
    credentials, bootstrap = _bootstrap()
    hass = HomeAssistant("synthetic-config")
    unique_id = cloud_unique_id(credentials)

    stage_cloud_bootstrap(hass, unique_id, bootstrap)
    consumed = consume_cloud_bootstrap(hass, unique_id)

    assert consumed is bootstrap
    assert consume_cloud_bootstrap(hass, unique_id) is None
    runtime = GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials),
        unique_id,
        bootstrap,
    )
    assert runtime.region == "aus"
    assert runtime.reusable_bootstrap is bootstrap
    await runtime.aclose()


def test_handoff_rejects_a_different_entry_unique_id() -> None:
    credentials, bootstrap = _bootstrap()

    with pytest.raises(GwmConfigurationError):
        GwmCloudClient.from_entry_data(
            cloud_entry_data(credentials),
            "cloud:aus:different-account",
            bootstrap,
        )


@pytest.mark.asyncio
async def test_multi_vehicle_refresh_maps_snapshots_and_anz_optional_basics() -> None:
    client = _ReadClient()
    runtime = GwmCloudClient("aus", client, clock=lambda: _REFRESHED_AT)

    result = await runtime.async_get_vehicle_data()

    assert result["region"] == "aus"
    assert result["remote_commands_enabled"] is False
    assert result["charging_control_enabled"] is False
    vehicles = result["vehicles"]
    assert isinstance(vehicles, list)
    assert [vehicle["vin"] for vehicle in vehicles] == [
        "SYNTHETIC-VEHICLE-A",
        "SYNTHETIC-VEHICLE-B",
    ]
    assert vehicles[0]["values"]["soc"] == 80.0
    assert vehicles[0]["climate"]["target_temperature_c"] == 23
    assert vehicles[1]["values"]["soc"] == 55.0
    assert vehicles[1]["climate"]["target_temperature_c"] == 22
    assert all(
        vehicle["timestamps"]["last_refresh"] == "2026-08-28T12:00:00+00:00"
        for vehicle in vehicles
    )


@pytest.mark.asyncio
async def test_optional_basics_is_not_hidden_outside_anz() -> None:
    client = _ReadClient()
    runtime = GwmCloudClient("eu", client, clock=lambda: _REFRESHED_AT)

    with pytest.raises(GwmOptionalEndpointError):
        await runtime.async_get_vehicle_data()


@pytest.mark.asyncio
async def test_charging_capability_and_typed_delegation_follow_independent_opt_in() -> None:
    client = _ReadClient()
    runtime = GwmCloudClient(
        "aus",
        client,
        clock=lambda: _REFRESHED_AT,
        charging_control_enabled=True,
    )

    result = await runtime.async_get_vehicle_data()
    assert result["charging_control_enabled"] is True
    assert all(
        vehicle["capabilities"]["charging_control"] is True
        for vehicle in result["vehicles"]
    )
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE-A")
    assert await runtime.async_get_charging_plan(identifier) == ChargingPlanInfo()
    command = ChargingPlanCommand(identifier, False)
    await runtime.async_set_charging_plan(command)
    assert client.charging_commands == [command]


@pytest.mark.asyncio
async def test_refresh_is_atomic_when_any_vehicle_read_fails() -> None:
    client = _ReadClient()

    async def failed_status(identifier: VehicleIdentifier) -> CloudVehicleStatus:
        if identifier.value == "SYNTHETIC-VEHICLE-B":
            raise GwmNetworkError(operation="get_last_status")
        return client.statuses[identifier.value]

    client.get_last_status = failed_status  # type: ignore[method-assign]
    runtime = GwmCloudClient("aus", client, clock=lambda: _REFRESHED_AT)

    with pytest.raises(GwmNetworkError):
        await runtime.async_get_vehicle_data()


@pytest.mark.asyncio
async def test_rejected_runtime_revision_cannot_be_restaged() -> None:
    credentials, bootstrap = _bootstrap()

    class StateStore:
        cleared: dict[str, object] | None = None

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            self.cleared = data

    state_store = StateStore()
    runtime = GwmCloudClient(
        "aus",
        _ReadClient(),
        bootstrap=bootstrap,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    await runtime.async_authentication_rejected()

    assert runtime.reusable_bootstrap is None
    assert state_store.cleared == cloud_entry_data(credentials)


@pytest.mark.asyncio
async def test_china_runtime_handoff_maps_platform_capabilities_and_no_pin_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = GwmCloudCredentials(
        "cn",
        "CN",
        "13800138000",
        None,
        _DEVICE_ID,
    )
    regional = credentials.client_credentials()
    state = replace(
        ChinaAuthState.for_credentials(regional),
        g_token="synthetic-g-token",
        g_refresh_token="synthetic-g-refresh-token",
        user_id="synthetic-g-user",
        bean_id="synthetic-g-bean",
        bean_tech_access_token="synthetic-bean-access-token",
        auto_ai_token_id="synthetic-auto-token",
        auto_ai_user_id="synthetic-auto-user",
    )
    bootstrap = GwmCloudBootstrap.from_authentication(
        credentials,
        ChinaAuthenticated(state),
    )
    navinfo = ChinaVehicle(
        identifier=VehicleIdentifier("LGWTEST0000000001"),
        app_show_series_name="Synthetic NavInfo",
        platform="navinfo",
    )
    beantech = ChinaVehicle(
        identifier=VehicleIdentifier("LGWTEST0000000002"),
        app_show_series_name="Synthetic BeanTech",
        platform="beantech",
    )

    class ChinaReadClient:
        authenticated = True

        def __init__(self) -> None:
            self.climate: list[ClimateCommand] = []
            self.locks: list[DoorLockCommand] = []
            self.windows: list[CloseWindowsCommand] = []
            self.controls: list[ChinaVehicleControlCommand] = []
            self.charging: list[ChargingPlanCommand] = []
            self.closed = False

        async def acquire_vehicles(self) -> tuple[ChinaVehicle, ...]:
            return (navinfo, beantech)

        async def get_last_status(
            self,
            identifier: VehicleIdentifier,
        ) -> CloudVehicleStatus:
            return CloudVehicleStatus(device_id=f"serial-{identifier.value[-1]}")

        async def get_charging_plan(
            self,
            identifier: VehicleIdentifier,
        ) -> ChargingPlanInfo:
            assert identifier == navinfo.identifier
            return ChargingPlanInfo()

        async def set_charging_plan(self, command: ChargingPlanCommand) -> None:
            self.charging.append(command)

        async def send_climate_command(
            self,
            command: ClimateCommand,
        ) -> RemoteCommandAcceptance:
            self.climate.append(command)
            return RemoteCommandAcceptance("china-climate-command")

        async def send_lock_command(
            self,
            command: DoorLockCommand,
        ) -> RemoteCommandAcceptance:
            self.locks.append(command)
            return RemoteCommandAcceptance("china-lock-command")

        async def send_close_windows_command(
            self,
            command: CloseWindowsCommand,
        ) -> RemoteCommandAcceptance:
            self.windows.append(command)
            return RemoteCommandAcceptance("china-window-command")

        async def send_vehicle_control_command(
            self,
            command: ChinaVehicleControlCommand,
        ) -> RemoteCommandAcceptance:
            self.controls.append(command)
            return RemoteCommandAcceptance("china-control-command")

        async def get_remote_command_results(
            self,
            identifier: VehicleIdentifier,
            command_id: str,
        ) -> tuple[()]:
            del identifier, command_id
            return ()

        async def aclose(self) -> None:
            self.authenticated = False
            self.closed = True

    client = ChinaReadClient()

    def create_china_client(*args: object, **kwargs: object) -> ChinaReadClient:
        assert kwargs["authenticated_state"] == state
        return client

    monkeypatch.setattr(cloud_runtime, "ChinaClient", create_china_client)
    runtime = GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials),
        cloud_unique_id(credentials),
        bootstrap,
        climate_commands_enabled=True,
        lock_window_commands_enabled=True,
        charging_control_enabled=True,
    )

    result = await runtime.async_get_vehicle_data()
    snapshots = result["vehicles"]
    assert isinstance(snapshots, list)
    assert snapshots[0]["capabilities"] == {
        "remote_commands": True,
        "charging_control": True,
        "climate_commands": True,
        "lock_window_commands": True,
        "china_vehicle_commands": True,
    }
    assert snapshots[1]["capabilities"] == {
        "remote_commands": True,
        "charging_control": False,
        "climate_commands": False,
        "lock_window_commands": True,
        "china_vehicle_commands": True,
    }

    context = await runtime.async_get_climate_context(
        navinfo.identifier,
        include_status=False,
    )
    assert context.basics.climate == CloudClimateConfiguration("22", "900")
    await runtime.async_update_climate_defaults(
        navinfo.identifier,
        temperature=25,
        operation_time_minutes=20,
    )
    updated = await runtime.async_get_climate_context(
        navinfo.identifier,
        include_status=False,
    )
    assert updated.basics.climate == CloudClimateConfiguration("25", "1200")

    climate = ClimateCommand(navinfo.identifier, "heat", 25, 20, False)
    lock = DoorLockCommand(beantech.identifier, True)
    windows = CloseWindowsCommand(beantech.identifier)
    control = ChinaVehicleControlCommand(beantech.identifier, "horn")
    charging = ChargingPlanCommand(navinfo.identifier, False)
    await runtime.async_send_climate_command(climate)
    await runtime.async_send_lock_command(lock)
    await runtime.async_send_close_windows_command(windows)
    await runtime.async_send_vehicle_control_command(control)
    await runtime.async_set_charging_plan(charging)

    assert client.climate == [climate]
    assert client.locks == [lock]
    assert client.windows == [windows]
    assert client.controls == [control]
    assert client.charging == [charging]
    with pytest.raises(GwmRoutePolicyError):
        await runtime.async_get_climate_context(
            beantech.identifier,
            include_status=False,
        )
    await runtime.aclose()
    assert client.closed
