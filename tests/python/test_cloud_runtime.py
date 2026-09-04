"""Offline tests for the GWM cloud read runtime and bounded handoff."""

from __future__ import annotations

import asyncio
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
    AnzCredentials,
    CabinCleanCommand,
    ChargingPlanCommand,
    ChargingPlanInfo,
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaVehicle,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloudClimateConfiguration,
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    EuAuthenticated,
    EuAuthState,
    EuCredentials,
    FrontDefrosterCommand,
    GwmApiError,
    GwmAuthenticationError,
    GwmClient,
    GwmConfigurationError,
    GwmNetworkError,
    GwmOptionalEndpointError,
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
        refresh_token="synthetic-refresh-token",
        gw_id="synthetic-gw-id",
    )
    session = GwmSession(
        "AU",
        _DEVICE_ID,
        "synthetic-access-token",
        ssl.create_default_context(),
        gw_id="synthetic-gw-id",
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
                items=(
                    CloudStatusItem("2013021", 80, "%"),
                    CloudStatusItem("2078020", 0),
                    CloudStatusItem("2222001", 0),
                ),
            ),
            "SYNTHETIC-VEHICLE-B": CloudVehicleStatus(
                device_id="SYNTHETIC-SERIAL-B",
                items=(CloudStatusItem("2013021", 55, "%"),),
            ),
        }
        self.basics: dict[str, CloudVehicleBasics | Exception] = {
            "SYNTHETIC-VEHICLE-A": CloudVehicleBasics(CloudClimateConfiguration(temperature="23", operation_time="15")),
            "SYNTHETIC-VEHICLE-B": GwmOptionalEndpointError(
                operation="vehicle_basics",
                api_code="607099",
            ),
        }
        self.calls: list[tuple[str, str | None]] = []
        self.charging_commands: list[ChargingPlanCommand] = []
        self.front_defroster_commands: list[FrontDefrosterCommand] = []
        self.cabin_clean_commands: list[CabinCleanCommand] = []

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

    async def send_front_defroster_command(
        self,
        command: FrontDefrosterCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance:
        assert len(security_password_hash) == 32
        self.front_defroster_commands.append(command)
        return RemoteCommandAcceptance("provider-command-defrost")

    async def send_cabin_clean_command(
        self,
        command: CabinCleanCommand,
        *,
        security_password_hash: str,
    ) -> RemoteCommandAcceptance:
        assert len(security_password_hash) == 32
        self.cabin_clean_commands.append(command)
        return RemoteCommandAcceptance("provider-command-cabin-clean")

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
    assert isinstance(runtime._client, GwmClient)
    assert runtime._client._config.anz_authentication_method == ANZ_AUTHENTICATION_METHOD_CURRENT
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
    assert all(vehicle["timestamps"]["last_refresh"] == "2026-08-28T12:00:00+00:00" for vehicle in vehicles)


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
    assert all(vehicle["capabilities"]["charging_control"] is True for vehicle in result["vehicles"])
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE-A")
    assert await runtime.async_get_charging_plan(identifier) == ChargingPlanInfo()
    command = ChargingPlanCommand(identifier, False)
    await runtime.async_set_charging_plan(command)
    assert client.charging_commands == [command]


@pytest.mark.asyncio
async def test_overseas_comfort_controls_require_reported_status_and_delegate_typed_commands() -> None:
    client = _ReadClient()
    runtime = GwmCloudClient(
        "aus",
        client,
        clock=lambda: _REFRESHED_AT,
        climate_commands_enabled=True,
    )

    result = await runtime.async_get_vehicle_data()
    vehicles = result["vehicles"]
    assert isinstance(vehicles, list)
    assert vehicles[0]["capabilities"]["front_defroster_commands"] is True
    assert vehicles[0]["capabilities"]["cabin_clean_commands"] is True
    assert vehicles[1]["capabilities"]["front_defroster_commands"] is False
    assert vehicles[1]["capabilities"]["cabin_clean_commands"] is False

    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE-A")
    defrost = FrontDefrosterCommand(identifier, True)
    cabin_clean = CabinCleanCommand(identifier)
    await runtime.async_send_front_defroster_command(
        defrost,
        security_password_hash="0123456789abcdef0123456789abcdef",
    )
    await runtime.async_send_cabin_clean_command(
        cabin_clean,
        security_password_hash="0123456789abcdef0123456789abcdef",
    )

    assert client.front_defroster_commands == [defrost]
    assert client.cabin_clean_commands == [cabin_clean]


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
async def test_expired_current_anz_session_rotates_once_persists_and_retries() -> None:
    credentials, bootstrap = _bootstrap()

    class RenewingReadClient(_ReadClient):
        def __init__(self) -> None:
            super().__init__()
            self.expired = True
            self.refresh_calls = 0

        async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
            if self.expired:
                await asyncio.sleep(0)
                raise GwmApiError(
                    operation="acquire_vehicles",
                    api_code="550004",
                )
            return await super().acquire_vehicles()

        async def refresh_current_anz_session(
            self,
            regional_credentials: AnzCredentials,
            state: AnzAuthState,
        ) -> AnzAuthenticated:
            assert regional_credentials == credentials.client_credentials()
            self.refresh_calls += 1
            await asyncio.sleep(0.01)
            self.expired = False
            updated_state = replace(
                state,
                access_token="synthetic-rotated-access-token",
                refresh_token="synthetic-rotated-refresh-token",
            )
            return AnzAuthenticated(
                updated_state,
                GwmSession(
                    "AU",
                    _DEVICE_ID,
                    "synthetic-rotated-access-token",
                    ssl.create_default_context(),
                    gw_id="synthetic-gw-id",
                ),
            )

    class StateStore:
        def __init__(self) -> None:
            self.saved: list[AnzAuthState] = []
            self.cleared = False

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            state: AnzAuthState,
        ) -> None:
            assert saved_credentials is credentials
            self.saved.append(state)

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            del data
            self.cleared = True

    client = RenewingReadClient()
    state_store = StateStore()
    runtime = GwmCloudClient(
        "aus",
        client,
        clock=lambda: _REFRESHED_AT,
        bootstrap=bootstrap,
        credentials=credentials,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    first, second = await asyncio.gather(
        runtime.async_get_vehicle_data(),
        runtime.async_get_vehicle_data(),
    )

    assert first["vehicles"] == second["vehicles"]
    assert client.refresh_calls == 1
    assert len(state_store.saved) == 1
    assert state_store.saved[0].access_token == "synthetic-rotated-access-token"
    assert state_store.saved[0].refresh_token == "synthetic-rotated-refresh-token"
    assert not state_store.cleared
    assert runtime.reusable_bootstrap is not None
    assert runtime.reusable_bootstrap.state == state_store.saved[0]


@pytest.mark.asyncio
async def test_expired_eu_session_rotates_persists_and_retries() -> None:
    credentials = GwmCloudCredentials(
        "eu",
        "IL",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
    )
    regional = credentials.client_credentials()
    assert type(regional) is EuCredentials
    state = replace(
        EuAuthState.for_credentials(regional),
        access_token="synthetic-eu-access-token",
        refresh_token="synthetic-eu-refresh-token",
        gw_id="synthetic-eu-gw-id",
        bean_id="synthetic-eu-bean-id",
    )
    bootstrap = GwmCloudBootstrap.from_authentication(
        credentials,
        EuAuthenticated(
            state,
            GwmSession(
                "IL",
                _DEVICE_ID,
                "synthetic-eu-access-token",
                ssl.create_default_context(),
            ),
        ),
    )

    class RenewingReadClient(_ReadClient):
        def __init__(self) -> None:
            super().__init__()
            self.basics["SYNTHETIC-VEHICLE-B"] = CloudVehicleBasics()
            self.expired = True
            self.refresh_calls = 0

        async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
            if self.expired:
                raise GwmApiError(
                    operation="acquire_vehicles",
                    api_code="550004",
                )
            return await super().acquire_vehicles()

        async def refresh_eu_session(
            self,
            regional_credentials: EuCredentials,
            expired_state: EuAuthState,
        ) -> EuAuthenticated:
            assert regional_credentials == regional
            self.refresh_calls += 1
            self.expired = False
            updated_state = replace(
                expired_state,
                access_token="synthetic-eu-rotated-access-token",
                refresh_token="synthetic-eu-rotated-refresh-token",
            )
            return EuAuthenticated(
                updated_state,
                GwmSession(
                    "IL",
                    _DEVICE_ID,
                    "synthetic-eu-rotated-access-token",
                    ssl.create_default_context(),
                ),
            )

    class StateStore:
        def __init__(self) -> None:
            self.saved: list[EuAuthState] = []

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            saved_state: EuAuthState,
        ) -> None:
            assert saved_credentials is credentials
            self.saved.append(saved_state)

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            del data
            raise AssertionError("renewed state must not be cleared")

    client = RenewingReadClient()
    state_store = StateStore()
    runtime = GwmCloudClient(
        "eu",
        client,
        bootstrap=bootstrap,
        credentials=credentials,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    result = await runtime.async_get_vehicle_data()

    assert len(result["vehicles"]) == 2
    assert client.refresh_calls == 1
    assert len(state_store.saved) == 1
    assert state_store.saved[0].access_token == "synthetic-eu-rotated-access-token"
    assert state_store.saved[0].refresh_token == "synthetic-eu-rotated-refresh-token"


@pytest.mark.asyncio
async def test_unknown_refresh_error_preserves_durable_session() -> None:
    credentials, bootstrap = _bootstrap()

    class FailingRefreshClient(_ReadClient):
        async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
            raise GwmApiError(
                operation="acquire_vehicles",
                api_code="550004",
            )

        async def refresh_current_anz_session(
            self,
            regional_credentials: AnzCredentials,
            state: AnzAuthState,
        ) -> AnzAuthenticated:
            del regional_credentials, state
            raise GwmApiError(
                operation="refresh_token",
                api_code="550002",
            )

    class StateStore:
        cleared = False

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            saved_state: AnzAuthState,
        ) -> None:
            del saved_credentials, saved_state
            raise AssertionError("a failed refresh must not be saved")

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            del data
            self.cleared = True

    state_store = StateStore()
    runtime = GwmCloudClient(
        "aus",
        FailingRefreshClient(),
        bootstrap=bootstrap,
        credentials=credentials,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    with pytest.raises(GwmApiError) as raised:
        await runtime.async_get_vehicle_data()

    assert raised.value.api_code == "550002"
    assert not state_store.cleared
    assert runtime.reusable_bootstrap == bootstrap


@pytest.mark.asyncio
async def test_rotated_session_is_not_retried_until_durable_save_succeeds() -> None:
    credentials, bootstrap = _bootstrap()

    class RenewingReadClient(_ReadClient):
        def __init__(self) -> None:
            super().__init__()
            self.expired = True
            self.refresh_calls = 0
            self.read_calls = 0

        async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
            self.read_calls += 1
            if self.expired:
                raise GwmApiError(
                    operation="acquire_vehicles",
                    api_code="550004",
                )
            return await super().acquire_vehicles()

        async def refresh_current_anz_session(
            self,
            regional_credentials: AnzCredentials,
            state: AnzAuthState,
        ) -> AnzAuthenticated:
            assert regional_credentials == credentials.client_credentials()
            self.refresh_calls += 1
            self.expired = False
            updated_state = replace(
                state,
                access_token="synthetic-rotated-access-token",
                refresh_token="synthetic-rotated-refresh-token",
            )
            return AnzAuthenticated(
                updated_state,
                GwmSession(
                    "AU",
                    _DEVICE_ID,
                    "synthetic-rotated-access-token",
                    ssl.create_default_context(),
                    gw_id="synthetic-gw-id",
                ),
            )

    class StateStore:
        def __init__(self) -> None:
            self.save_calls = 0
            self.cleared = False

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            saved_state: AnzAuthState,
        ) -> None:
            del saved_credentials, saved_state
            self.save_calls += 1
            if self.save_calls == 1:
                raise OSError("synthetic storage failure")

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            del data
            self.cleared = True

    client = RenewingReadClient()
    state_store = StateStore()
    runtime = GwmCloudClient(
        "aus",
        client,
        bootstrap=bootstrap,
        credentials=credentials,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    with pytest.raises(GwmNetworkError):
        await runtime.async_get_vehicle_data()

    assert client.refresh_calls == 1
    assert client.read_calls == 1
    assert state_store.save_calls == 1
    assert not state_store.cleared

    result = await runtime.async_get_vehicle_data()

    assert result["vehicles"]
    assert client.refresh_calls == 1
    assert client.read_calls == 2
    assert state_store.save_calls == 2


@pytest.mark.asyncio
async def test_expired_current_session_without_refresh_token_requests_reauth() -> None:
    credentials, bootstrap = _bootstrap()
    state = replace(bootstrap.state, refresh_token=None)
    bootstrap = GwmCloudBootstrap(
        region=bootstrap.region,
        account_binding=bootstrap.account_binding,
        state=state,
        session=bootstrap.session,
    )

    class ExpiredReadClient(_ReadClient):
        async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
            raise GwmApiError(
                operation="acquire_vehicles",
                api_code="550004",
            )

    class StateStore:
        cleared = False

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            saved_state: AnzAuthState,
        ) -> None:
            del saved_credentials, saved_state
            raise AssertionError("expired state must not be saved")

        async def async_clear_auth_state(self, data: dict[str, object]) -> None:
            del data
            self.cleared = True

    state_store = StateStore()
    runtime = GwmCloudClient(
        "aus",
        ExpiredReadClient(),
        bootstrap=bootstrap,
        credentials=credentials,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
    )

    with pytest.raises(GwmAuthenticationError) as raised:
        await runtime.async_get_vehicle_data()

    assert raised.value.api_code == "550004"
    assert state_store.cleared
    assert runtime.reusable_bootstrap is None


@pytest.mark.asyncio
async def test_rejected_runtime_revision_cannot_be_restaged() -> None:
    credentials, bootstrap = _bootstrap()

    class StateStore:
        cleared: dict[str, object] | None = None

        async def async_save_auth_state(
            self,
            saved_credentials: GwmCloudCredentials,
            state: AnzAuthState,
        ) -> None:
            del saved_credentials, state

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

        async def get_bean_tech_ac_temperature(
            self,
            identifier: VehicleIdentifier,
        ) -> int | None:
            del identifier
            return None

        async def set_charging_plan(self, command: ChargingPlanCommand) -> None:
            self.charging.append(command)

        async def send_climate_command(
            self,
            command: ClimateCommand,
        ) -> RemoteCommandAcceptance:
            self.climate.append(command)
            return RemoteCommandAcceptance("china-climate-command")

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
        "lock_window_commands": False,
        "china_vehicle_commands": True,
        "front_defroster_commands": False,
        "cabin_clean_commands": False,
    }
    assert snapshots[1]["capabilities"] == {
        "remote_commands": True,
        "charging_control": False,
        "climate_commands": True,
        "lock_window_commands": False,
        "china_vehicle_commands": True,
        "front_defroster_commands": False,
        "cabin_clean_commands": False,
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
    control = ChinaVehicleControlCommand(beantech.identifier, "seat_heating_start")
    charging = ChargingPlanCommand(navinfo.identifier, False)
    await runtime.async_send_climate_command(climate)
    await runtime.async_send_vehicle_control_command(control)
    await runtime.async_set_charging_plan(charging)

    assert client.climate == [climate]
    assert client.controls == [control]
    assert client.charging == [charging]
    beantech_context = await runtime.async_get_climate_context(
        beantech.identifier,
        include_status=False,
    )
    assert beantech_context.basics.climate == CloudClimateConfiguration("22", "900")
    await runtime.async_update_climate_defaults(
        beantech.identifier,
        temperature=25,
        operation_time_minutes=20,
    )
    beantech_updated = await runtime.async_get_climate_context(
        beantech.identifier,
        include_status=False,
    )
    assert beantech_updated.basics.climate == CloudClimateConfiguration("25", "1200")
    await runtime.aclose()
    assert client.closed
