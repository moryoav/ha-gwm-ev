"""Cloud command orchestration, journal recovery, timeout, and isolation tests."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.cloud_auth import (
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_commands import GwmCommandApi
from custom_components.gwm_ora.cloud_runtime import GwmClimateContext
from custom_components.gwm_ora.cloud_storage import cloud_state_store
from custom_components.gwm_ora.errors import GwmCommandError, GwmCommandForbidden
from gwm_client import (
    AnzAuthState,
    ChargingPlanCommand,
    ChargingPlanInfo,
    ChargingPlanItem,
    ChinaAuthState,
    ChinaCredentials,
    ChinaVehicleControlCommand,
    CloudClimateConfiguration,
    CloudStatusItem,
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    EuAuthState,
    EuIssuedIdentity,
    GwmApiError,
    RemoteCommandAcceptance,
    RemoteCommandResultItem,
    RussiaAuthState,
    VehicleIdentifier,
)

_NOW = datetime(2026, 8, 28, 18, 0, tzinfo=UTC)
_VIN = "LGWEEUA50PK000001"
_DEVICE_ID = "0123456789abcdef0123456789abcdef"


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> datetime:
        return self.value


class _Cloud:
    region = "eu"

    def __init__(self, *, currently_on: bool = True) -> None:
        self.currently_on = currently_on
        self.updated: list[tuple[int, int]] = []
        self.sent = []
        self.lock_sent = []
        self.windows_sent = []
        self.vehicle_controls_sent: list[ChinaVehicleControlCommand] = []
        self.charging_sent: list[ChargingPlanCommand] = []
        self.charging_info = ChargingPlanInfo()
        self.charging_error: BaseException | None = None
        self.poll_results: list[tuple[RemoteCommandResultItem, ...]] = []
        self.send_error: BaseException | None = None

    async def async_get_climate_context(
        self,
        identifier: VehicleIdentifier,
        *,
        include_status: bool,
    ) -> GwmClimateContext:
        status = (
            CloudVehicleStatus(
                items=(CloudStatusItem("2202001", "1" if self.currently_on else "0"),)
            )
            if include_status
            else None
        )
        return GwmClimateContext(
            vehicle=CloudVehicle(identifier),
            basics=CloudVehicleBasics(CloudClimateConfiguration("22", "900")),
            status=status,
        )

    async def async_update_climate_defaults(
        self,
        identifier: VehicleIdentifier,
        *,
        temperature: int,
        operation_time_minutes: int,
    ) -> None:
        assert identifier.value == _VIN
        self.updated.append((temperature, operation_time_minutes))

    async def async_send_climate_command(
        self,
        command: object,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.send_error is not None:
            raise self.send_error
        if self.region == "cn":
            assert security_password_hash is None
        else:
            assert security_password_hash is not None
            assert len(security_password_hash) == 32
        self.sent.append(command)
        return RemoteCommandAcceptance("provider-command-1")

    async def async_get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
    ) -> tuple[RemoteCommandResultItem, ...]:
        assert identifier.value == _VIN
        assert command_id.startswith("provider-command-")
        return self.poll_results.pop(0) if self.poll_results else ()

    async def async_send_lock_command(
        self,
        command: object,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.send_error is not None:
            raise self.send_error
        if self.region == "cn":
            assert security_password_hash is None
        else:
            assert security_password_hash is not None
            assert len(security_password_hash) == 32
        self.lock_sent.append(command)
        return RemoteCommandAcceptance("provider-command-lock")

    async def async_send_close_windows_command(
        self,
        command: object,
        *,
        security_password_hash: str | None = None,
    ) -> RemoteCommandAcceptance:
        if self.send_error is not None:
            raise self.send_error
        if self.region == "cn":
            assert security_password_hash is None
        else:
            assert security_password_hash is not None
            assert len(security_password_hash) == 32
        self.windows_sent.append(command)
        return RemoteCommandAcceptance("provider-command-windows")

    async def async_send_vehicle_control_command(
        self,
        command: ChinaVehicleControlCommand,
    ) -> RemoteCommandAcceptance:
        if self.send_error is not None:
            raise self.send_error
        self.vehicle_controls_sent.append(command)
        return RemoteCommandAcceptance("provider-command-control")

    async def async_get_vehicle_data(self) -> dict[str, object]:
        return {"region": self.region, "vehicles": []}

    async def async_get_charging_plan(
        self,
        identifier: VehicleIdentifier,
    ) -> ChargingPlanInfo:
        assert identifier.value == _VIN
        if self.charging_error is not None:
            raise self.charging_error
        return self.charging_info

    async def async_set_charging_plan(self, command: ChargingPlanCommand) -> None:
        if self.charging_error is not None:
            raise self.charging_error
        self.charging_sent.append(command)


def _credentials(region: str = "eu") -> GwmCloudCredentials:
    country = {"eu": "DE", "aus": "AU", "rus": "RU"}[region]
    return GwmCloudCredentials(
        region,
        country,
        "private-account",
        "private-password",
        _DEVICE_ID,
    )


def _state(credentials: GwmCloudCredentials) -> Any:
    client_credentials = credentials.client_credentials()
    if credentials.region == "eu":
        return replace(
            EuAuthState.for_credentials(client_credentials),  # type: ignore[arg-type]
            access_token="private-access",
            refresh_token="private-refresh",
            gw_id="private-gw",
            bean_id="private-bean",
            issued_identity=EuIssuedIdentity(
                certificate=base64.b64encode(b"synthetic-certificate").decode(),
                private_key=base64.b64encode(b"synthetic-private-key").decode(),
            ),
        )
    if credentials.region == "aus":
        return replace(
            AnzAuthState.for_credentials(client_credentials),  # type: ignore[arg-type]
            access_token="private-access",
            refresh_token="private-refresh",
        )
    return replace(
        RussiaAuthState.for_credentials(client_credentials),  # type: ignore[arg-type]
        access_token="private-access",
        refresh_token="private-refresh",
        gw_id="private-gw",
        bean_id="private-bean",
    )


async def _api(
    tmp_path: Path,
    cloud: _Cloud,
    clock: _Clock,
    *,
    enabled: bool = True,
    charging_enabled: bool = False,
    region: str = "eu",
) -> tuple[GwmCommandApi, Any, GwmCloudCredentials]:
    credentials = _credentials(region)
    cloud.region = region
    hass = HomeAssistant(str(tmp_path))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, _state(credentials))
    api = GwmCommandApi(
        cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=enabled,
        charging_enabled=charging_enabled,
        security_pin="1234" if enabled else None,
        clock=clock,
    )
    return api, store, credentials


async def _china_api(
    tmp_path: Path,
    cloud: _Cloud,
    clock: _Clock,
    *,
    enabled: bool = True,
) -> tuple[GwmCommandApi, Any, GwmCloudCredentials]:
    credentials = GwmCloudCredentials(
        "cn",
        "CN",
        "13800138000",
        None,
        _DEVICE_ID,
    )
    hass = HomeAssistant(str(tmp_path))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(
        credentials,
        ChinaAuthState.for_credentials(
            ChinaCredentials(credentials.account, credentials.device_id)
        ),
    )
    cloud.region = "cn"
    api = GwmCommandApi(
        cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=enabled,
        security_pin=None,
        clock=clock,
    )
    return api, store, credentials


@pytest.mark.asyncio
async def test_acceptance_is_journaled_before_polling_and_reaches_terminal_result(
    tmp_path: Path,
) -> None:
    cloud = _Cloud()
    cloud.poll_results = [
        (RemoteCommandResultItem("provider-command-1", "0x04", "2000", "Waiting"),),
        (RemoteCommandResultItem("provider-command-1", "0x04", "0", "Success"),),
    ]
    clock = _Clock()
    api, store, credentials = await _api(tmp_path, cloud, clock)

    accepted = await api.async_set_climate(_VIN, mode="cool", temperature=21)
    journal = await store.async_get_command_journal(cloud_entry_data(credentials))
    assert accepted["state"] == "in_progress"
    assert len(journal) == 1
    assert journal[0].cloud_command_id == "provider-command-1"
    assert journal[0].state == "accepted"
    assert cloud.updated == [(21, 15)]
    assert len(cloud.sent) == 1

    pending = await api.async_get_command(str(accepted["id"]))
    assert pending["state"] == "in_progress"
    assert (await store.async_get_command_journal(cloud_entry_data(credentials)))[
        0
    ].state == "polling"
    completed = await api.async_get_command(str(accepted["id"]))
    assert completed["state"] == "completed"
    assert "Success [0]" in str(completed["status"])
    assert (await store.async_get_command_journal(cloud_entry_data(credentials)))[
        0
    ].state == "completed"


@pytest.mark.asyncio
async def test_restart_restores_polling_without_resending_vehicle_operation(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    first_cloud = _Cloud()
    first, store, credentials = await _api(tmp_path, first_cloud, clock)
    accepted = await first.async_set_climate(_VIN, mode="cool")
    assert len(first_cloud.sent) == 1

    second_cloud = _Cloud()
    second_cloud.poll_results = [
        (RemoteCommandResultItem("provider-command-1", "0x04", "6", "Success"),)
    ]
    second = GwmCommandApi(
        second_cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=True,
        security_pin="1234",
        clock=clock,
    )
    restored = await second.async_restore(cloud_entry_data(credentials))
    assert restored[0]["id"] == accepted["id"]
    assert second_cloud.sent == []
    completed = await second.async_get_command(str(accepted["id"]))
    assert completed["state"] == "completed"
    assert second_cloud.sent == []


@pytest.mark.asyncio
async def test_timeout_is_persisted_without_an_extra_poll(tmp_path: Path) -> None:
    cloud = _Cloud()
    clock = _Clock()
    api, store, credentials = await _api(tmp_path, cloud, clock)
    accepted = await api.async_set_climate(_VIN, mode="cool")
    clock.value += timedelta(seconds=91)

    timed_out = await api.async_get_command(str(accepted["id"]))
    assert timed_out["state"] == "timeout"
    assert cloud.poll_results == []
    assert (await store.async_get_command_journal(cloud_entry_data(credentials)))[
        0
    ].state == "failed"


@pytest.mark.asyncio
async def test_rejection_and_disabled_mode_never_create_a_journal_entry(
    tmp_path: Path,
) -> None:
    cloud = _Cloud()
    cloud.send_error = GwmApiError(operation="send_climate_command", api_code="607777")
    clock = _Clock()
    api, store, credentials = await _api(tmp_path, cloud, clock)
    with pytest.raises(GwmApiError):
        await api.async_set_climate(_VIN, mode="cool")
    assert await store.async_get_command_journal(cloud_entry_data(credentials)) == ()

    disabled, _store, _credentials_value = await _api(
        tmp_path / "disabled", _Cloud(), clock, enabled=False
    )
    with pytest.raises(GwmCommandForbidden):
        await disabled.async_set_climate(_VIN, mode="cool")


@pytest.mark.asyncio
async def test_runtime_only_and_temperature_while_off_save_without_command(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud(currently_on=False)
    api, _store, _credentials_value = await _api(tmp_path, cloud, clock)

    runtime = await api.async_set_climate(_VIN, operation_time_minutes=20)
    temperature = await api.async_set_climate(_VIN, temperature=24)
    assert runtime["state"] == "completed"
    assert temperature["state"] == "completed"
    assert cloud.updated == [(22, 20), (24, 20)]
    assert cloud.sent == []


@pytest.mark.asyncio
async def test_saved_runtime_is_used_by_immediate_climate_start(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud(currently_on=False)
    api, _store, _credentials_value = await _api(tmp_path, cloud, clock)

    saved = await api.async_set_climate(_VIN, operation_time_minutes=5)
    started = await api.async_set_climate(_VIN, mode="cool")

    assert saved["state"] == "completed"
    assert started["state"] == "in_progress"
    assert cloud.updated == [(22, 5), (22, 5)]
    assert len(cloud.sent) == 1
    assert cloud.sent[0].operation_time_minutes == 5
    assert api.climate_operation_time_minutes(_VIN) == 5


@pytest.mark.asyncio
async def test_lock_and_window_acceptance_use_same_restart_safe_journal(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    first_cloud = _Cloud()
    first, store, credentials = await _api(tmp_path, first_cloud, clock)

    locked = await first.async_lock(_VIN, "lock")
    closed = await first.async_close_windows(_VIN)
    journal = await store.async_get_command_journal(cloud_entry_data(credentials))

    assert [entry.command_name for entry in journal] == ["Door lock", "Window close"]
    assert locked["state"] == closed["state"] == "in_progress"
    assert len(first_cloud.lock_sent) == len(first_cloud.windows_sent) == 1

    second_cloud = _Cloud()
    second_cloud.poll_results = [
        (
            RemoteCommandResultItem("stale", "0x04", "9", "Wrong family"),
            RemoteCommandResultItem("provider-command-lock", "0x05", "6", "Success"),
        ),
        (
            RemoteCommandResultItem("stale", "0x04", "9", "Wrong family"),
            RemoteCommandResultItem(
                "provider-command-windows", "0x08", "6", "Success"
            ),
        ),
    ]
    second = GwmCommandApi(
        second_cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=True,
        security_pin="1234",
        clock=clock,
    )
    restored = await second.async_restore(cloud_entry_data(credentials))

    assert {item["id"] for item in restored} == {locked["id"], closed["id"]}
    assert second_cloud.lock_sent == second_cloud.windows_sent == []
    assert (await second.async_get_command(str(locked["id"])))["state"] == "completed"
    assert (await second.async_get_command(str(closed["id"])))["state"] == "completed"
    assert second_cloud.lock_sent == second_cloud.windows_sent == []


@pytest.mark.asyncio
async def test_lock_window_validation_rejection_and_disabled_mode_are_fail_closed(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    api, store, credentials = await _api(tmp_path, cloud, clock)

    with pytest.raises(GwmCommandError, match="action must be"):
        await api.async_lock(_VIN, "open")
    with pytest.raises(GwmCommandError, match="valid vehicle"):
        await api.async_close_windows(" ")
    assert await store.async_get_command_journal(cloud_entry_data(credentials)) == ()
    assert cloud.lock_sent == cloud.windows_sent == []

    cloud.send_error = GwmApiError(operation="send_lock_command", api_code="607777")
    with pytest.raises(GwmApiError):
        await api.async_lock(_VIN, "unlock")
    assert await store.async_get_command_journal(cloud_entry_data(credentials)) == ()

    disabled, _store, _credentials_value = await _api(
        tmp_path / "disabled-lock",
        _Cloud(),
        clock,
        enabled=False,
    )
    with pytest.raises(GwmCommandForbidden):
        await disabled.async_close_windows(_VIN)


@pytest.mark.asyncio
async def test_charging_plan_write_read_and_clear_persist_exact_ownership(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    start = int(_NOW.timestamp() * 1000)
    end = start + 60 * 60 * 1000
    cloud.charging_info = ChargingPlanInfo(
        (ChargingPlanItem(42, "0", start, end, ""),)
    )
    api, store, credentials = await _api(
        tmp_path,
        cloud,
        clock,
        charging_enabled=True,
    )

    assert await api.async_set_charging_plan(
        _VIN,
        enable=True,
        start_time=start,
        end_time=end,
        plan_type=0,
    ) == {}
    owned = await store.async_get_owned_charging_plans(cloud_entry_data(credentials))
    assert len(owned) == 1
    assert owned[0].plan_id == 42
    assert owned[0].start_time_ms == start
    assert (await api.async_get_charging_plan(_VIN))["charge_plan_list"][0][
        "plan_id"
    ] == 42

    assert await api.async_set_charging_plan(_VIN, enable=False) == {}
    assert len(cloud.charging_sent) == 2
    assert cloud.charging_sent[1] == ChargingPlanCommand(
        VehicleIdentifier(_VIN),
        False,
    )
    assert await store.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == ()


@pytest.mark.asyncio
async def test_charging_opt_out_clears_exact_match_but_preserves_app_replacement(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    start = int(_NOW.timestamp() * 1000)
    end = start + 60 * 60 * 1000
    cloud.charging_info = ChargingPlanInfo(
        (ChargingPlanItem(42, "0", start, end, ""),)
    )
    enabled, store, credentials = await _api(
        tmp_path,
        cloud,
        clock,
        charging_enabled=True,
    )
    await enabled.async_set_charging_plan(
        _VIN,
        enable=True,
        start_time=start,
        end_time=end,
    )
    disabled = GwmCommandApi(
        cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=False,
        charging_enabled=False,
        security_pin=None,
        clock=clock,
    )

    await disabled.async_cleanup_owned_charging_plans(cloud_entry_data(credentials))
    assert [command.enable for command in cloud.charging_sent] == [True, False]
    assert await store.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == ()

    cloud.charging_info = ChargingPlanInfo(
        (ChargingPlanItem(50, "0", start, end, ""),)
    )
    await enabled.async_set_charging_plan(
        _VIN,
        enable=True,
        start_time=start,
        end_time=end,
    )
    cloud.charging_info = ChargingPlanInfo(
        (ChargingPlanItem(99, "0", start + 1000, end + 1000, ""),)
    )
    before = len(cloud.charging_sent)
    await disabled.async_cleanup_owned_charging_plans(cloud_entry_data(credentials))

    assert len(cloud.charging_sent) == before
    assert await store.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == ()


@pytest.mark.asyncio
async def test_charging_disabled_and_provider_rejection_are_fail_closed(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    disabled, _store, _credentials_value = await _api(tmp_path, cloud, clock)
    with pytest.raises(GwmCommandForbidden):
        await disabled.async_set_charging_plan(_VIN, enable=False)
    assert cloud.charging_sent == []

    enabled, provider_store, provider_credentials = await _api(
        tmp_path / "provider-error",
        cloud,
        clock,
        charging_enabled=True,
    )
    cloud.charging_error = GwmApiError(
        operation="set_charging_plan",
        api_code="607777",
    )
    with pytest.raises(GwmApiError):
        await enabled.async_set_charging_plan(_VIN, enable=False)
    assert cloud.charging_sent == []
    assert await provider_store.async_get_owned_charging_plans(
        cloud_entry_data(provider_credentials)
    ) == ()


@pytest.mark.asyncio
async def test_close_windows_timeout_is_terminal_without_an_extra_poll(
    tmp_path: Path,
) -> None:
    cloud = _Cloud()
    clock = _Clock()
    api, store, credentials = await _api(tmp_path, cloud, clock)
    accepted = await api.async_close_windows(_VIN)
    clock.value += timedelta(seconds=91)

    timed_out = await api.async_get_command(str(accepted["id"]))

    assert timed_out["state"] == "timeout"
    assert cloud.poll_results == []
    journal = await store.async_get_command_journal(cloud_entry_data(credentials))
    assert journal[0].state == "failed"


@pytest.mark.asyncio
async def test_china_vehicle_control_is_no_pin_journaled_and_restart_safe(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    first_cloud = _Cloud()
    first, store, credentials = await _china_api(tmp_path, first_cloud, clock)

    accepted = await first.async_vehicle_control(
        _VIN,
        "remote_start",
        run_time_minutes=20,
    )
    journal = await store.async_get_command_journal(cloud_entry_data(credentials))
    assert accepted["state"] == "in_progress"
    assert len(first_cloud.vehicle_controls_sent) == 1
    assert first_cloud.vehicle_controls_sent[0].run_time_minutes == 20
    assert journal[0].command_name == "Remote start"
    assert journal[0].cloud_command_id == "provider-command-control"

    second_cloud = _Cloud()
    second_cloud.region = "cn"
    second_cloud.poll_results = [
        (
            RemoteCommandResultItem(
                "provider-command-control",
                None,
                "0",
                "Success",
            ),
        )
    ]
    second = GwmCommandApi(
        second_cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=True,
        security_pin=None,
        clock=clock,
    )
    restored = await second.async_restore(cloud_entry_data(credentials))
    assert restored[0]["id"] == accepted["id"]
    assert second_cloud.vehicle_controls_sent == []
    completed = await second.async_get_command(str(accepted["id"]))
    assert completed["state"] == "completed"
    assert second_cloud.vehicle_controls_sent == []


@pytest.mark.asyncio
async def test_china_vehicle_control_validation_rejection_and_region_gate_are_local(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    api, store, credentials = await _china_api(tmp_path, cloud, clock)

    with pytest.raises(GwmCommandError, match="Unsupported China vehicle control"):
        await api.async_vehicle_control(_VIN, "tailgate_open", run_time_minutes=15)
    assert cloud.vehicle_controls_sent == []
    assert await store.async_get_command_journal(cloud_entry_data(credentials)) == ()

    cloud.send_error = GwmApiError(
        operation="send_vehicle_control_command",
        api_code="607777",
    )
    with pytest.raises(GwmApiError):
        await api.async_vehicle_control(_VIN, "horn")
    assert await store.async_get_command_journal(cloud_entry_data(credentials)) == ()

    overseas, _overseas_store, _overseas_credentials = await _api(
        tmp_path / "overseas-control",
        _Cloud(),
        clock,
    )
    with pytest.raises(GwmCommandForbidden, match="only for mainland China"):
        await overseas.async_vehicle_control(_VIN, "horn")


@pytest.mark.asyncio
@pytest.mark.parametrize("region", ["eu", "aus", "rus"])
async def test_overseas_write_lifecycle_matrix_resumes_every_family_without_resend(
    tmp_path: Path,
    region: str,
) -> None:
    clock = _Clock()
    first_cloud = _Cloud()
    first, store, credentials = await _api(
        tmp_path,
        first_cloud,
        clock,
        region=region,
    )

    accepted = (
        await first.async_set_climate(_VIN, mode="cool"),
        await first.async_lock(_VIN, "lock"),
        await first.async_close_windows(_VIN),
    )
    assert (
        len(await store.async_get_command_journal(cloud_entry_data(credentials))) == 3
    )

    second_cloud = _Cloud()
    second_cloud.region = region
    command_contracts = (
        ("provider-command-1", "0x04"),
        ("provider-command-lock", "0x05"),
        ("provider-command-windows", "0x08"),
    )
    second_cloud.poll_results = [
        (
            RemoteCommandResultItem("stale-command", "0xff", "9", "Wrong command"),
            RemoteCommandResultItem(
                None if region == "rus" else command_id,
                remote_type,
                "6",
                "Success",
            ),
        )
        for command_id, remote_type in command_contracts
    ]
    second = GwmCommandApi(
        second_cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=True,
        security_pin="1234",
        clock=clock,
    )

    restored = await second.async_restore(cloud_entry_data(credentials))
    assert {item["id"] for item in restored} == {item["id"] for item in accepted}
    assert second_cloud.sent == []
    assert second_cloud.lock_sent == []
    assert second_cloud.windows_sent == []

    for item in accepted:
        assert (await second.async_get_command(str(item["id"])))["state"] == "completed"

    assert second_cloud.sent == []
    assert second_cloud.lock_sent == []
    assert second_cloud.windows_sent == []
    assert {
        entry.state
        for entry in await store.async_get_command_journal(
            cloud_entry_data(credentials)
        )
    } == {"completed"}


@pytest.mark.asyncio
async def test_china_no_pin_lifecycle_journals_heat_lock_window_and_extended_controls(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    first_cloud = _Cloud()
    first, store, credentials = await _china_api(tmp_path, first_cloud, clock)

    accepted = (
        await first.async_set_climate(_VIN, mode="heat", temperature=26),
        await first.async_lock(_VIN, "unlock"),
        await first.async_close_windows(_VIN),
        await first.async_vehicle_control(_VIN, "sunroof_close"),
    )
    assert [
        entry.command_name
        for entry in await store.async_get_command_journal(
            cloud_entry_data(credentials)
        )
    ] == [
        "A/C",
        "Door unlock",
        "Window close",
        "Sunroof close",
    ]

    second_cloud = _Cloud()
    second_cloud.region = "cn"
    command_ids = (
        "provider-command-1",
        "provider-command-lock",
        "provider-command-windows",
        "provider-command-control",
    )
    second_cloud.poll_results = [
        (RemoteCommandResultItem(command_id, None, "0", "Success"),)
        for command_id in command_ids
    ]
    second = GwmCommandApi(
        second_cloud,  # type: ignore[arg-type]
        store,
        credentials,
        enabled=True,
        security_pin=None,
        clock=clock,
    )

    restored = await second.async_restore(cloud_entry_data(credentials))
    assert {item["id"] for item in restored} == {item["id"] for item in accepted}
    for item in accepted:
        assert (await second.async_get_command(str(item["id"])))["state"] == "completed"
    assert second_cloud.sent == []
    assert second_cloud.lock_sent == []
    assert second_cloud.windows_sent == []
    assert second_cloud.vehicle_controls_sent == []


@pytest.mark.asyncio
async def test_command_context_region_mismatch_fails_before_any_write(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    _api_value, store, credentials = await _api(tmp_path, cloud, clock)
    cloud.region = "aus"

    with pytest.raises(ValueError, match="gwm_command_api_invalid"):
        GwmCommandApi(
            cloud,  # type: ignore[arg-type]
            store,
            credentials,
            enabled=True,
            security_pin="1234",
            clock=clock,
        )

    assert cloud.sent == []
    assert cloud.lock_sent == []
    assert cloud.windows_sent == []


@pytest.mark.asyncio
async def test_cancellation_after_provider_acceptance_finishes_recovery_journal(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    api, store, credentials = await _api(tmp_path, cloud, clock)
    original = store.async_record_accepted_command
    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_record(*args: Any, **kwargs: Any) -> Any:
        started.set()
        await release.wait()
        return await original(*args, **kwargs)

    store.async_record_accepted_command = delayed_record  # type: ignore[method-assign]
    task = asyncio.create_task(api.async_lock(_VIN, "lock"))
    await started.wait()
    task.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    journal = await store.async_get_command_journal(cloud_entry_data(credentials))
    assert len(cloud.lock_sent) == 1
    assert len(journal) == 1
    assert journal[0].cloud_command_id == "provider-command-lock"
    assert journal[0].state == "accepted"


@pytest.mark.asyncio
async def test_cancellation_after_terminal_result_finishes_journal_transition(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    cloud.poll_results = [
        (RemoteCommandResultItem("provider-command-lock", "0x05", "6", "Success"),)
    ]
    api, store, credentials = await _api(tmp_path, cloud, clock)
    accepted = await api.async_lock(_VIN, "lock")
    original = store.async_update_command
    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_update(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("state") == "completed":
            started.set()
            await release.wait()
        return await original(*args, **kwargs)

    store.async_update_command = delayed_update  # type: ignore[method-assign]
    task = asyncio.create_task(api.async_get_command(str(accepted["id"])))
    await started.wait()
    task.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    journal = await store.async_get_command_journal(cloud_entry_data(credentials))
    assert journal[0].state == "completed"
    assert await api.async_restore(cloud_entry_data(credentials)) == ()


@pytest.mark.asyncio
async def test_charging_acceptance_finishes_ownership_save_before_cancellation(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    cloud = _Cloud()
    api, store, credentials = await _api(
        tmp_path,
        cloud,
        clock,
        charging_enabled=True,
    )
    original = store.async_set_owned_charging_plan
    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_save(*args: Any, **kwargs: Any) -> None:
        started.set()
        await release.wait()
        await original(*args, **kwargs)

    store.async_set_owned_charging_plan = delayed_save  # type: ignore[method-assign]
    start = int(_NOW.timestamp() * 1000)
    task = asyncio.create_task(
        api.async_set_charging_plan(
            _VIN,
            enable=True,
            start_time=start,
            end_time=start + 60 * 60 * 1000,
        )
    )
    await started.wait()
    task.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    owned = await store.async_get_owned_charging_plans(cloud_entry_data(credentials))
    assert len(cloud.charging_sent) == 1
    assert len(owned) == 1
    assert owned[0].vehicle_id == _VIN
