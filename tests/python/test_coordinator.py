"""Coordinator VIN-resolution tests."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.gwm_ora.cloud_commands import GwmCommandApi
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from gwm_client import GwmApiError, GwmAuthenticationError, GwmNetworkError


def _coordinator_with(vehicles: list[dict]) -> GwmDataUpdateCoordinator:
    # Bypass __init__ (needs a real hass/api); resolve_vehicle only reads .data.
    coordinator = GwmDataUpdateCoordinator.__new__(GwmDataUpdateCoordinator)
    coordinator.data = {"vehicles": vehicles}
    coordinator._charging_plan_active = {}
    return coordinator


def test_resolve_vehicle_matches_encoded_vin_or_display_serial() -> None:
    coordinator = _coordinator_with(
        [{"vin": "ENCODED123", "serial_number": "LGWTEST00XX000001"}]
    )

    # The encoded VIN used by the cloud API.
    assert coordinator.resolve_vehicle("ENCODED123")["serial_number"] == "LGWTEST00XX000001"
    # The display VIN / device serial the user sees and services.yaml documents.
    assert coordinator.resolve_vehicle("LGWTEST00XX000001")["vin"] == "ENCODED123"
    # Display VIN entry is case-insensitive.
    assert coordinator.resolve_vehicle("lgwtest00xx000001")["vin"] == "ENCODED123"
    # Unknown identifier.
    assert coordinator.resolve_vehicle("NOPE") is None


def test_vehicle_lookup_stays_strict_on_encoded_vin() -> None:
    coordinator = _coordinator_with(
        [{"vin": "ENCODED123", "serial_number": "LGWTEST00XX000001"}]
    )

    assert coordinator.vehicle("ENCODED123") is not None
    assert coordinator.vehicle("LGWTEST00XX000001") is None


def test_charging_plan_state_is_kept_per_vehicle() -> None:
    coordinator = _coordinator_with([])
    coordinator.async_update_listeners = lambda: None

    coordinator.set_charging_plan_active("VIN-A", True)
    coordinator.set_charging_plan_active("VIN-B", False)

    assert coordinator.charging_plan_active("VIN-A") is True
    assert coordinator.charging_plan_active("VIN-B") is False
    assert coordinator.charging_plan_active("VIN-C") is None


@pytest.mark.asyncio
async def test_cloud_coordinator_uses_configured_account_interval() -> None:
    class CloudClient:
        async def async_get_vehicle_data(self) -> dict:
            return {"region": "eu", "vehicles": []}

    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        AsyncMock(),
        cloud_client=CloudClient(),  # type: ignore[arg-type]
        update_interval_seconds=120,
    )

    assert await coordinator._async_update_data() == {"region": "eu", "vehicles": []}
    assert coordinator.update_interval.total_seconds() == 120


@pytest.mark.asyncio
async def test_cloud_refresh_keeps_latest_remote_command_status() -> None:
    class CloudClient:
        async def async_get_vehicle_data(self) -> dict:
            return {
                "region": "eu",
                "vehicles": [
                    {
                        "vin": "SYNTHETIC-VIN",
                        "command_status": "No remote command has run yet",
                    }
                ],
            }

    api = AsyncMock()
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=CloudClient(),  # type: ignore[arg-type]
    )
    coordinator.data = await coordinator._async_update_data()
    coordinator.async_track_command(
        {
            "id": "completed-command",
            "vin": "SYNTHETIC-VIN",
            "state": "completed",
            "status": "A/C: completed - Success [0]",
        }
    )

    refreshed = await coordinator._async_update_data()

    assert refreshed["vehicles"][0]["command_status"] == (
        "A/C: completed - Success [0]"
    )

    api.async_refresh.return_value = await CloudClient().async_get_vehicle_data()
    await coordinator._async_refresh_after_completed_command()

    assert coordinator.data["vehicles"][0]["command_status"] == (
        "A/C: completed - Success [0]"
    )


@pytest.mark.asyncio
async def test_cloud_coordinator_runs_owned_charging_cleanup_after_each_refresh() -> None:
    calls: list[dict[str, object]] = []

    class CloudClient:
        async def async_get_vehicle_data(self) -> dict[str, object]:
            return {"region": "eu", "vehicles": []}

    api = object.__new__(GwmCommandApi)

    async def cleanup(entry_data: dict[str, object]) -> None:
        calls.append(entry_data)

    api.async_cleanup_owned_charging_plans = cleanup  # type: ignore[method-assign]
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        api,
        cloud_client=CloudClient(),  # type: ignore[arg-type]
    )
    coordinator.config_entry = type("Entry", (), {"data": {"region": "eu"}})()

    assert await coordinator._async_update_data() == {"region": "eu", "vehicles": []}
    assert calls == [{"region": "eu"}]

    async def failed_cleanup(entry_data: dict[str, object]) -> None:
        del entry_data
        raise ValueError("synthetic storage failure")

    api.async_cleanup_owned_charging_plans = failed_cleanup  # type: ignore[method-assign]
    assert await coordinator._async_update_data() == {"region": "eu", "vehicles": []}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (GwmAuthenticationError(operation="acquire_vehicles"), ConfigEntryAuthFailed),
        (GwmNetworkError(operation="acquire_vehicles"), UpdateFailed),
    ],
)
async def test_cloud_coordinator_classifies_refresh_failures(
    error: Exception,
    expected: type[Exception],
) -> None:
    class CloudClient:
        region = "eu"
        retired = False

        async def async_get_vehicle_data(self) -> dict:
            raise error

        async def async_authentication_rejected(self) -> None:
            self.retired = True

    cloud_client = CloudClient()

    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        AsyncMock(),
        cloud_client=cloud_client,  # type: ignore[arg-type]
    )

    with pytest.raises(expected):
        await coordinator._async_update_data()
    assert cloud_client.retired is isinstance(error, GwmAuthenticationError)


@pytest.mark.asyncio
async def test_cloud_coordinator_surfaces_only_sanitized_api_failure_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class CloudClient:
        region = "aus"

        async def async_get_vehicle_data(self) -> dict:
            raise GwmApiError(operation="get_last_status", api_code="607099")

    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        AsyncMock(),
        cloud_client=CloudClient(),  # type: ignore[arg-type]
    )

    with caplog.at_level(logging.WARNING), pytest.raises(UpdateFailed) as raised:
        await coordinator._async_update_data()

    assert str(raised.value) == (
        "GWM cloud api_error during get_last_status (API code 607099)"
    )
    assert caplog.messages[-1] == (
        "GWM cloud refresh failed: region=aus type=GwmApiError "
        "category=api_error operation=get_last_status api_code=607099 "
        "http_status=None retry_after_seconds=None"
    )


@pytest.mark.asyncio
async def test_command_polling_tasks_are_cancelled_and_joined_before_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    finished = asyncio.Event()

    async def blocked_sleep(_delay: float) -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            finished.set()

    monkeypatch.setattr(
        "custom_components.gwm_ora.coordinator.asyncio.sleep",
        blocked_sleep,
    )
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant("synthetic-config"),
        AsyncMock(),
        cloud_client=object(),  # type: ignore[arg-type]
    )
    coordinator.data = {"region": "eu", "vehicles": []}
    coordinator.async_track_command(
        {
            "id": "accepted-command",
            "vin": "SYNTHETIC-VIN",
            "state": "in_progress",
            "status": "accepted",
        }
    )
    await started.wait()

    await coordinator.async_cancel_command_tasks()

    assert finished.is_set()
    assert coordinator._command_tasks == {}
