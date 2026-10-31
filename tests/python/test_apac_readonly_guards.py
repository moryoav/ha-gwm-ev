"""APAC read-only guards for stale options and direct command calls."""

from types import SimpleNamespace

import pytest

from custom_components.gwm_ora.cloud_commands import GwmCommandApi
from custom_components.gwm_ora.cloud_runtime import GwmCloudClient
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.errors import GwmCommandForbidden
from custom_components.gwm_ora.gwm_client.errors import GwmRoutePolicyError


class ReadOnlyFake:
    def __init__(self):
        """Retain synthetic dependencies without making network requests."""
        self.calls = []

    async def acquire_vehicles(self):
        """Return synthetic discovery data or the configured authentication failure."""
        self.calls.append("acquire_vehicles")
        return ()


@pytest.mark.asyncio
async def test_stale_enabled_options_cannot_expose_apac_controls():
    """Keep APAC controls unavailable even when an entry retains stale enabled flags."""
    fake = ReadOnlyFake()
    cloud = GwmCloudClient(
        REGION_APAC,
        fake,
        climate_commands_enabled=True,
        lock_window_commands_enabled=True,
        charging_control_enabled=True,
    )
    data = await cloud.async_get_vehicle_data()
    assert data["remote_commands_enabled"] is False
    assert data["charging_control_enabled"] is False
    assert fake.calls == ["acquire_vehicles"]


@pytest.mark.asyncio
async def test_direct_cloud_writes_are_denied_before_client_call():
    """Block direct APAC cloud write methods before dispatching a client operation."""
    fake = ReadOnlyFake()
    cloud = GwmCloudClient(
        REGION_APAC,
        fake,
        climate_commands_enabled=True,
        lock_window_commands_enabled=True,
        charging_control_enabled=True,
    )
    operations = [
        cloud.async_update_climate_defaults(None, temperature=20, operation_time_minutes=15),
        cloud.async_set_charging_plan(None),
        cloud.async_get_charging_plan(None),
        cloud.async_send_climate_command(None, security_password_hash="synthetic"),
        cloud.async_send_lock_command(None, security_password_hash="synthetic"),
        cloud.async_send_close_windows_command(None, security_password_hash="synthetic"),
        cloud.async_send_front_defroster_command(None, security_password_hash="synthetic"),
        cloud.async_send_cabin_clean_command(None, security_password_hash="synthetic"),
    ]
    for operation in operations:
        with pytest.raises(GwmRoutePolicyError):
            await operation
    assert fake.calls == []


@pytest.mark.asyncio
async def test_direct_service_api_rejects_stale_enabled_options():
    """Block APAC service writes despite stale command-consent options."""
    api = object.__new__(GwmCommandApi)
    api._cloud = SimpleNamespace(region=REGION_APAC)
    api._enabled = True
    api._charging_enabled = True
    api._security_pin = "synthetic"
    with pytest.raises(GwmCommandForbidden):
        await api.async_set_climate("synthetic", mode="auto")
    with pytest.raises(GwmCommandForbidden):
        await api.async_set_charging_plan("synthetic", enable=True)
