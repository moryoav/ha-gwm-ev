"""Charging actions exercised through Home Assistant's service registry."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("homeassistant")

import voluptuous as vol
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.gwm_ora import _async_register_services
from custom_components.gwm_ora.const import DOMAIN, SERVICE_CLEAR_CHARGING_PLAN, SERVICE_SET_CHARGING_PLAN
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.gwm_client import GwmApiError
from custom_components.gwm_ora.switch import _charging_plan_is_active

VIN = "LGWTEST0000000001"
WINDOW = {"vin": "DISPLAY-VIN", "start_time": "2026-01-01T02:00:00+02:00", "end_time": "2026-01-01T02:05:00+02:00"}


def _services(tmp_path):
    """Register real services and a real coordinator against an offline cloud API."""
    hass = HomeAssistant(str(tmp_path))
    api = SimpleNamespace(async_set_charging_plan=AsyncMock(return_value={}))
    coordinator = GwmDataUpdateCoordinator(hass, api, cloud_client=SimpleNamespace())
    coordinator.async_set_updated_data({"region": "eu", "vehicles": [{
        "vin": VIN, "serial_number": "DISPLAY-VIN", "capabilities": {"charging_control": True},
    }]})
    entry = SimpleNamespace(runtime_data=SimpleNamespace(api=api, coordinator=coordinator))
    hass.config_entries = SimpleNamespace(async_loaded_entries=lambda domain: [entry] if domain == DOMAIN else [])
    _async_register_services(hass)
    return hass, api, coordinator


@pytest.mark.asyncio
async def test_charging_services_resolve_display_vin_and_publish_only_successful_changes(tmp_path):
    hass, api, coordinator = _services(tmp_path)
    await hass.services.async_call(DOMAIN, SERVICE_SET_CHARGING_PLAN, WINDOW, blocking=True)
    api.async_set_charging_plan.assert_awaited_once_with(
        VIN, enable=True, start_time=1767225600000, end_time=1767225900000, plan_type=0,
    )
    assert coordinator.charging_plan_active(VIN) is True
    api.async_set_charging_plan.reset_mock()
    await hass.services.async_call(DOMAIN, SERVICE_CLEAR_CHARGING_PLAN, {"vin": "DISPLAY-VIN"}, blocking=True)
    api.async_set_charging_plan.assert_awaited_once_with(VIN, enable=False)
    assert coordinator.charging_plan_active(VIN) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    {key: value for key, value in WINDOW.items() if key != "vin"},
    {key: value for key, value in WINDOW.items() if key != "start_time"},
    {key: value for key, value in WINDOW.items() if key != "end_time"},
    {**WINDOW, "start_time": "invalid-date"},
    {**WINDOW, "end_time": "2026-01-01T02:04:59+02:00"},
    {**WINDOW, "end_time": "2026-01-01T01:00:00+02:00"},
    {**WINDOW, "vin": "UNKNOWN-VIN"},
    {**WINDOW, "enable": False},
], ids=["missing-vin", "missing-start", "missing-end", "invalid-date", "short-window", "reversed-window", "unknown-vin", "unexpected-enable"])
async def test_invalid_charging_window_never_reaches_the_cloud(tmp_path, data):
    hass, api, coordinator = _services(tmp_path)
    with pytest.raises((vol.Invalid, ServiceValidationError)):
        await hass.services.async_call(DOMAIN, SERVICE_SET_CHARGING_PLAN, data, blocking=True)
    api.async_set_charging_plan.assert_not_called()
    assert coordinator.charging_plan_active(VIN) is None


@pytest.mark.asyncio
async def test_rejected_charging_service_keeps_the_last_confirmed_state(tmp_path):
    hass, api, coordinator = _services(tmp_path)
    coordinator.set_charging_plan_active(VIN, False)
    api.async_set_charging_plan.side_effect = GwmApiError(operation="set_charging_plan", api_code="550002")
    with pytest.raises(HomeAssistantError) as raised:
        await hass.services.async_call(DOMAIN, SERVICE_SET_CHARGING_PLAN, WINDOW, blocking=True)
    assert raised.value.translation_key == "cloud_request_failed"
    assert coordinator.charging_plan_active(VIN) is False


@pytest.mark.parametrize("response,expected", [
    ({"charge_plan_list": []}, False),
    ({"charge_plan_list": [{"plan_type": "-1"}]}, False),
    ({"charge_plan_list": [{"plan_type": "0"}]}, True),
    ({"charge_plan_list": [{"plan_type": 0}]}, True),
])
def test_charging_plan_active_state(response, expected):
    assert _charging_plan_is_active(response) is expected
