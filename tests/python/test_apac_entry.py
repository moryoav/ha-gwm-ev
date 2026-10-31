"""Home Assistant APAC setup with a synthetic account and fake transport."""

import json
import ssl
from dataclasses import replace
from types import MappingProxyType

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

import custom_components.gwm_ora as integration
import custom_components.gwm_ora.cloud_runtime as runtime
from custom_components.gwm_ora.cloud_auth import GwmCloudCredentials, cloud_entry_data, cloud_unique_id
from custom_components.gwm_ora.cloud_runtime import stage_cloud_bootstrap
from custom_components.gwm_ora.const import PLATFORMS, REGION_APAC
from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_flow import ApacAuthenticated
from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadSession
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity
from custom_components.gwm_ora.gwm_client.regions import TlsMode


@pytest.mark.asyncio
@pytest.mark.parametrize("country", ["PK", "TH", "MY", "ID"])
async def test_setup_uses_apac_read_only_data_without_vehicle_writes(tmp_path, monkeypatch, country):
    """Exercise setup, read polling and shutdown using no real GWM transport."""
    calls = []
    forwarded = []

    class FakeTransport:
        async def execute(self, request, **kwargs):
            """Return the synthetic response for one explicitly requested operation."""
            calls.append(request.operation)
            data = {
                "acquire_vehicles": [{"vin": "SYNTHETIC-VEHICLE"}],
                "get_last_status": {"items": [{"code": "2013021", "value": "65", "unit": "%"}]},
                "get_vehicle_basics": {},
            }[request.operation]
            return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

        async def aclose(self):
            """Record synthetic transport cleanup without network activity."""
            calls.append("closed")

    class Coordinator:
        def __init__(self, hass, api, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            self.api = api
            self.data = None

        async def async_config_entry_first_refresh(self):
            """Complete the synthetic coordinator's first refresh without network activity."""
            self.data = await self.api.async_get_vehicles()

        async def async_cancel_command_tasks(self):
            """Complete synthetic coordinator cleanup without submitting commands."""
            pass

    class Entries:
        async def async_forward_entry_setups(self, entry, platforms):
            """Record the Home Assistant platforms forwarded during APAC setup."""
            forwarded.extend(platforms)

        async def async_unload_platforms(self, entry, platforms):
            """Confirm that the synthetic Home Assistant platforms unload successfully."""
            return True

    credentials = GwmCloudCredentials(REGION_APAC, country, "person@example.invalid", "synthetic-password", "a" * 32)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    session = ApacReadSession(credentials.device_id, tokens.access_token, context, country)
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = Entries()
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain="gwm_ora",
        entry_id="synthetic-entry",
        minor_version=1,
        options={"enable_remote_commands": True, "enable_charging_control": True},
        source="user",
        subentries_data=None,
        title="GWM APAC",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )
    stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: FakeTransport())
    monkeypatch.setattr(integration, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(integration, "_async_register_services", lambda hass: None)

    assert await integration.async_setup_entry(hass, entry)
    assert set(forwarded) == set(PLATFORMS)
    assert entry.runtime_data.coordinator.data["vehicles"][0]["values"]["soc"] == 65.0
    assert entry.runtime_data.coordinator.data["remote_commands_enabled"] is False
    assert entry.runtime_data.coordinator.data["charging_control_enabled"] is False
    assert calls == ["acquire_vehicles", "get_last_status", "get_vehicle_basics"]
    assert await integration.async_unload_entry(hass, entry)
    assert calls[-1] == "closed"
