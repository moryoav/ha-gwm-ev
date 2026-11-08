"""Home Assistant APAC setup with a synthetic account and fake transport."""

import json
import ssl
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from unittest.mock import AsyncMock

import pytest
from homeassistant.config_entries import ConfigEntries, ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

import custom_components.gwm_ora as integration
import custom_components.gwm_ora.cloud_runtime as runtime
from custom_components.gwm_ora import config_flow
from custom_components.gwm_ora.cloud_auth import GwmCloudCredentials, cloud_entry_data, cloud_unique_id
from custom_components.gwm_ora.cloud_runtime import stage_cloud_bootstrap
from custom_components.gwm_ora.const import (
    CONF_ACCOUNT,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    PLATFORMS,
    REGION_APAC,
)
from custom_components.gwm_ora.gwm_client import apac_auth_client, apac_material, apac_restore
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
@pytest.mark.parametrize("linked_bundle", [False, True])
async def test_packaged_apac_install_signs_in_and_resumes_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, linked_bundle: bool
) -> None:
    """Sign in from installed resources and reload the saved session on startup."""
    component = tmp_path / "custom_components" / "gwm_ora"
    installed = component / "resources" / "apac"
    resources = tmp_path / "mounted_bundle" if linked_bundle else installed
    resources.mkdir(parents=True)
    if linked_bundle:
        installed.parent.mkdir(parents=True)
        try:
            installed.symlink_to(resources, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Directory symlinks are unavailable on this platform")
    (resources / "bootstrap.cer").write_bytes(b"fixture-certificate")
    (resources / "bootstrap.key").write_bytes(b"c3ludGhldGljLWtleQ==")
    (resources / "ca.pem").write_bytes(b"fixture-ca-bundle")
    (resources / "signing.json").write_text(
        '{"app_key":"fixture-app-key","app_secret":"fixture-app-secret"}', encoding="utf-8"
    )
    monkeypatch.setattr(apac_material, "_SOURCE_DIRECTORY", component / "gwm_client")

    def tls_context(mode: TlsMode) -> ssl.SSLContext:
        """Represent a prevalidated client TLS context at the fake transport boundary."""
        context = ssl.create_default_context()
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        return _register_validated_context(context, mode)

    bootstrap_context = tls_context(TlsMode.APAC_BOOTSTRAP_MTLS)
    issued_context = tls_context(TlsMode.APAC_ISSUED_MTLS)
    monkeypatch.setattr(apac_auth_client, "create_apac_bootstrap_context", lambda *_: bootstrap_context)
    for module in (apac_auth_client, apac_restore):
        monkeypatch.setattr(module, "create_apac_issued_context", lambda *args, **kwargs: issued_context)

    operations: list[str] = []
    profile = {"gwId": "fixture-account", "beanId": "fixture-bean"}
    responses = {
        "login": {**profile, "accessToken": "fixture-access", "refreshToken": "fixture-refresh"},
        "get_user_info": profile,
        "enroll_certificate": {"encoded": "c3ludGhldGlj"},
        "acquire_vehicles": [{"vin": "SYNTHETIC-VEHICLE"}],
        "get_last_status": {"items": [{"code": "2013021", "value": "65", "unit": "%"}]},
        "get_vehicle_basics": {},
    }

    class Transport:
        """Serve fixture APAC responses without contacting the cloud."""

        async def execute(self, request, **kwargs):
            """Require the installed signing profile on every APAC request."""
            assert request.headers["bt-auth-appkey"] == "fixture-app-key"
            operations.append(request.operation)
            data = {"code": "000000", "data": responses[request.operation]}
            return _TransportResponse(200, {}, json.dumps(data).encode())

        async def aclose(self) -> None:
            """Close the fixture transport without network activity."""

    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: Transport())
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = ConfigEntries(hass, {})
    flow = config_flow.GwmConfigFlow()
    flow.hass = hass
    flow.handler = DOMAIN
    flow.context = {"source": "user"}
    await flow.async_step_user({CONF_REGION: REGION_APAC})
    result = await flow.async_step_account(
        {CONF_COUNTRY: "PK", CONF_ACCOUNT: "person@example.invalid", CONF_PASSWORD: "fixture-password"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result.get("errors")
    assert "login" in operations and "enroll_certificate" in operations

    entry = ConfigEntry(
        data=result["data"],
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="fixture-entry",
        minor_version=1,
        options={},
        source="user",
        state=ConfigEntryState.SETUP_IN_PROGRESS,
        subentries_data=None,
        title=result["title"],
        unique_id=flow.unique_id,
        version=1,
    )
    operations.clear()
    restarted = HomeAssistant(str(tmp_path))
    restarted.config_entries = ConfigEntries(restarted, {})
    monkeypatch.setattr(restarted.config_entries, "async_forward_entry_setups", AsyncMock())
    monkeypatch.setattr(restarted.config_entries, "async_unload_platforms", AsyncMock(return_value=True))
    assert await integration.async_setup_entry(restarted, entry)
    try:
        assert entry.runtime_data.coordinator.data["vehicles"][0]["values"]["soc"] == 65.0
        assert {"login", "enroll_certificate"}.isdisjoint(operations)
    finally:
        assert await integration.async_unload_entry(restarted, entry)


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
