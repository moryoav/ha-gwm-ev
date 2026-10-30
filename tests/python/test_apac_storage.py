"""Private APAC storage contracts and cross-account rejection."""

import logging
from dataclasses import replace
from pathlib import Path

import pytest
from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.cloud_auth import GwmCloudCredentials, cloud_entry_data, cloud_unique_id
from custom_components.gwm_ora.cloud_storage import (
    _decode_auth_state,
    _encode_auth_state,
    _validate_regional_state,
    cloud_state_store,
)
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.eu_identity import EuIssuedIdentity


def _credentials(account="person@example.invalid", country="PK", device="a" * 32):
    return GwmCloudCredentials(REGION_APAC, country, account, "synthetic-password", device)


def test_private_storage_roundtrip_and_context_binding():
    credentials = _credentials()
    regional = credentials.client_credentials()
    assert isinstance(regional, ApacCredentials)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(ApacAuthState.for_credentials(regional), tokens=tokens, issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"))
    encoded = _encode_auth_state(state)
    restored = _decode_auth_state(REGION_APAC, encoded)
    assert restored == state
    _validate_regional_state(REGION_APAC, credentials.account_binding, restored, credentials=credentials)
    for changed in (_credentials(account="other@example.invalid"), _credentials(country="TH"), _credentials(device="b" * 32)):
        with pytest.raises(ValueError, match="^auth_state_invalid$"):
            _validate_regional_state(REGION_APAC, changed.account_binding, restored, credentials=changed)
    assert "synthetic" not in repr(restored)


def test_storage_rejects_extra_and_wrong_region_fields():
    credentials = _credentials()
    state = ApacAuthState.for_credentials(credentials.client_credentials())
    encoded = _encode_auth_state(state)
    encoded["unexpected"] = "synthetic"
    with pytest.raises(ValueError, match="^apac_state_invalid$"):
        _decode_auth_state(REGION_APAC, encoded)
    with pytest.raises(ValueError, match="^auth_state_invalid$"):
        _decode_auth_state("eu", _encode_auth_state(state))


@pytest.mark.asyncio
async def test_private_store_survives_restart_without_leaking_state(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    credentials = _credentials()
    regional = credentials.client_credentials()
    assert isinstance(regional, ApacCredentials)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(ApacAuthState.for_credentials(regional), tokens=tokens, issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"))
    caplog.set_level(logging.DEBUG, logger="custom_components.gwm_ora.cloud_storage")
    first = cloud_state_store(HomeAssistant(str(tmp_path)), cloud_unique_id(credentials))
    await first.async_save_auth_state(credentials, state)
    restarted = cloud_state_store(HomeAssistant(str(tmp_path)), cloud_unique_id(credentials))
    assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == state
    assert "synthetic" not in caplog.text

@pytest.mark.asyncio
async def test_apac_restart_restores_private_state_without_password_login(tmp_path, monkeypatch):
    """Home Assistant restart must use the persisted account-bound state."""
    import ssl
    from types import MappingProxyType

    from homeassistant.config_entries import ConfigEntry

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_runtime as runtime
    from custom_components.gwm_ora.gwm_client.apac_flow import ApacAuthenticated
    from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
    from custom_components.gwm_ora.gwm_client.apac_read import ApacReadSession
    from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial

    credentials = _credentials()
    regional = credentials.client_credentials()
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(ApacAuthState.for_credentials(regional), tokens=tokens, issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"))
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    session = ApacReadSession(credentials.device_id, tokens.access_token, ssl.create_default_context(), credentials.country)
    unique_id = cloud_unique_id(credentials)
    entry = ConfigEntry(data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain="gwm_ora", entry_id="synthetic-entry", minor_version=1, options={}, source="user", subentries_data=None, title="GWM APAC", unique_id=unique_id, version=1)
    first = HomeAssistant(str(tmp_path))
    await cloud_state_store(first, unique_id).async_save_auth_state(credentials, state)
    restarted = HomeAssistant(str(tmp_path))
    store = cloud_state_store(restarted, unique_id)
    calls = []
    class FakeAuthenticator:
        def __init__(self, *, apac_material_loader): assert callable(apac_material_loader)
        async def async_authenticate(self, supplied, **kwargs):
            calls.append((kwargs["state"], kwargs["allow_password_login"]))
            return ApacAuthenticated(state, session, material)
    monkeypatch.setattr(integration, "GwmCloudAuthenticator", FakeAuthenticator)
    monkeypatch.setattr(runtime, "_is_validated_context", lambda context, mode: True)
    handoff = await integration._async_load_cloud_bootstrap(restarted, entry, store)
    assert calls == [(state, False)]
    assert handoff.state == state
    assert await store.async_load_auth_state(dict(entry.data)) == state
