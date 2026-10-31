"""Private APAC storage contracts and cross-account rejection."""

import asyncio
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
    """Construct credentials for a synthetic APAC account."""
    return GwmCloudCredentials(REGION_APAC, country, account, "synthetic-password", device)


def test_private_storage_roundtrip_and_context_binding():
    """Preserve private state only within its original account and configuration context."""
    credentials = _credentials()
    regional = credentials.client_credentials()
    assert isinstance(regional, ApacCredentials)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(
        ApacAuthState.for_credentials(regional),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    encoded = _encode_auth_state(state)
    restored = _decode_auth_state(REGION_APAC, encoded)
    assert restored == state
    _validate_regional_state(REGION_APAC, credentials.account_binding, restored, credentials=credentials)
    for changed in (
        _credentials(account="other@example.invalid"),
        _credentials(country="TH"),
        _credentials(device="b" * 32),
    ):
        with pytest.raises(ValueError, match="^auth_state_invalid$"):
            _validate_regional_state(REGION_APAC, changed.account_binding, restored, credentials=changed)
    assert "synthetic" not in repr(restored)


def test_storage_rejects_extra_and_wrong_region_fields():
    """Reject unknown private fields and state encoded for another region."""
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
    """Reload persisted APAC state after restart without exposing private values."""
    credentials = _credentials()
    regional = credentials.client_credentials()
    assert isinstance(regional, ApacCredentials)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(
        ApacAuthState.for_credentials(regional),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
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
    state = replace(
        ApacAuthState.for_credentials(regional),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    session = ApacReadSession(
        credentials.device_id, tokens.access_token, ssl.create_default_context(), credentials.country
    )
    unique_id = cloud_unique_id(credentials)
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain="gwm_ora",
        entry_id="synthetic-entry",
        minor_version=1,
        options={},
        source="user",
        subentries_data=None,
        title="GWM APAC",
        unique_id=unique_id,
        version=1,
    )
    first = HomeAssistant(str(tmp_path))
    await cloud_state_store(first, unique_id).async_save_auth_state(credentials, state)
    restarted = HomeAssistant(str(tmp_path))
    store = cloud_state_store(restarted, unique_id)
    calls = []

    class FakeAuthenticator:
        def __init__(self, *, apac_material_loader):
            """Retain synthetic dependencies without making network requests."""
            assert callable(apac_material_loader)

        async def async_authenticate(self, supplied, **kwargs):
            """Return a synthetic regional authentication result for the test."""
            calls.append((kwargs["state"], kwargs["allow_password_login"]))
            return ApacAuthenticated(state, session, material)

    monkeypatch.setattr(integration, "GwmCloudAuthenticator", FakeAuthenticator)
    monkeypatch.setattr(runtime, "_is_validated_context", lambda context, mode: True)
    handoff = await integration._async_load_cloud_bootstrap(restarted, entry, store)
    assert calls == [(state, False)]
    assert handoff.state == state
    assert await store.async_load_auth_state(dict(entry.data)) == state


@pytest.mark.asyncio
async def test_startup_rotation_survives_a_follow_up_failure_and_process_restart(tmp_path, monkeypatch):
    """Reload the rotated pair from disk after startup restoration fails."""
    import json
    import ssl
    from types import SimpleNamespace

    from homeassistant.exceptions import ConfigEntryNotReady

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_auth as auth_boundary
    import custom_components.gwm_ora.gwm_client.apac_restore as restore
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
    from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
    from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
    from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
    from custom_components.gwm_ora.gwm_client.regions import TlsMode

    credentials = _credentials()
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean"),
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    unique_id = cloud_unique_id(credentials)
    entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=unique_id)
    first = HomeAssistant(str(tmp_path))
    store = cloud_state_store(first, unique_id)
    await store.async_save_auth_state(credentials, state)
    renewed = replace(state, tokens=ApacTokens("renewed-access", "renewed-refresh", "synthetic-gw", "synthetic-bean"))
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    calls = []

    class Transport:
        async def execute(self, request, **kwargs):
            """Return the synthetic response for one explicitly requested operation."""
            calls.append(request.operation)
            if request.operation == "acquire_vehicles":
                return _TransportResponse(401, {}, b"{}")
            if request.operation == "refresh_token":
                assert json.loads(request.body)["refreshToken"] == "synthetic-refresh"
                return _TransportResponse(
                    200,
                    {},
                    b'{"code":"000000","data":{"accessToken":"renewed-access","refreshToken":"renewed-refresh"}}',
                )
            assert request.operation == "get_user_info"
            assert request.headers["accessToken"] == "renewed-access"
            return _TransportResponse(503, {}, b"{}")

        async def aclose(self):
            """Record synthetic transport cleanup without network activity."""
            calls.append("closed")

    actual_authenticator = auth_boundary.GwmCloudAuthenticator
    monkeypatch.setattr(
        integration,
        "GwmCloudAuthenticator",
        lambda **kwargs: actual_authenticator(apac_material_loader=lambda: material),
    )
    monkeypatch.setattr(auth_boundary.AiohttpTransport, "create_owned", lambda **kwargs: Transport())
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    with pytest.raises(ConfigEntryNotReady):
        await integration._async_load_cloud_bootstrap(first, entry, store)
    restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    assert await restarted.async_load_auth_state(dict(entry.data)) == renewed
    assert calls == ["acquire_vehicles", "refresh_token", "get_user_info", "closed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["startup", "config_flow"])
async def test_cancelled_apac_setup_finishes_rotated_token_persistence(tmp_path, monkeypatch, boundary):
    """Finish a rotated-state save despite repeated cancellation during setup."""
    import ssl
    from types import SimpleNamespace

    import custom_components.gwm_ora as integration
    from custom_components.gwm_ora.config_flow import GwmConfigFlow
    from custom_components.gwm_ora.gwm_client.apac_read import ApacReadSession
    from custom_components.gwm_ora.gwm_client.apac_restore import ApacRestored

    credentials = _credentials()
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean"),
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    replacement = replace(
        state, tokens=ApacTokens("renewed-access", "renewed-refresh", "synthetic-gw", "synthetic-bean")
    )
    session = ApacReadSession(credentials.device_id, "renewed-access", ssl.create_default_context(), "PK")
    unique_id = cloud_unique_id(credentials)
    hass = HomeAssistant(str(tmp_path))
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    save_started = asyncio.Event()

    async def hold_store_and_publish(callback):
        """Hold the real store lock while the caller publishes a rotation."""
        await store._lock.acquire()
        save_started.set()
        await callback(ApacRestored(replacement, session))
        pytest.fail("Setup cancellation must propagate after the save finishes")

    class Authenticator:
        def __init__(self, **kwargs):
            """Accept the private material loader without opening a connection."""

        async def async_authenticate(self, supplied, **kwargs):
            """Publish the synthetic rotation through the real startup callback."""
            assert kwargs["allow_password_login"] is False
            assert kwargs["state"] == state
            await hold_store_and_publish(kwargs["apac_session_updated"])

    if boundary == "startup":
        monkeypatch.setattr(integration, "GwmCloudAuthenticator", Authenticator)
        entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=unique_id)
        setup = integration._async_load_cloud_bootstrap(hass, entry, store)
    else:
        flow = GwmConfigFlow()
        flow.hass = hass
        flow._cloud_credentials = credentials
        flow._auth_state = state
        setup = hold_store_and_publish(flow._async_apac_session_updated)
    task = asyncio.create_task(setup)
    try:
        await asyncio.wait_for(save_started.wait(), timeout=5)
        for _ in range(2):
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
        store._lock.release()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        if store._lock.locked():
            store._lock.release()
        await asyncio.gather(task, return_exceptions=True)
    restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == replacement


@pytest.mark.asyncio
async def test_apac_state_publication_finishes_while_home_assistant_is_stopping(tmp_path):
    """Write a pending APAC revision before shutdown reports publication complete."""
    from homeassistant.core import CoreState

    credentials = _credentials()
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean"),
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    hass = HomeAssistant(str(tmp_path))
    hass.set_state(CoreState.stopping)
    unique_id = cloud_unique_id(credentials)
    await cloud_state_store(hass, unique_id).async_save_auth_state(credentials, state)
    restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == state
