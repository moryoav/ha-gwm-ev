"""APAC account-bound configuration handoff tests."""

import ssl
from dataclasses import replace

import pytest

import custom_components.gwm_ora.cloud_runtime as runtime
from custom_components.gwm_ora.cloud_auth import GwmCloudCredentials
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_flow import ApacAuthenticated
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.apac_restore import ApacRestored
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.errors import GwmAuthenticationError, GwmConfigurationError, GwmNetworkError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity


def test_handoff_requires_matching_account_device_and_token(monkeypatch):
    """Reject runtime handoffs whose account, device, or token binding differs."""
    credentials = GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)
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
    session = ApacReadSession("a" * 32, "synthetic-access", ssl.create_default_context(), "PK")
    monkeypatch.setattr(runtime, "_is_validated_context", lambda context, mode: True)
    handoff = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    assert handoff.state == state
    assert "synthetic" not in repr(handoff)
    bad_session = replace(session, access_token="different-token")
    with pytest.raises(GwmConfigurationError):
        runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, bad_session, material))
    other = GwmCloudCredentials(REGION_APAC, "PK", "other@example.invalid", "synthetic-password", "a" * 32)
    with pytest.raises(GwmConfigurationError):
        runtime.GwmCloudBootstrap.from_authentication(other, ApacAuthenticated(state, session, material))


@pytest.mark.asyncio
async def test_expired_session_persists_rotated_tokens_before_retry(monkeypatch):
    """Persist a rotated session before retrying the interrupted runtime read."""
    credentials = GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    session = ApacReadSession("a" * 32, "synthetic-access", ssl.create_default_context(), "PK")
    monkeypatch.setattr(runtime, "_is_validated_context", lambda context, mode: True)
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    calls = []

    class FakeStore:
        async def async_save_auth_state(self, credentials, state):
            """Record the private state revision published by the runtime."""
            calls.append("saved")

    client = ApacReadClient(material=material, session=session, transport=None)
    cloud = runtime.GwmCloudClient(
        REGION_APAC, client, credentials=credentials, bootstrap=bootstrap, state_store=FakeStore()
    )
    new_tokens = ApacTokens("renewed-access", "renewed-refresh", "synthetic-gw", "synthetic-bean")
    new_state = replace(state, tokens=new_tokens)
    new_session = replace(session, access_token="renewed-access")

    async def fake_restore(**kwargs):
        """Return the replacement synthetic session for runtime recovery."""
        calls.append("restore")
        return ApacRestored(new_state, new_session)

    monkeypatch.setattr(runtime, "restore_apac_session", fake_restore)

    async def action():
        """Reject expired authentication once before returning the requested data."""
        calls.append("read")
        if calls.count("read") == 1:
            raise GwmAuthenticationError(operation="acquire_vehicles")
        return "synthetic-result"

    assert await cloud._async_with_session_renewal(action) == "synthetic-result"
    assert calls == ["read", "restore", "saved", "read"]
    assert cloud.reusable_bootstrap.state == new_state


@pytest.mark.asyncio
@pytest.mark.parametrize("expire_status", [False, True])
async def test_apac_runtime_discovers_and_maps_read_only_snapshot(monkeypatch, expire_status):
    """Exercise the real client adapter with a fake transport and no writes."""
    import json

    import custom_components.gwm_ora.gwm_client.apac_restore as restore
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
    from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
    from custom_components.gwm_ora.gwm_client.regions import TlsMode

    class FakeTransport:
        def __init__(self):
            """Retain synthetic dependencies without making network requests."""
            self.operations = []

        async def execute(self, request, **kwargs):
            """Return the synthetic response for one explicitly requested operation."""
            self.operations.append(request.operation)
            if (
                request.operation == "get_last_status"
                and expire_status
                and request.headers["accessToken"] == "synthetic-access"
            ):
                return _TransportResponse(401, {}, b"{}")
            payloads = {
                "acquire_vehicles": [{"vin": "SYNTHETIC-VEHICLE"}],
                "get_last_status": {"items": [{"code": 2013021, "value": "65", "unit": "%"}]},
                "get_vehicle_basics": {},
                "refresh_token": {"accessToken": "renewed-access", "refreshToken": "renewed-refresh"},
                "get_user_info": {"gwId": "synthetic-gw", "beanId": "synthetic-bean"},
            }
            return _TransportResponse(
                200, {}, json.dumps({"code": "000000", "data": payloads[request.operation]}).encode()
            )

        async def aclose(self):
            """Record synthetic transport cleanup without network activity."""
            pass

    credentials = GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)
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
    session = ApacReadSession("a" * 32, "synthetic-access", context, "PK")
    handoff = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    transport = FakeTransport()
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials),
        cloud_unique_id(credentials),
        handoff,
        climate_commands_enabled=True,
        lock_window_commands_enabled=True,
        charging_control_enabled=True,
    )
    try:
        snapshot = await cloud.async_get_vehicle_data()
        assert transport.operations == (
            [
                "acquire_vehicles",
                "get_last_status",
                "refresh_token",
                "get_user_info",
                "acquire_vehicles",
                "acquire_vehicles",
                "get_last_status",
                "get_vehicle_basics",
            ]
            if expire_status
            else ["acquire_vehicles", "get_last_status", "get_vehicle_basics"]
        )
        assert cloud.reusable_bootstrap.state.tokens.refresh_token == (
            "renewed-refresh" if expire_status else "synthetic-refresh"
        )
        assert snapshot["vehicles"][0]["values"]["soc"] == 65.0
        assert snapshot["remote_commands_enabled"] is False
        assert snapshot["charging_control_enabled"] is False
        assert snapshot["vehicles"][0]["capabilities"]["climate_commands"] is False
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_operation", ["get_user_info", "acquire_vehicles"])
async def test_runtime_retains_a_rotation_when_follow_up_validation_fails(monkeypatch, failure_operation):
    """Keep memory and private storage on the new token pair after a read failure."""
    credentials = GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean"),
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    session = ApacReadSession("a" * 32, "synthetic-access", ssl.create_default_context(), "PK")
    monkeypatch.setattr(runtime, "_is_validated_context", lambda *args: True)
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    saved = []

    class Store:
        async def async_save_auth_state(self, supplied, replacement):
            """Record the private state revision published by the runtime."""
            saved.append(replacement)

    client = ApacReadClient(material=material, session=session, transport=None)
    cloud = runtime.GwmCloudClient(
        REGION_APAC, client, credentials=credentials, bootstrap=bootstrap, state_store=Store()
    )
    replacement = replace(
        state, tokens=ApacTokens("renewed-access", "renewed-refresh", "synthetic-gw", "synthetic-bean")
    )
    renewed_session = replace(session, access_token="renewed-access")

    async def restore_then_fail(**kwargs):
        """Publish the rotation and then fail the profile or discovery request."""
        await kwargs["on_session_updated"](ApacRestored(replacement, renewed_session))
        raise GwmNetworkError(operation=failure_operation)

    async def expired_action():
        """Require one token restoration before the requested read can proceed."""
        raise GwmAuthenticationError(operation="get_last_status")

    monkeypatch.setattr(runtime, "restore_apac_session", restore_then_fail)
    with pytest.raises(GwmNetworkError):
        await cloud._async_with_session_renewal(expired_action)
    assert saved == [replacement]
    assert cloud.reusable_bootstrap.state == replacement
    assert client._session.access_token == "renewed-access"
