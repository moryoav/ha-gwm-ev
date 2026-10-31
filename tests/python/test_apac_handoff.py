"""APAC account-bound configuration handoff tests."""

import asyncio
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


def _runtime_with_synthetic_transport(monkeypatch, transport, state_store=None, **options):
    """Build the real APAC reader and runtime around a synthetic transport."""
    import custom_components.gwm_ora.gwm_client.apac_restore as restore
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data
    from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
    from custom_components.gwm_ora.gwm_client.regions import TlsMode

    credentials = GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)
    state = replace(
        ApacAuthState.for_credentials(credentials.client_credentials()),
        tokens=ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean"),
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    session = ApacReadSession(credentials.device_id, state.tokens.access_token, context, "PK")
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, ApacAuthenticated(state, session, material))
    reader = ApacReadClient(material=material, session=session, transport=transport, owns_transport=True)
    cloud = runtime.GwmCloudClient(
        REGION_APAC,
        reader,
        credentials=credentials,
        bootstrap=bootstrap,
        state_store=state_store,
        entry_data=cloud_entry_data(credentials),
        **options,
    )
    return cloud, credentials, state


class _RuntimeTransport:
    """Supply protocol-shaped APAC responses and record transport ownership."""

    def __init__(self):
        """Start with an expired synthetic access token and an open transport."""
        self.operations = []
        self.closed = False

    async def execute(self, request, **kwargs):
        """Expire the initial session and serve a nonempty read-only snapshot."""
        import json

        from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

        self.operations.append(request.operation)
        assert not self.closed
        if request.operation == "acquire_vehicles" and request.headers["accessToken"] == "synthetic-access":
            return _TransportResponse(401, {}, b"{}")
        payloads = {
            "refresh_token": {"accessToken": "renewed-access", "refreshToken": "renewed-refresh"},
            "get_user_info": {"gwId": "synthetic-gw", "beanId": "synthetic-bean"},
            "acquire_vehicles": [{"vin": "SYNTHETIC-VEHICLE"}],
            "get_last_status": {"items": [{"code": 2013021, "value": "65", "unit": "%"}]},
            "get_vehicle_basics": {},
        }
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": payloads[request.operation]}).encode())

    async def aclose(self):
        """Record disposal after all active recovery work has finished."""
        self.closed = True


def _synthetic_config_entry(credentials):
    """Construct a real Home Assistant entry for synthetic APAC lifecycle tests."""
    from types import MappingProxyType

    from homeassistant.config_entries import ConfigEntry

    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id

    return ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain="gwm_ora",
        entry_id="synthetic-apac-entry",
        minor_version=1,
        options={},
        source="user",
        subentries_data=None,
        title="GWM APAC",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )


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
    assert cloud.reusable_bootstrap is None
    assert client._session.access_token == "renewed-access"


@pytest.mark.asyncio
async def test_runtime_finishes_rotated_token_save_before_propagating_cancellation(tmp_path, monkeypatch):
    """Persist a rotated pair across restart even when shutdown cancels polling twice."""
    from homeassistant.core import HomeAssistant

    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

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
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    await store.async_save_auth_state(credentials, state)
    replacement = replace(
        state, tokens=ApacTokens("renewed-access", "renewed-refresh", "synthetic-gw", "synthetic-bean")
    )
    renewed_session = replace(session, access_token="renewed-access")
    save_started = asyncio.Event()
    release_save = asyncio.Event()
    save_cancelled = asyncio.Event()

    class DelayedStore:
        async def async_save_auth_state(self, supplied, updated):
            """Pause the real private save at the cancellation boundary."""
            save_started.set()
            try:
                await release_save.wait()
                await store.async_save_auth_state(supplied, updated)
            except asyncio.CancelledError:
                save_cancelled.set()
                raise

    async def rotate_session(**kwargs):
        """Publish a replacement pair before any subsequent profile validation."""
        await kwargs["on_session_updated"](ApacRestored(replacement, renewed_session))
        pytest.fail("Cancellation must stop the read after its private save completes")

    async def expired_action():
        """Require runtime token recovery without sending a vehicle request."""
        raise GwmAuthenticationError(operation="get_last_status")

    monkeypatch.setattr(runtime, "restore_apac_session", rotate_session)
    client = ApacReadClient(material=material, session=session, transport=None)
    cloud = runtime.GwmCloudClient(
        REGION_APAC, client, credentials=credentials, bootstrap=bootstrap, state_store=DelayedStore()
    )
    polling = asyncio.create_task(cloud._async_with_session_renewal(expired_action))
    try:
        await asyncio.wait_for(save_started.wait(), timeout=5)
        for _ in range(2):
            polling.cancel()
            await asyncio.sleep(0)
            assert not save_cancelled.is_set()
            assert not polling.done()
        release_save.set()
        with pytest.raises(asyncio.CancelledError):
            await polling
    finally:
        release_save.set()
        await asyncio.gather(polling, return_exceptions=True)
    restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == replacement
    assert cloud.reusable_bootstrap is None
    assert cloud._pending_auth_state is None


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_close_once", [False, True])
async def test_runtime_shutdown_drains_recovery_and_rejects_queued_reads(monkeypatch, cancel_close_once):
    """Keep the owning transport open until refresh and private persistence finish."""
    from custom_components.gwm_ora.gwm_client.errors import GwmClosedError

    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()
    saved = []

    class Transport(_RuntimeTransport):
        async def execute(self, request, **kwargs):
            """Hold the successful refresh response while runtime shutdown starts."""
            if request.operation == "refresh_token":
                refresh_started.set()
                await release_refresh.wait()
            return await super().execute(request, **kwargs)

    class Store:
        async def async_save_auth_state(self, credentials, state):
            """Record the published token revision before transport disposal."""
            assert not transport.closed
            saved.append(state)

    transport = Transport()
    cloud, _credentials, _state = _runtime_with_synthetic_transport(monkeypatch, transport, Store())
    active = asyncio.create_task(cloud.async_get_vehicle_data())
    queued = closing = None
    try:
        await asyncio.wait_for(refresh_started.wait(), timeout=5)
        queued = asyncio.create_task(cloud.async_get_vehicle_data())
        await asyncio.sleep(0)
        closing = asyncio.create_task(cloud.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        assert not transport.closed
        assert cloud.reusable_bootstrap is None
        with pytest.raises(GwmClosedError):
            await cloud.async_get_vehicle_data()
        if cancel_close_once:
            closing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert not transport.closed
            closing = asyncio.create_task(cloud.aclose())
            await asyncio.sleep(0)
        release_refresh.set()
        snapshot = await active
        assert snapshot["vehicles"][0]["values"]["soc"] == 65.0
        with pytest.raises(GwmClosedError):
            await queued
        await closing
        await cloud.aclose()
        with pytest.raises(GwmClosedError):
            await cloud.async_get_vehicle_data()
        assert transport.closed
        assert len(saved) == 1
        assert saved[0].tokens.refresh_token == "renewed-refresh"
        assert transport.operations.count("refresh_token") == 1
        assert transport.operations.count("get_last_status") == 1
    finally:
        release_refresh.set()
        await asyncio.gather(*(task for task in (active, queued, closing) if task is not None), return_exceptions=True)
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["startup", "runtime"])
@pytest.mark.parametrize("failure_operation", ["get_user_info", "acquire_vehicles"])
@pytest.mark.parametrize("rejection", ["551004", "http401", "http403"])
async def test_post_refresh_rejection_requires_reauthentication(
    tmp_path, monkeypatch, boundary, failure_operation, rejection
):
    """Retire failed recovery after one rotation for API-code and HTTP rejection."""
    from types import SimpleNamespace

    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_auth as auth_boundary
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    class Transport(_RuntimeTransport):
        async def execute(self, request, **kwargs):
            """Reject a validation read after the token rotation has succeeded."""
            if request.operation == failure_operation and request.headers.get("accessToken") == "renewed-access":
                self.operations.append(request.operation)
                if rejection.startswith("http"):
                    return _TransportResponse(int(rejection[4:]), {}, b"{}")
                return _TransportResponse(200, {}, b'{"code":"551004","data":{}}')
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    material = cloud.reusable_bootstrap.apac_material
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    cloud._state_store = store
    if boundary == "startup":
        monkeypatch.setattr(integration, "load_apac_material", lambda *args: material)
        monkeypatch.setattr(auth_boundary.AiohttpTransport, "create_owned", lambda **kwargs: transport)
        entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=unique_id)

        async def run():
            """Restore through the real Home Assistant startup authentication boundary."""
            return await integration._async_load_cloud_bootstrap(hass, entry, store)

        expected = ConfigEntryAuthFailed
    else:
        run = cloud.async_get_vehicle_data
        expected = GwmAuthenticationError
    try:
        with pytest.raises(expected):
            await run()
        assert await store.async_load_auth_state(cloud_entry_data(credentials)) is None
        assert transport.operations.count("refresh_token") == 1
        operations = list(transport.operations)
        with pytest.raises(expected):
            await run()
        assert transport.operations == operations
        if boundary == "runtime":
            assert cloud.reusable_bootstrap is None
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("matching_profile", [False, True])
async def test_pending_profile_validation_precedes_snapshots_and_reusable_handoffs(
    tmp_path, monkeypatch, matching_profile
):
    """Retain a rotated pair without accepting data until its account check succeeds."""
    from homeassistant.core import HomeAssistant

    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    class Transport(_RuntimeTransport):
        async def execute(self, request, **kwargs):
            """Fail one profile read, then return either this account or another one."""
            if request.operation == "get_user_info":
                attempts = self.operations.count("get_user_info")
                if attempts == 0:
                    self.operations.append(request.operation)
                    raise GwmNetworkError(operation="get_user_info")
                if not matching_profile:
                    self.operations.append(request.operation)
                    return _TransportResponse(
                        200, {}, b'{"code":"000000","data":{"gwId":"different-account","beanId":"synthetic-bean"}}'
                    )
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    await store.async_save_auth_state(credentials, state)
    cloud._state_store = store
    try:
        with pytest.raises(GwmNetworkError):
            await cloud.async_get_vehicle_data()
        retained = await store.async_load_auth_state(cloud_entry_data(credentials))
        assert retained.tokens.refresh_token == "renewed-refresh"
        assert cloud.reusable_bootstrap is None
        assert "get_last_status" not in transport.operations
        if matching_profile:
            snapshot = await cloud.async_get_vehicle_data()
            assert snapshot["vehicles"][0]["values"]["soc"] == 65.0
            assert cloud.reusable_bootstrap.state == retained
            second_profile = [i for i, operation in enumerate(transport.operations) if operation == "get_user_info"][1]
            assert second_profile < transport.operations.index("get_last_status")
            await cloud.async_get_vehicle_data()
        else:
            with pytest.raises(GwmAuthenticationError):
                await cloud.async_get_vehicle_data()
            assert await store.async_load_auth_state(cloud_entry_data(credentials)) is None
            assert cloud.reusable_bootstrap is None
            assert "get_last_status" not in transport.operations
        assert transport.operations.count("get_user_info") == 2
        assert transport.operations.count("refresh_token") == 1
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
async def test_refresh_failure_before_rotation_can_retry_without_skipping_refresh(monkeypatch):
    """Retry a failed refresh exchange without treating old tokens as a new session."""
    attempts = []

    class Transport(_RuntimeTransport):
        async def execute(self, request, **kwargs):
            """Fail the first refresh before the server returns replacement tokens."""
            if request.operation == "refresh_token":
                attempts.append("refresh")
                if len(attempts) == 1:
                    raise GwmNetworkError(operation="refresh_token")
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, _credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    try:
        with pytest.raises(GwmNetworkError):
            await cloud.async_get_vehicle_data()
        assert cloud.reusable_bootstrap.state == state
        snapshot = await cloud.async_get_vehicle_data()
        assert snapshot["vehicles"][0]["values"]["soc"] == 65.0
        assert len(attempts) == 2
        assert cloud.reusable_bootstrap.state.tokens.refresh_token == "renewed-refresh"
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_context", ["same", "changed_password", "removed"])
async def test_startup_retries_failed_rotation_save_before_reusing_credentials(tmp_path, monkeypatch, retry_context):
    """Retry private publication without reviving tokens after context change or removal."""
    from types import SimpleNamespace

    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_auth as auth_boundary
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

    first_transport = _RuntimeTransport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, first_transport)
    material = cloud.reusable_bootstrap.apac_material
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    original_save = store._store.async_save
    save_attempts = []
    transports = []

    async def fail_one_save(data):
        """Raise once at the actual Home Assistant disk publication boundary."""
        save_attempts.append("save")
        if len(save_attempts) == 1:
            raise OSError("synthetic temporary storage failure")
        await original_save(data)

    def make_transport(**kwargs):
        """Give each startup attempt a separately owned synthetic transport."""
        transport = first_transport if not transports else _RuntimeTransport()
        transports.append(transport)
        return transport

    monkeypatch.setattr(store._store, "async_save", fail_one_save)
    monkeypatch.setattr(integration, "load_apac_material", lambda *args: material)
    monkeypatch.setattr(auth_boundary.AiohttpTransport, "create_owned", make_transport)
    entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=unique_id)
    try:
        with pytest.raises(ConfigEntryNotReady):
            await integration._async_load_cloud_bootstrap(hass, entry, store)
        assert first_transport.operations == ["acquire_vehicles", "refresh_token"]
        if retry_context == "same":
            bootstrap = await integration._async_load_cloud_bootstrap(hass, entry, store)
            assert bootstrap.state.tokens.refresh_token == "renewed-refresh"
            assert transports[1].operations == ["acquire_vehicles", "get_user_info"]
            restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
            assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == bootstrap.state
        else:
            if retry_context == "changed_password":
                credentials = replace(credentials, password="replacement-password")
                entry.data = cloud_entry_data(credentials)
            else:
                await store.async_remove()
            with pytest.raises(ConfigEntryAuthFailed):
                await integration._async_load_cloud_bootstrap(hass, entry, store)
            assert len(transports) == 1
            assert await store.async_load_auth_state(entry.data) is None
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("close_save_fails_once", [False, True])
async def test_shutdown_flushes_failed_apac_rotation_before_disposing_transport(
    tmp_path, monkeypatch, close_save_fails_once
):
    """Publish pending tokens and close owned resources even if publication fails."""
    from homeassistant.core import HomeAssistant

    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

    transport = _RuntimeTransport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    await store.async_save_auth_state(credentials, state)
    cloud._state_store = store
    original_save = store._store.async_save
    attempts = []

    async def fail_then_publish(data):
        """Fail the poll save and optionally the first cleanup retry before recovery."""
        attempts.append("save")
        if len(attempts) <= (2 if close_save_fails_once else 1):
            raise OSError("synthetic temporary storage failure")
        await original_save(data)

    monkeypatch.setattr(store._store, "async_save", fail_then_publish)
    try:
        with pytest.raises(GwmNetworkError):
            await cloud.async_get_vehicle_data()
        assert cloud.reusable_bootstrap is None
        if close_save_fails_once:
            with pytest.raises(GwmNetworkError):
                await cloud.aclose()
            assert transport.closed
        await cloud.aclose()
        assert len(attempts) == (3 if close_save_fails_once else 2)
        assert transport.closed
        assert cloud.reusable_bootstrap is None
        assert transport.operations == ["acquire_vehicles", "refresh_token"]
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
        restored = await restarted.async_load_auth_state(cloud_entry_data(credentials))
        assert restored.tokens.refresh_token == "renewed-refresh"
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
async def test_logged_atomic_writer_failure_keeps_rotation_pending_until_disk_confirmation(tmp_path, monkeypatch):
    """Detect the real Store's swallowed writer error and retry before cleanup succeeds."""
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import storage as ha_storage

    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

    transport = _RuntimeTransport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
    await store.async_save_auth_state(credentials, state)
    cloud._state_store = store
    original_write = ha_storage.write_utf8_file_atomic
    attempts = []

    def fail_one_atomic_write(filename, *args, **kwargs):
        """Raise the writer error which Home Assistant itself catches and logs."""
        if filename == store._store.path:
            attempts.append("write")
            if len(attempts) == 1:
                raise ha_storage.WriteError("synthetic atomic writer failure")
        return original_write(filename, *args, **kwargs)

    monkeypatch.setattr(ha_storage, "write_utf8_file_atomic", fail_one_atomic_write)
    try:
        with pytest.raises(GwmNetworkError):
            await cloud.async_get_vehicle_data()
        assert cloud.reusable_bootstrap is None
        await cloud.aclose()
        assert len(attempts) == 2
        assert transport.closed
        assert transport.operations == ["acquire_vehicles", "refresh_token"]
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
        restored = await restarted.async_load_auth_state(cloud_entry_data(credentials))
        assert restored.tokens.refresh_token == "renewed-refresh"
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
async def test_first_refresh_and_cleanup_save_failures_preserve_automatic_setup_retry(tmp_path, monkeypatch):
    """Keep the real coordinator's retryable setup failure through failed cleanup."""
    from types import MappingProxyType

    from homeassistant.config_entries import ConfigEntry, ConfigEntryState
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryNotReady

    import custom_components.gwm_ora as integration
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

    transport = _RuntimeTransport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    runtime.stage_cloud_bootstrap(hass, unique_id, cloud.reusable_bootstrap)
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain="gwm_ora",
        entry_id="synthetic-setup-entry",
        minor_version=1,
        options={},
        source="user",
        subentries_data=None,
        title="GWM APAC",
        unique_id=unique_id,
        version=1,
    )
    entry._async_set_state(hass, ConfigEntryState.SETUP_IN_PROGRESS, None)
    original_save = store._store.async_save
    failed_saves = []

    async def fail_rotated_publications(data):
        """Fail the first-refresh and cleanup publications of replacement credentials."""
        if data["auth_state"]["tokens"]["refresh_token"] == "renewed-refresh":
            failed_saves.append("save")
            if len(failed_saves) <= 2:
                raise OSError("synthetic temporary storage failure")
        await original_save(data)

    monkeypatch.setattr(store._store, "async_save", fail_rotated_publications)
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    try:
        with pytest.raises(ConfigEntryNotReady):
            await integration.async_setup_entry(hass, entry)
        assert len(failed_saves) == 2
        assert transport.closed
        assert runtime.consume_cloud_bootstrap(hass, unique_id) is None
        retained = await store.async_load_auth_state(cloud_entry_data(credentials))
        assert retained.tokens.refresh_token == "renewed-refresh"
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
        assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == retained
    finally:
        await cloud.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("stopping", [False, True])
async def test_cancelled_staged_writer_cannot_overwrite_a_later_confirmed_rotation(tmp_path, monkeypatch, stopping):
    """Retain the old writer's locks until it finishes before accepting a new rotation."""
    import threading

    from homeassistant.core import CoreState, HomeAssistant
    from homeassistant.helpers import storage as ha_storage

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_auth as auth_boundary
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store

    transport = _RuntimeTransport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    material = cloud.reusable_bootstrap.apac_material
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    runtime.stage_cloud_bootstrap(hass, unique_id, cloud.reusable_bootstrap)
    if stopping:
        hass.set_state(CoreState.stopping)
    entry = _synthetic_config_entry(credentials)
    original_write = ha_storage.write_utf8_file_atomic
    loop = asyncio.get_running_loop()
    writer_started = asyncio.Event()
    writer_finished = asyncio.Event()
    release_writer = threading.Event()
    held = []

    def delay_one_write(filename, *args, **kwargs):
        """Hold the actual executor write independently of its awaiting task."""
        if filename != store._store.path or held:
            return original_write(filename, *args, **kwargs)
        held.append("old-write")
        loop.call_soon_threadsafe(writer_started.set)
        try:
            if not release_writer.wait(timeout=15):
                raise ha_storage.WriteError("synthetic writer was not released")
            return original_write(filename, *args, **kwargs)
        finally:
            loop.call_soon_threadsafe(writer_finished.set)

    monkeypatch.setattr(ha_storage, "write_utf8_file_atomic", delay_one_write)
    monkeypatch.setattr(integration, "load_apac_material", lambda *args: material)
    monkeypatch.setattr(auth_boundary.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    older = asyncio.create_task(integration._async_load_cloud_bootstrap(hass, entry, store))
    newer = None
    try:
        await asyncio.wait_for(writer_started.wait(), timeout=5)
        for _ in range(2):
            older.cancel()
            await asyncio.sleep(0)
            assert not older.done()
        newer = asyncio.create_task(integration._async_load_cloud_bootstrap(hass, entry, store))
        await asyncio.sleep(0)
        assert not newer.done()
        assert transport.operations == []
        release_writer.set()
        with pytest.raises(asyncio.CancelledError):
            await older
        bootstrap = await newer
        assert bootstrap.state.tokens.refresh_token == "renewed-refresh"
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
        assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) == bootstrap.state
        assert transport.operations.count("refresh_token") == 1
    finally:
        release_writer.set()
        await asyncio.gather(*(task for task in (older, newer) if task is not None), return_exceptions=True)
        await asyncio.wait_for(writer_finished.wait(), timeout=5)
        await cloud.aclose()


@pytest.mark.asyncio
async def test_failed_startup_retirement_publication_retries_before_requesting_reauthentication(tmp_path, monkeypatch):
    """Classify a logged clear failure as retryable until the rejected state is retired."""
    import json

    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
    from homeassistant.helpers import storage as ha_storage

    import custom_components.gwm_ora as integration
    import custom_components.gwm_ora.cloud_auth as auth_boundary
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_storage import cloud_state_store
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    class Transport(_RuntimeTransport):
        async def execute(self, request, **kwargs):
            """Reject the renewed session during account validation."""
            if request.operation == "get_user_info":
                self.operations.append(request.operation)
                return _TransportResponse(401, {}, b"{}")
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, credentials, state = _runtime_with_synthetic_transport(monkeypatch, transport)
    material = cloud.reusable_bootstrap.apac_material
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, state)
    entry = _synthetic_config_entry(credentials)
    original_write = ha_storage.write_utf8_file_atomic
    failed_clear = []

    def fail_one_retirement_write(filename, data, *args, **kwargs):
        """Inject a real writer failure only when retiring rejected authentication."""
        if filename == store._store.path and json.loads(data)["data"]["auth_state"] is None and not failed_clear:
            failed_clear.append("clear")
            raise ha_storage.WriteError("synthetic retirement writer failure")
        return original_write(filename, data, *args, **kwargs)

    monkeypatch.setattr(ha_storage, "write_utf8_file_atomic", fail_one_retirement_write)
    monkeypatch.setattr(integration, "load_apac_material", lambda *args: material)
    monkeypatch.setattr(auth_boundary.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    try:
        with pytest.raises(ConfigEntryNotReady):
            await integration._async_load_cloud_bootstrap(hass, entry, store)
        assert failed_clear == ["clear"]
        assert transport.closed
        operations = list(transport.operations)
        with pytest.raises(ConfigEntryAuthFailed):
            await integration._async_load_cloud_bootstrap(hass, entry, store)
        assert transport.operations == operations
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), unique_id)
        assert await restarted.async_load_auth_state(cloud_entry_data(credentials)) is None
    finally:
        await cloud.aclose()

@pytest.mark.asyncio
@pytest.mark.parametrize(("options", "vehicle", "charging"), [
    ({}, False, False),
    ({"enable_apac_climate": True}, False, False),
    ({"enable_apac_remote": True}, True, False),
    ({"enable_apac_charging": True}, False, True),
    ({"enable_apac_remote": True, "enable_apac_charging": True}, True, True),
])
async def test_setup_unifies_vehicle_consent_and_keeps_charging_separate(
    tmp_path, monkeypatch, options, vehicle, charging
):
    """Route one vehicle opt-in to climate and remote gates without widening old consent."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from homeassistant.core import HomeAssistant

    import custom_components.gwm_ora as integration
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id

    cloud, credentials, _ = _runtime_with_synthetic_transport(monkeypatch, _RuntimeTransport())
    entry = SimpleNamespace(
        unique_id=cloud_unique_id(credentials), data=cloud_entry_data(credentials),
        options={**options, "security_pin": "synthetic-pin"},
    )
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = SimpleNamespace(async_forward_entry_setups=AsyncMock())
    monkeypatch.setattr(integration, "_async_load_cloud_bootstrap", AsyncMock(return_value=cloud.reusable_bootstrap))
    supplied = {}

    def build(*args, **kwargs):
        """Capture the runtime consent supplied by actual Home Assistant setup."""
        supplied.update(kwargs)
        return cloud

    monkeypatch.setattr(integration.GwmCloudClient, "from_entry_data", build)
    coordinator = SimpleNamespace(async_config_entry_first_refresh=AsyncMock())
    monkeypatch.setattr(integration, "GwmDataUpdateCoordinator", lambda *args, **kwargs: coordinator)
    monkeypatch.setattr(integration, "_async_register_services", lambda hass: None)
    try:
        assert await integration._async_setup_cloud_entry(hass, entry)
        assert supplied["apac_climate_enabled"] is vehicle
        assert supplied["apac_remote_enabled"] is vehicle
        assert supplied["apac_charging_enabled"] is charging
        assert entry.runtime_data.api._apac_climate_enabled is vehicle
        assert entry.runtime_data.api._apac_remote_enabled is vehicle
        assert entry.runtime_data.api._apac_charging_enabled is charging
    finally:
        await cloud.aclose()

@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["tailgate_open", "charge_now"])
@pytest.mark.parametrize("phase", ["session_lock", "preflight", "dispatch"])
async def test_control_cancellation_respects_actual_dispatch(monkeypatch, action, phase):
    """Cancel queued controls, but finish one dispatched write and its journal."""
    from custom_components.gwm_ora.cloud_commands import GwmCommandApi
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    class Transport(_RuntimeTransport):
        """Pause a real request boundary without contacting a vehicle."""

        def __init__(self):
            """Prepare a controllable pause after initial discovery."""
            super().__init__()
            self.pausing = False
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def execute(self, request, **kwargs):
            """Pause validation or dispatch and return synthetic acceptance."""
            target = "get_user_info" if phase == "preflight" else "send_apac_control"
            if self.pausing and request.operation == target:
                self.started.set()
                await self.release.wait()
            if request.operation == "send_apac_control":
                self.operations.append(request.operation)
                return _TransportResponse(200, {}, b'{"code":"000000","data":{}}')
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, _, _ = _runtime_with_synthetic_transport(
        monkeypatch, transport, apac_remote_enabled=True, apac_charging_enabled=True
    )
    recorded = []
    api = object.__new__(GwmCommandApi)
    api._apac_closing = False
    api._apac_submissions = {}
    api._cloud = cloud
    api._security_pin = "1234"
    api._apac_remote_enabled = True
    api._apac_charging_enabled = True

    async def record(identifier, name, command_id):
        """Observe the journal boundary only after provider acceptance."""
        recorded.append(command_id)
        return {"id": command_id}

    monkeypatch.setattr(api, "_record_acceptance", record)
    await cloud.async_get_vehicle_data()
    transport.operations.clear()
    transport.pausing = True
    if phase == "session_lock":
        await cloud._session_renewal_lock.acquire()
    task = asyncio.create_task(api.async_apac_control("SYNTHETIC-VEHICLE", action))
    try:
        if phase == "session_lock":
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        else:
            await asyncio.wait_for(transport.started.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        if phase == "session_lock":
            cloud._session_renewal_lock.release()
        transport.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        dispatched = phase == "dispatch"
        assert transport.operations.count("send_apac_control") == int(dispatched)
        assert len(recorded) == int(dispatched)
    finally:
        transport.release.set()
        if cloud._session_renewal_lock.locked() and phase == "session_lock":
            cloud._session_renewal_lock.release()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await cloud.aclose()

@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_unload", [False, True])
async def test_unload_waits_for_apac_acceptance_publication(tmp_path, monkeypatch, cancel_unload):
    """Finish accepted-command storage before unload, even when both callers cancel."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from homeassistant.core import HomeAssistant

    import custom_components.gwm_ora as integration
    from custom_components.gwm_ora.cloud_auth import cloud_entry_data, cloud_unique_id
    from custom_components.gwm_ora.cloud_commands import GwmCommandApi
    from custom_components.gwm_ora.cloud_storage import cloud_state_store
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    class Transport(_RuntimeTransport):
        """Accept one fake control on the same transport as account validation."""

        async def execute(self, request, **kwargs):
            """Return a control acceptance without performing a vehicle action."""
            if request.operation == "send_apac_control":
                self.operations.append(request.operation)
                return _TransportResponse(200, {}, b'{"code":"000000","data":{}}')
            return await super().execute(request, **kwargs)

    transport = Transport()
    cloud, credentials, _ = _runtime_with_synthetic_transport(
        monkeypatch, transport, apac_remote_enabled=True
    )
    await cloud.async_get_vehicle_data()
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = SimpleNamespace(async_unload_platforms=AsyncMock(return_value=True))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    cloud._state_store = store
    await store.async_save_auth_state(credentials, cloud.reusable_bootstrap.state)
    api = GwmCommandApi(cloud, store, credentials, enabled=True,
                        apac_remote_enabled=True, security_pin="1234")
    entry = _synthetic_config_entry(credentials)
    entry.runtime_data = SimpleNamespace(api=api, cloud=cloud, state_store=store,
        coordinator=SimpleNamespace(async_cancel_command_tasks=AsyncMock()))
    started = asyncio.Event()
    release = asyncio.Event()
    original = store.async_record_accepted_command

    async def delayed_record(*args, **kwargs):
        """Pause acceptance before the real private disk publication."""
        started.set()
        await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(store, "async_record_accepted_command", delayed_record)
    caller = asyncio.create_task(api.async_apac_control("SYNTHETIC-VEHICLE", "tailgate_open"))
    await asyncio.wait_for(started.wait(), 2)
    caller.cancel()
    unloading = asyncio.create_task(integration.async_unload_entry(hass, entry))
    try:
        for _ in range(5):
            await asyncio.sleep(0)
        assert not unloading.done()
        assert not transport.closed
        if cancel_unload:
            for _ in range(2):
                unloading.cancel()
                caller.cancel()
                await asyncio.sleep(0)
            assert not unloading.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await caller
        if cancel_unload:
            with pytest.raises(asyncio.CancelledError):
                await unloading
        else:
            assert await unloading
        assert transport.closed
        restarted = cloud_state_store(HomeAssistant(str(tmp_path)), cloud_unique_id(credentials))
        journal = await restarted.async_get_command_journal(cloud_entry_data(credentials))
        assert len(journal) == 1 and journal[0].state == "accepted"
        assert transport.operations.count("send_apac_control") == 1
    finally:
        release.set()
        await asyncio.gather(caller, unloading, return_exceptions=True)
        await cloud.aclose()
