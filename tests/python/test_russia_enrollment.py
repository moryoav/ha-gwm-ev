"""Russian enrollment, real local mutual TLS, and private restart journeys."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import socket
import ssl
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import aiohttp
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from support.certificates import RegionalCertificateChain, sign_csr
from support.overseas import _response

pytest.importorskip("homeassistant")
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

import custom_components.gwm_ora as integration
from custom_components.gwm_ora import cloud_runtime, config_flow
from custom_components.gwm_ora.cloud_auth import (
    GwmCloudAuthenticator,
    GwmCloudCredentials,
    _load_bootstrap_material,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_runtime import GwmCloudBootstrap, GwmCloudClient
from custom_components.gwm_ora.cloud_storage import (
    _decode_auth_state,
    _encode_auth_state,
    cloud_state_store,
    credentials_for_auth_state,
)
from custom_components.gwm_ora.const import CONF_RUSSIA_CERTIFICATE_ENROLLMENT
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.gwm_client import russia_auth
from custom_components.gwm_ora.gwm_client._protocol import _TransportRequest
from custom_components.gwm_ora.gwm_client.client import GwmClient
from custom_components.gwm_ora.gwm_client.config import GwmClientConfig
from custom_components.gwm_ora.gwm_client.crypto import generate_client_certificate_request
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmHttpError,
    GwmSchemaError,
)
from custom_components.gwm_ora.gwm_client.russia_auth import RussiaAuthenticated, RussiaAuthState
from custom_components.gwm_ora.gwm_client.russia_identity import (
    RussiaBootstrapMaterial,
)
from custom_components.gwm_ora.gwm_client.tls import create_gwm_ssl_context
from custom_components.gwm_ora.gwm_client.transport import AiohttpTransport

DEVICE = "0123456789abcdef0123456789abcdef"
PROFILE = {"gwId": "synthetic-account-id", "beanId": "synthetic-bean-id"}


@pytest.fixture(scope="module")
def chain():
    return RegionalCertificateChain.create()


def _credentials(enabled=True):
    return GwmCloudCredentials(
        "rus", "RU", "synthetic@example.invalid", "synthetic-password", DEVICE,
        russia_certificate_enrollment=enabled,
    )


def _state(credentials, **changes):
    return RussiaAuthState(
        credentials.account_binding, "RU", DEVICE, "synthetic-access", "synthetic-refresh",
        PROFILE["gwId"], PROFILE["beanId"], **changes,
    )


def _material(chain):
    material = _load_bootstrap_material("rus")
    assert type(material) is RussiaBootstrapMaterial
    return replace(material, ca_bundle=chain.bundle)


def _patch_contexts(monkeypatch, tmp_path, chain):
    request = generate_client_certificate_request("RU", DEVICE, common_name="LGWGWM-AD-RU-GENERAL")
    certificate = sign_csr(request.csr, chain.general)
    certfile, keyfile = tmp_path / "bootstrap.pem", tmp_path / "bootstrap.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM) + chain.general.certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(serialization.load_der_private_key(base64.b64decode(request.private_key), None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    keyfile.chmod(0o600)
    bootstrap = create_gwm_ssl_context(ca_data=chain.bundle, certfile=certfile, keyfile=keyfile)
    default = ssl.create_default_context(cadata=chain.bundle.decode())
    monkeypatch.setattr(russia_auth, "create_russia_bootstrap_ssl_context", lambda *args, **kwargs: bootstrap)
    monkeypatch.setattr(russia_auth, "_create_default_ssl_context", lambda: default)
    return bootstrap


class _EnrollmentProvider:
    def __init__(self, chain, *, failure=None, days=30):
        self.chain, self.failure, self.days = chain, failure, days
        self.requests = []
        self.encoded = None

    async def execute(self, request, **kwargs):
        self.requests.append(request)
        if request.operation == "get_user_info":
            return _response(PROFILE)
        if request.operation in {"login", "refresh_token"}:
            return _response({"accessToken": "synthetic-access", "refreshToken": "synthetic-refresh", **PROFILE})
        if request.operation == "enroll_certificate":
            if self.failure is not None:
                return self.failure
            body = json.loads(request.body)
            assert body["phone"] == PROFILE["gwId"]
            certificate = sign_csr(body["csr"], self.chain.issued, days=self.days)
            self.encoded = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()
            return _response({"encoded": self.encoded})
        if request.operation == "acquire_vehicles":
            return _response([{"vin": "LGWTEST0000000001", "modelName": "Synthetic"}])
        raise AssertionError(request.operation)

    async def aclose(self):
        pass


def _authenticator(provider, chain):
    return GwmCloudAuthenticator(
        overseas_client_factory=lambda config: GwmClient(config, transport=provider),
        resource_loader=lambda region: _material(chain),
    )


@pytest.mark.asyncio
async def test_enrollment_validates_returned_key_chain_and_request_contract(monkeypatch, tmp_path, chain, caplog):
    caplog.set_level(logging.DEBUG)
    bootstrap = _patch_contexts(monkeypatch, tmp_path, chain)
    provider = _EnrollmentProvider(chain)
    credentials = _credentials()
    result = await _authenticator(provider, chain).async_authenticate(credentials, state=_state(credentials))
    assert type(result) is RussiaAuthenticated
    assert result.state.issued_identity is not None
    assert result.session.app_ssl_context is not bootstrap
    enrollment = provider.requests[-1]
    assert enrollment.url == "https://rus-app-gateway-common.gwmcloud.com/app-api/api/v1.0/appAuth/applyCertificate"
    assert enrollment.ssl_context is bootstrap
    assert enrollment.headers["accessToken"] == "synthetic-access"
    assert enrollment.headers["deviceId"] == enrollment.headers["iccid"]
    assert re.fullmatch(r"[a-f0-9]{32}[0-9]{13}", enrollment.headers["deviceId"])
    assert enrollment.headers["deviceId"] != DEVICE
    body = json.loads(enrollment.body)
    assert set(body) == {"csr", "phone"}
    csr = x509.load_der_x509_csr(base64.b64decode(body["csr"]))
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.startswith("LGWGWM-AD-RU")
    assert csr.public_key().public_numbers() == x509.load_der_x509_certificate(
        base64.b64decode(result.state.issued_identity.certificate),
    ).public_key().public_numbers()
    assert result.session.app_ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert result.session.app_ssl_context.check_hostname
    assert "stage=enrollment outcome=completed" in caplog.text
    for secret in (credentials.account, credentials.password, PROFILE["gwId"], DEVICE, body["csr"], provider.encoded,
                   result.state.issued_identity.private_key):
        assert secret not in caplog.text
    assert repr(result.state.issued_identity) == "RussiaIssuedIdentity()"


@pytest.mark.asyncio
@pytest.mark.parametrize("previously_enrolled", [False, True])
async def test_default_path_never_enrolls_and_removes_optional_identity(monkeypatch, tmp_path, chain, previously_enrolled):
    bootstrap = _patch_contexts(monkeypatch, tmp_path, chain)
    provider = _EnrollmentProvider(chain)
    credentials = _credentials(False)
    authenticator = _authenticator(provider, chain)
    state = _state(credentials)
    if previously_enrolled:
        enrolled = await authenticator.async_authenticate(_credentials(), state=state)
        state = enrolled.state
        assert state.issued_identity is not None
        provider.requests.clear()
    result = await authenticator.async_authenticate(credentials, state=state)
    assert result.session.app_ssl_context is bootstrap
    assert result.state.issued_identity is None
    assert [request.operation for request in provider.requests] == ["get_user_info"]
    assert CONF_RUSSIA_CERTIFICATE_ENROLLMENT not in cloud_entry_data(credentials)
    assert "issued_identity" not in _encode_auth_state(result.state)


@pytest.mark.asyncio
async def test_private_restart_reuses_certificate_without_enrollment_or_password(monkeypatch, tmp_path, chain):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    provider = _EnrollmentProvider(chain)
    authenticator = _authenticator(provider, chain)
    result = await authenticator.async_authenticate(credentials, state=_state(credentials))
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, result.state)
    restarted_hass = HomeAssistant(str(tmp_path / "ha"))
    restarted_store = cloud_state_store(restarted_hass, cloud_unique_id(credentials))
    restored = await restarted_store.async_load_auth_state(cloud_entry_data(credentials))
    assert restored == result.state
    rebuilt = credentials_for_auth_state(cloud_entry_data(credentials), restored)
    assert rebuilt.russia_certificate_enrollment is True
    provider.requests.clear()
    resumed = await authenticator.async_authenticate(rebuilt, state=restored, allow_password_login=False)
    assert resumed.state == restored
    assert [request.operation for request in provider.requests] == ["get_user_info"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,expected", [
    (_response(code="607012"), GwmApiError),
    (_response(status=400), GwmHttpError),
    (_response({"encoded": "not-a-certificate"}), GwmSchemaError),
])
async def test_enrollment_failure_is_bounded_and_does_not_fall_back(monkeypatch, tmp_path, chain, failure, expected):
    _patch_contexts(monkeypatch, tmp_path, chain)
    provider = _EnrollmentProvider(chain, failure=failure)
    credentials = _credentials()
    state = _state(credentials)
    with pytest.raises(expected) as caught:
        await _authenticator(provider, chain).async_authenticate(credentials, state=state)
    assert caught.value.operation == "enroll_certificate"
    assert state.issued_identity is None
    assert [request.operation for request in provider.requests] == ["get_user_info", "enroll_certificate"]


@pytest.mark.asyncio
async def test_renewal_replaces_expiring_identity_and_keeps_refresh_state(monkeypatch, tmp_path, chain):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    provider = _EnrollmentProvider(chain)
    authenticator = _authenticator(provider, chain)
    first = await authenticator.async_authenticate(credentials, state=_state(credentials))
    monkeypatch.setattr(russia_auth, "_utc_now", lambda: datetime.now(UTC) + timedelta(days=29, hours=12))
    # Issue the replacement with enough lifetime for the simulated future clock.
    provider.days = 60
    renewed = await authenticator.async_authenticate(credentials, state=first.state, allow_password_login=False)
    assert renewed.state.issued_identity != first.state.issued_identity
    assert renewed.state.device_id == first.state.device_id
    assert renewed.state.access_token == first.state.access_token
    assert [request.operation for request in provider.requests].count("enroll_certificate") == 2


@pytest.mark.asyncio
async def test_runtime_renews_before_action_and_persists_without_command_replay(monkeypatch, tmp_path, chain):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    provider = _EnrollmentProvider(chain)
    authenticator = _authenticator(provider, chain)
    result = await authenticator.async_authenticate(credentials, state=_state(credentials))
    bootstrap = GwmCloudBootstrap.from_authentication(credentials, result)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), result.session, transport=provider)
    store = type("Store", (), {"async_save_auth_state": AsyncMock()})()
    runtime = GwmCloudClient("rus", client, bootstrap=bootstrap, credentials=credentials, state_store=store,
                             entry_data=cloud_entry_data(credentials))
    monkeypatch.setattr(cloud_runtime, "is_russia_issued_identity_usable", lambda *args, **kwargs: False)
    monkeypatch.setattr(cloud_runtime, "GwmCloudAuthenticator", lambda: authenticator)
    action = AsyncMock(return_value="sent-once")
    assert await runtime._async_with_session_renewal(action) == "sent-once"
    action.assert_awaited_once()
    assert store.async_save_auth_state.await_count == 2
    await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["http_503", "cancel_enrollment", "cancel_save"])
async def test_rotated_tokens_survive_enrollment_failure_cancellation_and_restart(monkeypatch, tmp_path, chain, failure):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    enrollment_started, saving_started, finish_save = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class RotatingProvider(_EnrollmentProvider):
        rotating = False
        refreshed = False
        enrollment_failure = False

        async def execute(self, request, **kwargs):
            if self.rotating:
                if request.operation == "get_user_info" and request.headers["accessToken"] == "synthetic-access":
                    self.requests.append(request)
                    return _response(status=401)
                if request.operation == "refresh_token":
                    self.requests.append(request)
                    assert not self.refreshed, "The invalidated old refresh token was used again"
                    self.refreshed = True
                    return _response({"accessToken": "rotated-access", "refreshToken": "rotated-refresh"})
                if request.operation == "enroll_certificate" and self.enrollment_failure:
                    self.requests.append(request)
                    enrollment_started.set()
                    if failure == "cancel_enrollment":
                        await asyncio.Event().wait()
                    return _response(status=503)
            return await super().execute(request, **kwargs)

    provider = RotatingProvider(chain)
    authenticator = _authenticator(provider, chain)
    first = await authenticator.async_authenticate(credentials, state=_state(credentials))
    future = datetime.now(UTC) + timedelta(days=29, hours=12)
    monkeypatch.setattr(russia_auth, "_utc_now", lambda: future)
    monkeypatch.setattr(cloud_runtime, "GwmCloudAuthenticator", lambda: authenticator)
    provider.rotating = provider.enrollment_failure = True
    provider.days = 60
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    original_save = store.async_save_auth_state

    async def delayed_save(credentials, state):
        if failure == "cancel_save" and state.access_token == "rotated-access":
            saving_started.set()
            await finish_save.wait()
        await original_save(credentials, state)

    monkeypatch.setattr(store, "async_save_auth_state", delayed_save)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first),
        credentials=credentials, state_store=store, entry_data=cloud_entry_data(credentials), clock=lambda: future,
    )
    action = AsyncMock()
    try:
        if failure == "http_503":
            with pytest.raises(GwmHttpError):
                await runtime._async_with_session_renewal(action)
        else:
            task = asyncio.create_task(runtime._async_with_session_renewal(action))
            await asyncio.wait_for((saving_started if failure == "cancel_save" else enrollment_started).wait(), 5)
            task.cancel()
            await asyncio.sleep(0)
            if failure == "cancel_save":
                assert not task.done()
                task.cancel()
                finish_save.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        action.assert_not_awaited()
        assert runtime.reusable_bootstrap is None
        assert runtime._current_auth_state().access_token == "rotated-access"
        restarted_hass = HomeAssistant(str(tmp_path / "ha"))
        restarted_store = cloud_state_store(restarted_hass, cloud_unique_id(credentials))
        saved = await restarted_store.async_load_auth_state(cloud_entry_data(credentials))
        assert saved.access_token == "rotated-access"
        assert saved.refresh_token == "rotated-refresh"
        # Restart through the actual integration boundary; no password/SMS or second token rotation is allowed.
        provider.enrollment_failure = False
        monkeypatch.setattr(integration, "GwmCloudAuthenticator", lambda: authenticator)
        entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=cloud_unique_id(credentials))
        resumed = await integration._async_load_cloud_bootstrap(restarted_hass, entry, restarted_store)
        assert resumed.state.access_token == "rotated-access"
        assert resumed.state.issued_identity != first.state.issued_identity
        assert sum(request.operation == "refresh_token" for request in provider.requests) == 1
        assert not any(request.operation in {"login", "request_verification"} for request in provider.requests)
    finally:
        finish_save.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_command_preflight_rejection_retires_private_state_without_deadlock(monkeypatch, tmp_path, chain):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))

    class RejectedProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            return _response(status=401)

    provider = RejectedProvider(chain)
    authenticator = _authenticator(provider, chain)
    monkeypatch.setattr(cloud_runtime, "GwmCloudAuthenticator", lambda: authenticator)
    monkeypatch.setattr(cloud_runtime, "is_russia_issued_identity_usable", lambda *args, **kwargs: False)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials),
    )
    action = AsyncMock()
    try:
        with pytest.raises(GwmAuthenticationError):
            await asyncio.wait_for(runtime._async_with_session_renewal(action), 5)
        action.assert_not_awaited()
        assert runtime._current_auth_state() is None
        assert await store.async_load_auth_state(cloud_entry_data(credentials)) is None
        assert [request.operation for request in provider.requests] == ["get_user_info", "refresh_token"]
    finally:
        await runtime.aclose()


def test_legacy_storage_and_opt_in_validation():
    credentials = _credentials(False)
    state = _state(credentials)
    assert _decode_auth_state("rus", _encode_auth_state(state)) == state
    assert CONF_RUSSIA_CERTIFICATE_ENROLLMENT not in config_flow._account_schema("eu").schema
    schema = config_flow._account_schema("rus")
    values = schema({"account": credentials.account, "password": credentials.password})
    assert values[CONF_RUSSIA_CERTIFICATE_ENROLLMENT] is False
    for region in ("eu", "aus"):
        with pytest.raises(ValueError):
            GwmClientConfig(region, russia_certificate_enrollment=True)
    with pytest.raises(ValueError):
        GwmCloudCredentials("rus", "RU", "a", "b", DEVICE, russia_certificate_enrollment="true")


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
@pytest.mark.parametrize("command", [False, True])
async def test_rejected_runtime_session_clears_private_storage_without_refresh_or_replay(monkeypatch, tmp_path, chain, code, command):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))

    class RejectedProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            return _response(code=code)

    provider = RejectedProvider(chain)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials),
    )
    coordinator = GwmDataUpdateCoordinator(hass, AsyncMock(), cloud_client=runtime)
    try:
        if command:
            from custom_components.gwm_ora.gwm_client import VehicleIdentifier
            with pytest.raises(GwmAuthenticationError) as raised:
                await runtime._async_with_session_renewal(lambda: client.update_climate_defaults(
                    VehicleIdentifier("LGWTEST0000000001"), temperature=21, operation_time_minutes=10,
                ))
            assert raised.value.api_code == code
        else:
            with pytest.raises(ConfigEntryAuthFailed, match=code):
                await coordinator._async_update_data()
        assert runtime.reusable_bootstrap is None
        with pytest.raises(GwmAuthenticationError):
            await runtime.async_get_vehicle_data()
        assert len(provider.requests) == 1
        restarted_store = cloud_state_store(HomeAssistant(str(tmp_path / "ha")), cloud_unique_id(credentials))
        assert await restarted_store.async_load_auth_state(cloud_entry_data(credentials)) is None
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
async def test_startup_requests_reauth_and_explicit_sign_in_reuses_certificate(monkeypatch, tmp_path, chain, code):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))

    class RejectedProfileProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            if not self.requests:
                self.requests.append(request)
                assert request.operation == "get_user_info"
                return _response(code=code)
            return await super().execute(request, **kwargs)

    provider = RejectedProfileProvider(chain)
    authenticator = _authenticator(provider, chain)
    monkeypatch.setattr(integration, "GwmCloudAuthenticator", lambda: authenticator)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=cloud_unique_id(credentials))
    with pytest.raises(ConfigEntryAuthFailed, match=code):
        await integration._async_load_cloud_bootstrap(hass, entry, store)
    assert [request.operation for request in provider.requests] == ["get_user_info"]
    assert await store.async_load_auth_state(cloud_entry_data(credentials)) is None
    # An explicit sign-in can replace rejected tokens while the flow still has the certificate.
    provider.requests.clear()
    result = await authenticator.async_authenticate(credentials, state=first.state)
    assert result.state.issued_identity == first.state.issued_identity
    assert [request.operation for request in provider.requests] == ["get_user_info", "login", "get_user_info"]


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
async def test_late_terminal_response_does_not_clear_newer_russia_state(monkeypatch, tmp_path, chain, code):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))
    entered, release = asyncio.Event(), asyncio.Event()
    class PausedProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            entered.set()
            await release.wait()
            return _response(code=code)
    provider = PausedProvider(chain)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    store = cloud_state_store(HomeAssistant(str(tmp_path / "ha")), cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials),
    )
    task = asyncio.create_task(runtime._async_with_session_renewal(client.acquire_vehicles, retry_after_renewal=True))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        updated = replace(first, state=replace(first.state, access_token="new-access"), session=replace(first.session, access_token="new-access"))
        async with runtime._session_renewal_lock:
            runtime._bootstrap = GwmCloudBootstrap.from_authentication(credentials, updated)
            client.replace_session(updated.session)
            await store.async_save_auth_state(credentials, updated.state)
        release.set()
        with pytest.raises(GwmApiError) as raised:
            await asyncio.wait_for(task, 5)
        assert type(raised.value) is GwmApiError
        assert client.authenticated
        assert runtime._current_auth_state() == updated.state
        assert await store.async_load_auth_state(cloud_entry_data(credentials)) == updated.state
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
@pytest.mark.parametrize("command", [False, True])
async def test_queued_request_retires_the_replacement_it_actually_used(monkeypatch, tmp_path, chain, code, command):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))
    class RejectedProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            return _response(code=code)
    provider = RejectedProvider(chain)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials),
    )
    entered = asyncio.Event()
    async def action():
        entered.set()
        if command:
            from custom_components.gwm_ora.gwm_client import VehicleIdentifier
            return await client.update_climate_defaults(VehicleIdentifier("LGWTEST0000000001"), temperature=21, operation_time_minutes=10)
        return await client.acquire_vehicles()
    await client._request_lock.acquire()
    task = asyncio.create_task(runtime._async_with_session_renewal(action, retry_after_renewal=not command))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        updated = replace(first, state=replace(first.state, access_token="new-access"), session=replace(first.session, access_token="new-access"))
        async with runtime._session_renewal_lock:
            runtime._bootstrap = GwmCloudBootstrap.from_authentication(credentials, updated)
            client.replace_session(updated.session)
            await store.async_save_auth_state(credentials, updated.state)
        client._request_lock.release()
        with pytest.raises(GwmAuthenticationError) as raised:
            await asyncio.wait_for(task, 5)
        assert raised.value.api_code == code
        assert not client.authenticated
        assert runtime._current_auth_state() is None
        assert len(provider.requests) == 1
        assert provider.requests[0].headers["accessToken"] == "new-access"
        restarted_store = cloud_state_store(HomeAssistant(str(tmp_path / "ha")), cloud_unique_id(credentials))
        assert await restarted_store.async_load_auth_state(cloud_entry_data(credentials)) is None
    finally:
        if client._request_lock.locked():
            client._request_lock.release()
        await asyncio.gather(task, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
@pytest.mark.parametrize("replacement", [False, True])
async def test_terminal_retry_retires_current_session_but_preserves_later_replacement(monkeypatch, tmp_path, chain, code, replacement):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))
    entered, release = asyncio.Event(), asyncio.Event()
    class RetryProvider(_EnrollmentProvider):
        async def execute(self, request, **kwargs):
            if request.operation == "acquire_vehicles":
                self.requests.append(request)
                if len(self.requests) == 1:
                    return _response(code="550004")
                entered.set()
                await release.wait()
                return _response(code=code)
            return await super().execute(request, **kwargs)
    provider = RetryProvider(chain)
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials),
    )
    coordinator = GwmDataUpdateCoordinator(hass, AsyncMock(), cloud_client=runtime)
    task = asyncio.create_task(coordinator._async_update_data())
    updated = replace(first, state=replace(first.state, access_token="new-access"), session=replace(first.session, access_token="new-access"))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        if replacement:
            async with runtime._session_renewal_lock:
                runtime._bootstrap = GwmCloudBootstrap.from_authentication(credentials, updated)
                client.replace_session(updated.session)
                await store.async_save_auth_state(credentials, updated.state)
        release.set()
        with pytest.raises(UpdateFailed if replacement else ConfigEntryAuthFailed, match=code):
            await asyncio.wait_for(task, 5)
        assert client.authenticated is replacement
        expected = updated.state if replacement else None
        assert runtime._current_auth_state() == expected
        restarted_store = cloud_state_store(HomeAssistant(str(tmp_path / "ha")), cloud_unique_id(credentials))
        assert await restarted_store.async_load_auth_state(cloud_entry_data(credentials)) == expected
        assert [request.operation for request in provider.requests] == ["acquire_vehicles", "refresh_token", "get_user_info", "acquire_vehicles"]
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["570062", "607501"])
async def test_late_old_session_rejection_preserves_partial_renewal_and_restart(monkeypatch, tmp_path, chain, code):
    _patch_contexts(monkeypatch, tmp_path, chain)
    credentials = _credentials()
    first = await _authenticator(_EnrollmentProvider(chain), chain).async_authenticate(credentials, state=_state(credentials))
    read_entered, release_read = asyncio.Event(), asyncio.Event()
    enrollment_entered, release_enrollment = asyncio.Event(), asyncio.Event()
    rejection_entered = asyncio.Event()
    class Provider(_EnrollmentProvider):
        enrollment_fails = True
        async def execute(self, request, **kwargs):
            if request.operation == "acquire_vehicles":
                self.requests.append(request)
                read_entered.set()
                await release_read.wait()
                return _response(code=code)
            if request.operation == "get_user_info" and request.headers["accessToken"] == "synthetic-access":
                self.requests.append(request)
                return _response(code="550004")
            if request.operation == "refresh_token":
                self.requests.append(request)
                return _response({"accessToken": "rotated-access", "refreshToken": "rotated-refresh"})
            if request.operation == "enroll_certificate" and self.enrollment_fails:
                self.requests.append(request)
                enrollment_entered.set()
                await release_enrollment.wait()
                return _response(status=503)
            return await super().execute(request, **kwargs)
    provider = Provider(chain, days=60)
    authenticator = _authenticator(provider, chain)
    monkeypatch.setattr(cloud_runtime, "GwmCloudAuthenticator", lambda: authenticator)
    now = [datetime.now(UTC)]
    client = GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), first.session, transport=provider)
    hass = HomeAssistant(str(tmp_path / "ha"))
    store = cloud_state_store(hass, cloud_unique_id(credentials))
    await store.async_save_auth_state(credentials, first.state)
    runtime = GwmCloudClient(
        "rus", client, bootstrap=GwmCloudBootstrap.from_authentication(credentials, first), credentials=credentials,
        state_store=store, entry_data=cloud_entry_data(credentials), clock=lambda: now[0],
    )
    original_rejection = runtime._async_raise_russia_session_rejection
    async def observe_rejection(error):
        rejection_entered.set()
        await original_rejection(error)
    monkeypatch.setattr(runtime, "_async_raise_russia_session_rejection", observe_rejection)
    read = asyncio.create_task(runtime._async_with_session_renewal(client.acquire_vehicles, retry_after_renewal=True))
    renewal = None
    action = AsyncMock()
    try:
        await asyncio.wait_for(read_entered.wait(), 5)
        now[0] += timedelta(days=29, hours=12)
        monkeypatch.setattr(russia_auth, "_utc_now", lambda: now[0])
        renewal = asyncio.create_task(runtime._async_with_session_renewal(action))
        await asyncio.wait_for(enrollment_entered.wait(), 5)
        partial = runtime._current_auth_state()
        assert partial.access_token == "rotated-access"
        release_read.set()
        await asyncio.wait_for(rejection_entered.wait(), 5)
        assert not client.authenticated
        release_enrollment.set()
        with pytest.raises(GwmHttpError):
            await asyncio.wait_for(renewal, 5)
        with pytest.raises(GwmApiError) as raised:
            await asyncio.wait_for(read, 5)
        assert type(raised.value) is GwmApiError
        action.assert_not_awaited()
        restarted_hass = HomeAssistant(str(tmp_path / "ha"))
        restarted_store = cloud_state_store(restarted_hass, cloud_unique_id(credentials))
        assert await restarted_store.async_load_auth_state(cloud_entry_data(credentials)) == partial
        provider.enrollment_fails = False
        monkeypatch.setattr(integration, "GwmCloudAuthenticator", lambda: authenticator)
        entry = SimpleNamespace(data=cloud_entry_data(credentials), unique_id=cloud_unique_id(credentials))
        restored = await integration._async_load_cloud_bootstrap(restarted_hass, entry, restarted_store)
        assert restored.state.access_token == "rotated-access"
        assert restored.state.issued_identity != first.state.issued_identity
        assert sum(request.operation == "refresh_token" for request in provider.requests) == 1
        assert not any(request.operation in {"login", "request_verification"} for request in provider.requests)
    finally:
        release_read.set()
        release_enrollment.set()
        await asyncio.gather(*([read, renewal] if renewal is not None else [read]), return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
async def test_real_https_presents_general_certificate_for_enrollment_and_issued_for_discovery(monkeypatch, tmp_path, chain):
    _patch_contexts(monkeypatch, tmp_path, chain)
    server_request = generate_client_certificate_request("RU", DEVICE, common_name="localhost")
    server_cert = sign_csr(server_request.csr, chain.root, server=True)
    certfile, keyfile = tmp_path / "server.pem", tmp_path / "server.key"
    certfile.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(serialization.load_der_private_key(base64.b64decode(server_request.private_key), None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    keyfile.chmod(0o600)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile, keyfile)
    server_context.load_verify_locations(cadata=chain.bundle.decode())
    server_context.verify_mode = ssl.CERT_OPTIONAL
    observed = []

    async def handler(request):
        peer = request.transport.get_extra_info("peercert")
        issuer = dict(item for rdn in peer.get("issuer", ()) for item in rdn).get("commonName") if peer else None
        observed.append((request.path, issuer))
        if request.path.endswith("getUserBaseInfo"):
            data = PROFILE
        elif request.path.endswith("applyCertificate"):
            assert issuer == "IOV APP General SubCA"
            body = await request.json()
            data = {"encoded": base64.b64encode(sign_csr(body["csr"], chain.issued).public_bytes(serialization.Encoding.DER)).decode()}
        elif request.path.endswith("acquireVehicles"):
            assert issuer == "IOV APP SubCA"
            data = [{"vin": "LGWTEST0000000001", "modelName": "Synthetic"}]
        else:
            raise AssertionError(request.path)
        return web.json_response({"code": "000000", "data": data})

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_context)
    await site.start()
    original_hosts = []
    transports = []

    class LocalResolver(aiohttp.abc.AbstractResolver):
        async def resolve(self, host, port=0, family=socket.AF_INET):
            return [{"hostname": host, "host": "127.0.0.1", "port": site._server.sockets[0].getsockname()[1],
                     "family": socket.AF_INET, "proto": 0, "flags": 0}]

        async def close(self):
            pass

    class LocalTlsTransport:
        def __init__(self):
            session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(resolver=LocalResolver()),
                cookie_jar=aiohttp.DummyCookieJar(), middlewares=(), trust_env=False,
            )
            session._retry_connection = False
            self.transport = AiohttpTransport(session, owns_session=True)
            transports.append(self)

        async def execute(self, request: _TransportRequest, **kwargs):
            original_hosts.append(urlsplit(request.url).hostname)
            return await self.transport.execute(request, **kwargs)

        async def aclose(self):
            await self.transport.aclose()

    credentials = _credentials()
    try:
        authenticator = GwmCloudAuthenticator(
            overseas_client_factory=lambda config: GwmClient(config, transport=LocalTlsTransport()),
            resource_loader=lambda region: _material(chain),
        )
        result = await authenticator.async_authenticate(credentials, state=_state(credentials))
        async with GwmClient(GwmClientConfig("rus", russia_certificate_enrollment=True), result.session,
                             transport=LocalTlsTransport()) as client:
            vehicles = await client.acquire_vehicles()
        assert len(vehicles) == 1
        assert [issuer for path, issuer in observed] == [None, "IOV APP General SubCA", "IOV APP SubCA"]
        assert original_hosts == ["rus-h5-gateway.gwmcloud.com", "rus-app-gateway-common.gwmcloud.com", "rus-app-gateway.gwmcloud.com"]
    finally:
        for transport in transports:
            await transport.aclose()
        await runner.cleanup()
    assert len(transports) == 2
    assert all(transport.transport.closed for transport in transports)
