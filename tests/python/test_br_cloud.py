"""Brazil region wiring: config flow, runtime, storage and guards, all offline.

BR is read-only: password login (no OTP), ``acquireVehicles`` + ``getLastStatus``
and nothing else. Certificates are throwaway files generated in a temp directory.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import voluptuous as vol

pytest.importorskip("pytest_asyncio")
pytest.importorskip("homeassistant")

from homeassistant.config_entries import ConfigEntry, ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from support.br import FakeTransport, envelope, fake_jwt, html, write_dummy_material

import custom_components.gwm_ora as integration
import custom_components.gwm_ora.cloud_auth as cloud_auth
import custom_components.gwm_ora.cloud_runtime as runtime
from custom_components.gwm_ora import config_flow
from custom_components.gwm_ora.cloud_auth import (
    GwmCloudAuthenticator,
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_runtime import consume_cloud_bootstrap, stage_cloud_bootstrap
from custom_components.gwm_ora.cloud_storage import _decode_auth_state, _encode_auth_state
from custom_components.gwm_ora.const import (
    BR_PLATFORMS,
    CONF_ACCOUNT,
    CONF_CONNECTION_TYPE,
    CONF_COUNTRY,
    CONF_ENABLE_CHARGING_CONTROL,
    CONF_ENABLE_REMOTE_COMMANDS,
    CONF_LOG_LEVEL,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL_SECONDS,
    CONF_REGION,
    CONF_SECURITY_PIN,
    CONFIGURABLE_CLOUD_REGIONS,
    CONNECTION_TYPE_CLOUD,
    DOMAIN,
    PLATFORMS,
    REGION_BR,
    platforms_for_region,
)
from custom_components.gwm_ora.diagnostics import TO_REDACT
from custom_components.gwm_ora.errors import GwmCommandForbidden
from custom_components.gwm_ora.gwm_client import (
    GwmAuthenticationError,
    GwmConfigurationError,
    GwmRoutePolicyError,
    VehicleIdentifier,
    br_flow,
    br_installed,
)
from custom_components.gwm_ora.gwm_client._auth_diagnostics import begin_request
from custom_components.gwm_ora.gwm_client._diagnostics import _DISCOVERY_GATEWAYS
from custom_components.gwm_ora.gwm_client.br_auth_client import BrTokens
from custom_components.gwm_ora.gwm_client.br_flow import BrAuthenticated
from custom_components.gwm_ora.gwm_client.br_identity import BrCredentials
from custom_components.gwm_ora.gwm_client.br_material import create_br_ssl_context, load_br_material
from custom_components.gwm_ora.gwm_client.br_request import prepare_br_request
from custom_components.gwm_ora.gwm_client.br_state import BrAccountCredentials, BrAuthState
from custom_components.gwm_ora.sensor import _sensor_descriptions_for_vehicle

_REAL_REGISTER_SERVICES = integration._async_register_services
DEVICE = "0123456789abcdef0123456789abcdef"
ACCOUNT = "someone@example.invalid"
PASSWORD = "Synthetic-Password-1"
NOW_FAR = 4_000_000_000
VIN = "SYNTHETICVIN000001"
VEHICLES = [
    {
        "vin": VIN,
        "modelName": "SYNTHETIC EV",
        "appShowSeriesName": "SYNTHETIC",
        "powerType": "EV",
        "belongPlatform": "beantech",
        "agreementVersion": "T5",
        "hasScyPwd": True,
    }
]
STATUS = {
    "latitude": "-1.25",
    "longitude": "2.5",
    "items": [{"code": "2013021", "value": "80"}, {"code": "2011501", "value": "310"}],
}


def _login(exp: int = NOW_FAR) -> object:
    return envelope({"accessToken": fake_jwt(exp), "refreshToken": "synthetic-refresh"})


def _refresh(exp: int = NOW_FAR, refresh: str = "rotated-refresh") -> object:
    return envelope({"accessToken": fake_jwt(exp), "refreshToken": refresh})


def _component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake installed component whose bundled resources/br is absent (a damaged install)."""
    component = tmp_path / "config" / "custom_components" / "gwm_ora"
    (component / "gwm_client").mkdir(parents=True)
    monkeypatch.setattr(br_installed, "_SOURCE_DIRECTORY", component / "gwm_client")
    return component


def _context(tmp_path: Path) -> ssl.SSLContext:
    directory = tmp_path / "material"
    directory.mkdir(exist_ok=True)
    write_dummy_material(directory)
    return create_br_ssl_context(load_br_material(directory))


def _credentials(device_id: str = DEVICE) -> GwmCloudCredentials:
    return GwmCloudCredentials(REGION_BR, "BR", ACCOUNT, PASSWORD, device_id)


def _expired_state(credentials: GwmCloudCredentials) -> BrAuthState:
    state = BrAuthState.for_credentials(credentials.client_credentials())
    return replace(state, tokens=BrTokens(fake_jwt(1), "synthetic-refresh", 1.0))


class _ConfigEntries:
    def __init__(self, entry: ConfigEntry | None = None) -> None:
        self.entry = entry

    def async_get_known_entry(self, entry_id: str) -> ConfigEntry:
        """Return the stored entry, asserting one was provided."""
        assert self.entry is not None
        return self.entry

    def async_entry_for_domain_unique_id(self, domain: str, unique_id: str) -> ConfigEntry | None:
        return None


class _Hass:
    def __init__(self, entry: ConfigEntry | None = None) -> None:
        self.config_entries = _ConfigEntries(entry)
        self.data: dict[str, Any] = {}


class _Store:
    def __init__(self) -> None:
        self.saved: list[Any] = []
        self.cleared = 0
        self.loaded: Any = None

    async def async_load_auth_state(self, data: object) -> Any:
        return self.loaded

    async def async_save_auth_state(self, credentials: object, state: Any) -> None:
        self.saved.append(state)

    async def async_clear_auth_state(self, data: object) -> None:
        self.cleared += 1


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _Store:
    shared = _Store()
    monkeypatch.setattr(config_flow, "cloud_state_store", lambda hass, unique_id: shared)
    return shared


def _flow(monkeypatch: pytest.MonkeyPatch, authenticator: GwmCloudAuthenticator) -> config_flow.GwmConfigFlow:
    flow = config_flow.GwmConfigFlow()
    flow.hass = _Hass()  # type: ignore[assignment]
    flow.context = {}
    flow._cloud_authenticator = authenticator

    async def set_unique_id(unique_id: str) -> None:
        flow.context["unique_id"] = unique_id

    monkeypatch.setattr(flow, "async_set_unique_id", set_unique_id)
    monkeypatch.setattr(flow, "_abort_if_unique_id_configured", lambda **kwargs: None)
    return flow


def _authenticator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *responses: object) -> tuple[GwmCloudAuthenticator, FakeTransport]:
    transport = FakeTransport(*responses)  # type: ignore[arg-type]
    context = _context(tmp_path)
    monkeypatch.setattr(cloud_auth.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    return GwmCloudAuthenticator(br_context_loader=lambda: context), transport


# ---------------------------------------------------------------- config flow


def test_br_region_is_offered_with_a_br_only_country_selector() -> None:
    """Check that the BR region is offered with a country selector limited to BR."""
    assert REGION_BR in CONFIGURABLE_CLOUD_REGIONS
    assert {"value": REGION_BR, "label": "Brazil"} in config_flow._REGION_OPTIONS
    schema = config_flow._account_schema(REGION_BR)
    keys = {marker.schema: marker for marker in schema.schema}
    assert set(keys) == {CONF_COUNTRY, CONF_ACCOUNT, CONF_PASSWORD}
    assert schema({CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})[CONF_COUNTRY] == "BR"
    with pytest.raises(vol.Invalid):
        schema({CONF_COUNTRY: "DE", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})


@pytest.mark.asyncio
async def test_br_setup_signs_in_without_otp_and_creates_read_only_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
    """Check that BR setup signs in without an OTP and creates a read-only entry."""
    authenticator, transport = _authenticator(monkeypatch, tmp_path, _login(), envelope(VEHICLES))
    flow = _flow(monkeypatch, authenticator)

    form = await flow.async_step_user({CONF_REGION: "br"})
    assert form["step_id"] == "account"
    result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})

    assert result["type"] is FlowResultType.CREATE_ENTRY, result.get("errors")
    assert result["title"] == "GWM Brazil"
    assert result["data"][CONF_REGION] == "br"
    assert result["data"][CONF_COUNTRY] == "BR"
    assert set(result["data"]).isdisjoint({"access_token", "refresh_token", "device_id", "tokens"})
    assert [request.operation for request in transport.requests] == ["login", "acquire_vehicles"]
    assert transport.closed is True
    assert len(store.saved) == 1 and store.saved[0].tokens is not None
    assert consume_cloud_bootstrap(flow.hass, flow.context["unique_id"]) is not None


@pytest.mark.asyncio
async def test_br_rejected_credentials_show_invalid_auth_and_store_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store, caplog: pytest.LogCaptureFixture
) -> None:
    """Check that rejected BR credentials show invalid auth and store nothing."""
    authenticator, _ = _authenticator(monkeypatch, tmp_path, envelope(None, code="308001", description="bad"))
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})

    result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    assert store.saved == []
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text


@pytest.mark.asyncio
async def test_br_missing_bundled_files_give_a_clear_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store, caplog: pytest.LogCaptureFixture
) -> None:
    """Check that a missing certificate folder gives a clear form error."""
    component = _component(tmp_path, monkeypatch)
    assert not (component / "resources" / "br").exists()
    flow = _flow(monkeypatch, GwmCloudAuthenticator(br_context_loader=br_installed.load_installed_br_context))
    await flow.async_step_user({CONF_REGION: "br"})

    with caplog.at_level("ERROR"):
        result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})

    assert result["errors"] == {"base": "br_material_missing"}
    assert "reinstall" in caplog.text
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text
    en = json.loads(Path(config_flow.__file__).parent.joinpath("translations", "en.json").read_text())
    assert "Reinstall" in en["config"]["error"]["br_material_missing"]
    assert "resources/br" not in json.dumps(en)


@pytest.mark.asyncio
async def test_br_unusable_bundled_files_and_gateway_rejection_have_their_own_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
    """Check that unusable certificate files and gateway rejection map to distinct errors."""
    component = _component(tmp_path, monkeypatch)
    directory = component / "resources" / "br"
    directory.mkdir(parents=True)
    write_dummy_material(directory, key_mismatch=True)
    flow = _flow(monkeypatch, GwmCloudAuthenticator(br_context_loader=br_installed.load_installed_br_context))
    await flow.async_step_user({CONF_REGION: "br"})
    result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert result["errors"] == {"base": "br_material_invalid"}

    authenticator, _ = _authenticator(monkeypatch, tmp_path, html(400, "No required SSL certificate was sent"))
    tls_flow = _flow(monkeypatch, authenticator)
    await tls_flow.async_step_user({CONF_REGION: "br"})
    tls = await tls_flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert tls["errors"] == {"base": "br_tls_rejected"}


@pytest.mark.asyncio
async def test_br_country_other_than_br_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store) -> None:
    """Check that a country other than BR is rejected for the BR region."""
    authenticator, _ = _authenticator(monkeypatch, tmp_path)
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    result = await flow.async_step_account({CONF_COUNTRY: "DE", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert result["errors"] == {"base": "invalid_account"}


@pytest.mark.asyncio
async def test_br_reauth_asks_only_for_the_password_and_drops_stale_command_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
    """Check that BR reauth asks only for the password and drops stale command options."""
    credentials = _credentials()
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="br-entry",
        minor_version=1,
        options={
            CONF_POLL_INTERVAL_SECONDS: 90,
            CONF_ENABLE_REMOTE_COMMANDS: True,
            CONF_ENABLE_CHARGING_CONTROL: True,
            CONF_SECURITY_PIN: "1234",
        },
        source="user",
        subentries_data=None,
        title="GWM Brazil",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )
    authenticator, _ = _authenticator(monkeypatch, tmp_path, _login(), envelope(VEHICLES))
    flow = config_flow.GwmConfigFlow()
    flow.hass = _Hass(entry)  # type: ignore[assignment]
    flow.context = {"source": "reauth", "entry_id": entry.entry_id}
    flow._cloud_authenticator = authenticator
    updates: list[dict[str, Any]] = []

    def update_and_abort(updated: ConfigEntry, **kwargs: Any) -> ConfigFlowResult:
        updates.append(kwargs)
        return flow.async_abort(reason="reauth_successful")

    monkeypatch.setattr(flow, "async_update_reload_and_abort", update_and_abort)
    form = await flow.async_step_reauth(dict(entry.data))
    assert set(form["data_schema"].schema) == {CONF_PASSWORD}
    result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "New-Password-2"})

    assert result["reason"] == "reauth_successful"
    assert updates[0]["data"][CONF_PASSWORD] == "New-Password-2"
    assert updates[0]["options"] == {CONF_POLL_INTERVAL_SECONDS: 90, CONF_ENABLE_CHARGING_CONTROL: True}
    assert consume_cloud_bootstrap(flow.hass, entry.unique_id) is not None


@pytest.mark.asyncio
async def test_br_options_expose_only_polling_charging_opt_in_and_log_level() -> None:
    """Check that BR options expose only polling, the charging opt-in and the log level."""
    entry = ConfigEntry(
        data={CONF_CONNECTION_TYPE: CONNECTION_TYPE_CLOUD, CONF_REGION: REGION_BR},
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="br-options",
        minor_version=1,
        options={},
        source="user",
        subentries_data=None,
        title="GWM Brazil",
        unique_id="cloud:br:synthetic",
        version=1,
    )
    flow = config_flow.GwmOptionsFlow()
    flow.hass = _Hass(entry)  # type: ignore[assignment]
    flow.handler = entry.entry_id
    form = await flow.async_step_init()
    assert set(form["data_schema"].schema) == {
        CONF_POLL_INTERVAL_SECONDS,
        CONF_ENABLE_CHARGING_CONTROL,
        CONF_LOG_LEVEL,
    }
    assert form["data_schema"]({CONF_POLL_INTERVAL_SECONDS: 60, CONF_LOG_LEVEL: "info"})[CONF_ENABLE_CHARGING_CONTROL] is False

    saved = await flow.async_step_init(
        {
            CONF_POLL_INTERVAL_SECONDS: 120,
            CONF_LOG_LEVEL: "info",
            CONF_ENABLE_REMOTE_COMMANDS: True,
            CONF_ENABLE_CHARGING_CONTROL: True,
            CONF_SECURITY_PIN: "1234",
        }
    )
    assert saved["type"] is FlowResultType.CREATE_ENTRY
    assert saved["data"] == {
        CONF_POLL_INTERVAL_SECONDS: 120,
        CONF_LOG_LEVEL: "info",
        CONF_ENABLE_CHARGING_CONTROL: True,
    }


# ------------------------------------------------------ installed material


def test_br_bundled_material_lives_in_the_component_and_reports_what_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that installed BR material lives in the component folder and reports missing files."""
    component = _component(tmp_path, monkeypatch)
    directory = component / "resources" / "br"
    assert br_installed.installed_br_directory() == directory
    with pytest.raises(br_installed.GwmBrMaterialMissingError):
        br_installed.load_installed_br_material()

    directory.mkdir(parents=True)
    (directory / "gwm_general.key").write_bytes(b"partial")
    assert br_installed.missing_br_files(directory) == ["gwm_general.cer", "gwm_root.cer"]
    with pytest.raises(br_installed.GwmBrMaterialMissingError):
        br_installed.load_installed_br_material()

    write_dummy_material(directory)
    assert br_installed.missing_br_files(directory) == []
    assert br_installed.load_installed_br_context().security_level == 0


def test_br_bundled_material_loads_even_in_a_git_tracked_config_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that there is no source-checkout guard: bundled files load wherever the component is installed."""
    config = tmp_path / "config"
    component = _component(tmp_path, monkeypatch)
    (config / ".git").mkdir()
    (config / "pyproject.toml").write_text("[project]\n")
    (config / "tests").mkdir()
    directory = component / "resources" / "br"
    directory.mkdir(parents=True)
    write_dummy_material(directory)
    assert br_installed.load_installed_br_material() is not None


# ------------------------------------------------------------- credentials


def test_br_credentials_binding_state_and_storage_round_trip() -> None:
    """Check that BR credentials, binding and auth state survive a storage round trip."""
    credentials = _credentials()
    regional = credentials.client_credentials()
    assert isinstance(regional, BrAccountCredentials)
    assert ACCOUNT not in repr(regional) and PASSWORD not in repr(regional) and DEVICE not in repr(regional)
    assert regional.to_br_credentials() == BrCredentials.from_password(ACCOUNT, PASSWORD, DEVICE)
    assert cloud_unique_id(credentials).startswith("cloud:br:")
    assert cloud_unique_id(credentials) != cloud_unique_id(GwmCloudCredentials(REGION_BR, "BR", "other@example.invalid", PASSWORD, DEVICE))

    state = replace(BrAuthState.for_credentials(regional), tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR)))
    assert state.matches(regional)
    assert not state.matches(BrAccountCredentials(ACCOUNT, PASSWORD, "f" * 32))
    encoded = _encode_auth_state(state)
    assert _decode_auth_state(REGION_BR, json.loads(json.dumps(encoded))) == state
    with pytest.raises(ValueError):
        _decode_auth_state(REGION_BR, {**encoded, "extra": 1})
    with pytest.raises(ValueError):
        GwmCloudCredentials(REGION_BR, "DE", ACCOUNT, PASSWORD, DEVICE)


@pytest.mark.asyncio
async def test_br_startup_restore_makes_no_request_and_never_logs_in_by_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that startup restore makes no request and never logs in by password."""
    authenticator, transport = _authenticator(monkeypatch, tmp_path)
    credentials = _credentials()
    regional = credentials.client_credentials()

    fresh = replace(
        BrAuthState.for_credentials(regional),
        tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR)),
    )
    restored = await authenticator.async_authenticate(credentials, state=fresh, allow_password_login=False)
    assert isinstance(restored, BrAuthenticated)
    assert transport.requests == []

    # An expired access token is recoverable: resuming makes no request (the first read refreshes it).
    resumed = await authenticator.async_authenticate(
        credentials, state=_expired_state(credentials), allow_password_login=False
    )
    assert isinstance(resumed, BrAuthenticated)
    assert transport.requests == []

    with pytest.raises(GwmAuthenticationError):
        await authenticator.async_authenticate(
            credentials, state=BrAuthState.for_credentials(regional), allow_password_login=False
        )
    with pytest.raises(GwmConfigurationError):
        await authenticator.async_authenticate(credentials, verification_code="123456")


# ---------------------------------------------------------------- runtime


def _bootstrap(tmp_path: Path, state_tokens: bool = True, expired: bool = False) -> tuple[GwmCloudCredentials, runtime.GwmCloudBootstrap]:
    """Build BR credentials and a bootstrap, optionally without tokens or with an expired session."""
    credentials = _credentials()
    state = BrAuthState.for_credentials(credentials.client_credentials())
    if state_tokens:
        state = _expired_state(credentials) if expired else replace(
            state, tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR))
        )
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, BrAuthenticated(state, _context(tmp_path)))
    return credentials, bootstrap


def test_br_bootstrap_requires_tokens_and_an_mtls_context(tmp_path: Path) -> None:
    """Check that a BR bootstrap requires saved tokens and an mTLS context."""
    credentials = _credentials()
    state = BrAuthState.for_credentials(credentials.client_credentials())
    with pytest.raises(GwmConfigurationError):
        runtime.GwmCloudBootstrap.from_authentication(credentials, BrAuthenticated(state, _context(tmp_path)))
    _, ok = _bootstrap(tmp_path)
    assert ok.session is None and ok.br_ssl_context is not None
    with pytest.raises(GwmConfigurationError):
        runtime.GwmCloudBootstrap(
            region=REGION_BR, account_binding=ok.account_binding, state=ok.state, session=None, br_ssl_context=None
        )


@pytest.mark.asyncio
async def test_br_cloud_client_reads_vehicles_and_status_only_and_is_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that the BR client reads only vehicles and status and refuses every command."""
    credentials, bootstrap = _bootstrap(tmp_path)
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS))
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials),
        cloud_unique_id(credentials),
        bootstrap,
        state_store=_Store(),
        # Every consent below except charging is ignored for Brazil.
        climate_commands_enabled=True,
        apac_remote_enabled=True,
        apac_charging_enabled=True,
        lock_window_commands_enabled=True,
        charging_control_enabled=True,
    )

    data = await cloud.async_get_vehicle_data()

    assert [request.operation for request in transport.requests] == ["acquire_vehicles", "get_last_status"]
    assert data["region"] == "br"
    assert data["remote_commands_enabled"] is False
    assert data["charging_control_enabled"] is True
    vehicle = data["vehicles"][0]
    assert vehicle["values"]["soc"] == 80.0
    assert vehicle["location"]["latitude"] == pytest.approx(-1.25)
    capabilities = vehicle["capabilities"]
    assert {key for key, value in capabilities.items() if value is True} == {"charging_control"}, capabilities

    identifier = VehicleIdentifier(VIN)
    for call in (
        cloud.async_get_charging_plan(identifier),
        cloud.async_send_apac_control(identifier, "lock", security_password_hash="x"),
        cloud.async_get_climate_context(identifier, include_status=False),
        cloud.async_get_remote_command_results(identifier, "1"),
    ):
        with pytest.raises(GwmRoutePolicyError):
            await call
    assert len(transport.requests) == 2  # nothing else reached the transport
    await cloud.aclose()
    assert transport.closed is True


async def _br_cloud(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, transport: FakeTransport, *, expired: bool):
    credentials, bootstrap = _bootstrap(tmp_path, expired=expired)
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    store = _Store()
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials), cloud_unique_id(credentials), bootstrap, state_store=store
    )
    return cloud, store


@pytest.mark.asyncio
async def test_br_expired_token_is_refreshed_silently_and_the_rotated_tokens_are_saved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that an expired token is refreshed silently and the rotated tokens are saved."""
    transport = FakeTransport(_refresh(), envelope(VEHICLES), envelope(STATUS))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)

    data = await cloud.async_get_vehicle_data()

    assert [r.operation for r in transport.requests] == ["refresh_token", "acquire_vehicles", "get_last_status"]
    assert "login" not in [r.operation for r in transport.requests]
    assert transport.requests[0].ssl_context.security_level == 0
    assert data["vehicles"][0]["values"]["soc"] == 80.0
    assert store.cleared == 0
    assert store.saved and store.saved[-1].tokens.refresh_token == "rotated-refresh"
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_rotated_tokens_are_saved_even_when_the_read_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that rotated tokens are saved even when the read is cancelled."""
    transport = FakeTransport()
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=False)
    session = cloud._client._client.session

    async def rotate_then_get_cancelled() -> None:
        # The silent refresh swaps the tokens, then Home Assistant cancels the coroutine.
        session._tokens = BrTokens(fake_jwt(NOW_FAR), "rotated-refresh", float(NOW_FAR))
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await cloud._async_with_br_session(rotate_then_get_cancelled)

    assert store.cleared == 0
    assert store.saved and store.saved[-1].tokens.refresh_token == "rotated-refresh"
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_refused_refresh_asks_for_reauthentication_without_a_password_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that a refused refresh asks for reauthentication without a password login."""
    transport = FakeTransport(envelope(None, code="999999"), _login())
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)

    with pytest.raises(GwmAuthenticationError):
        await cloud.async_get_vehicle_data()

    assert [r.operation for r in transport.requests] == ["refresh_token"]  # no login request
    assert store.cleared == 1 and cloud.reusable_bootstrap is None
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_rejected_token_is_refreshed_and_the_read_repeated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that a rejected token is refreshed and the read repeated once."""
    transport = FakeTransport(html(401, "unauthorized"), _refresh(), envelope(VEHICLES), envelope(STATUS))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=False)

    await cloud.async_get_vehicle_data()

    assert [r.operation for r in transport.requests] == [
        "acquire_vehicles", "refresh_token", "acquire_vehicles", "get_last_status",
    ]
    assert store.cleared == 0
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_rejected_token_with_refused_refresh_asks_for_reauthentication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that a rejected token with a refused refresh asks for reauthentication."""
    transport = FakeTransport(html(401, "unauthorized"), html(401, "unauthorized"), _login())
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=False)

    with pytest.raises(GwmAuthenticationError):
        await cloud.async_get_vehicle_data()

    assert [r.operation for r in transport.requests] == ["acquire_vehicles", "refresh_token"]
    assert store.cleared == 1
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_startup_with_expired_saved_session_resumes_and_leaves_the_refresh_to_the_first_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that startup with an expired saved session resumes and leaves the refresh to the first read."""
    credentials = _credentials()
    state = _expired_state(credentials)
    transport = FakeTransport(_login(), envelope(VEHICLES))
    context = _context(tmp_path)
    monkeypatch.setattr(cloud_auth.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    monkeypatch.setattr(integration, "load_installed_br_context", lambda: context)

    class Store:
        cleared = 0

        async def async_load_auth_state(self, data: object) -> BrAuthState:
            return state

        async def async_save_auth_state(self, *args: object) -> None:
            return None  # the resumed state is saved as-is (still the expired tokens)

        async def async_clear_auth_state(self, data: object) -> None:
            Store.cleared += 1

    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=cloud_unique_id(credentials), version=1,
    )
    bootstrap = await integration._async_load_cloud_bootstrap_once(HomeAssistant(str(tmp_path)), entry, Store())  # type: ignore[arg-type]
    assert bootstrap is not None
    assert transport.requests == [] and Store.cleared == 0


@pytest.mark.asyncio
async def test_br_login_uses_a_clean_tls_context_and_reads_use_the_vehicle_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that login uses a clean TLS context and reads use the vehicle context."""
    authenticator, transport = _authenticator(monkeypatch, tmp_path, _login(), envelope(VEHICLES))
    credentials = _credentials()
    await authenticator.async_authenticate(credentials, allow_password_login=True)

    login, read = transport.requests
    assert login.operation == "login" and read.operation == "acquire_vehicles"
    assert login.ssl_context.security_level > 0  # not downgraded
    assert read.ssl_context.security_level == 0  # vehicle gateway identity only
    assert login.ssl_context is not read.ssl_context


@pytest.mark.asyncio
async def test_br_setup_forwards_only_read_only_platforms_and_never_enables_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that BR setup forwards only read-only platforms and never enables commands."""
    forwarded: list[object] = []
    unloaded: list[object] = []
    credentials, bootstrap = _bootstrap(tmp_path)
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS))

    class Coordinator:
        def __init__(self, hass: object, api: Any, **kwargs: Any) -> None:
            self.api = api
            self.data: Any = None

        async def async_config_entry_first_refresh(self) -> None:
            self.data = await self.api.async_get_vehicles()

        async def async_cancel_command_tasks(self) -> None:
            return None

    class Entries:
        async def async_forward_entry_setups(self, entry: object, platforms: list[object]) -> None:
            forwarded.extend(platforms)

        async def async_unload_platforms(self, entry: object, platforms: list[object]) -> bool:
            unloaded.extend(platforms)
            return True

    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = Entries()  # type: ignore[assignment]
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="br-entry",
        minor_version=1,
        options={CONF_ENABLE_REMOTE_COMMANDS: True, CONF_SECURITY_PIN: "1234"},
        source="user",
        subentries_data=None,
        title="GWM Brazil",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )
    stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)
    saved: list[object] = []

    async def save(self: object, credentials: object, state: object) -> None:
        saved.append(state)

    monkeypatch.setattr(integration.GwmCloudStateStore, "async_save_auth_state", save)
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    monkeypatch.setattr(integration, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(integration, "_async_register_services", lambda hass: None)

    async def restore(self: object, data: object) -> tuple[()]:
        return ()

    monkeypatch.setattr(integration.GwmCommandApi, "async_restore", restore)

    assert await integration.async_setup_entry(hass, entry)
    assert forwarded == BR_PLATFORMS == platforms_for_region(REGION_BR)
    assert {platform.value for platform in forwarded} == {"sensor", "binary_sensor", "device_tracker"}
    assert entry.runtime_data.coordinator.data["remote_commands_enabled"] is False
    assert entry.runtime_data.coordinator.data["vehicles"][0]["values"]["soc"] == 80.0
    with pytest.raises(GwmCommandForbidden):
        await entry.runtime_data.api.async_lock(VIN, "unlock")
    with pytest.raises(GwmCommandForbidden):
        await entry.runtime_data.api.async_set_climate(VIN, mode="auto")
    with pytest.raises(GwmCommandForbidden):
        await entry.runtime_data.api.async_set_charging_plan(VIN, enable=True)
    assert [request.operation for request in transport.requests] == ["acquire_vehicles", "get_last_status"]
    assert entry.runtime_data.platforms == BR_PLATFORMS
    # The config changed after setup (reconfigure or opt-in toggle): unload must still release
    # exactly what was forwarded, not what the new config would forward.
    monkeypatch.setattr(integration, "platforms_for_region", lambda region: PLATFORMS)
    assert await integration.async_unload_entry(hass, entry)
    assert unloaded == BR_PLATFORMS and transport.closed is True


@pytest.mark.asyncio
async def test_br_startup_without_certificate_files_retries_instead_of_asking_for_reauth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Check that startup without certificate files retries instead of asking for reauth."""
    from homeassistant.exceptions import ConfigEntryNotReady

    _component(tmp_path, monkeypatch)
    credentials = _credentials()
    state = _expired_state(credentials)

    class Store:
        async def async_load_auth_state(self, data: object) -> BrAuthState:
            return state

        async def async_clear_auth_state(self, data: object) -> None:
            raise AssertionError("missing files must not discard the session")

    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="br-entry",
        minor_version=1,
        options={},
        source="user",
        subentries_data=None,
        title="GWM Brazil",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )
    hass = HomeAssistant(str(tmp_path))
    with caplog.at_level("ERROR"), pytest.raises(ConfigEntryNotReady) as raised:
        await integration._async_load_cloud_bootstrap_once(hass, entry, Store())  # type: ignore[arg-type]
    assert "reinstall" in str(raised.value)
    assert "reinstall" in caplog.text
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text


# ------------------------------------------------------ entities, diagnostics


def test_br_sensor_set_has_no_command_status() -> None:
    """Check that the BR sensor set has no command status sensor."""
    br_keys = {d.key for d in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "br")}
    eu_keys = {d.key for d in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "eu")}
    assert "command_status" in eu_keys and "command_status" not in br_keys
    assert {"soc", "range_km"} <= br_keys


def test_br_diagnostics_know_the_hosts_and_redact_private_values(tmp_path: Path) -> None:
    """Check that diagnostics know the BR hosts and redact private values."""
    assert _DISCOVERY_GATEWAYS["br-app-gateway.gwmcloud.com"] == ("br", "br_static_mtls")
    assert {"password_md5", "access_token", "refresh_token", "device_id", "vin", "latitude", "longitude", "account"} <= TO_REDACT

    request = prepare_br_request(
        operation="login",
        ssl_context=ssl.create_default_context(),
        credentials=BrCredentials.from_password(ACCOUNT, PASSWORD, DEVICE),
    )
    exchange = begin_request(request, connect_timeout=10.0, read_timeout=20.0, remaining=30.0)
    assert exchange is not None
    assert exchange.fields["region"] == "br" and exchange.fields["signing"] == "none"
    flattened = json.dumps(exchange.fields, default=str)
    assert ACCOUNT not in flattened and DEVICE not in flattened and PASSWORD not in flattened
    assert br_flow.BrAuthenticated is BrAuthenticated


# ------------------------------------------------- opt-in charging schedule


def _plan_body(request: Any) -> dict[str, Any]:
    return json.loads(request.body)


def test_br_set_charging_plan_request_has_the_documented_url_and_body(tmp_path: Path) -> None:
    """Check that the set charging plan request has the documented URL and body."""
    from custom_components.gwm_ora.gwm_client import ChargingPlanCommand

    context = _context(tmp_path)
    identifier = VehicleIdentifier(VIN)
    start, end = 1_800_000_000_000, 1_800_000_000_000 + 8 * 3600 * 1000
    on = prepare_br_request(
        operation="set_charging_plan",
        ssl_context=context,
        access_token="tok-a",
        refresh_token="tok-r",
        plan=ChargingPlanCommand(identifier, enable=True, start_time_ms=start, end_time_ms=end),
    )
    assert on.method == "POST"
    assert on.url == f"https://br-app-gateway.gwmcloud.com/app-api/api/v1.0/vehicleCharge/setChargingPlan?vin={VIN}"
    assert on.headers["accessToken"] == "tok-a" and on.headers["content-type"] == "application/json"
    body = _plan_body(on)
    assert body["enable"] is True and body["startTime"] == start and body["endTime"] == end
    assert body["planType"] == "1" and body["vin"] == VIN
    assert body["seqNo"].endswith("1234") and len(body["seqNo"]) == 36 and "-" not in body["seqNo"]
    assert set(body) == {"enable", "startTime", "endTime", "seqNo", "planType", "vin"}  # no PIN field

    off = prepare_br_request(
        operation="set_charging_plan",
        ssl_context=context,
        access_token="tok-a",
        refresh_token="tok-r",
        plan=ChargingPlanCommand(identifier, enable=False),
    )
    assert _plan_body(off) | {"seqNo": ""} == {
        "enable": False, "startTime": "", "endTime": "", "seqNo": "", "planType": "1", "vin": VIN,
    }
    # The window rule lives in the shared command, not in the BR serializer.
    with pytest.raises(ValueError):
        ChargingPlanCommand(identifier, enable=True, start_time_ms=start, end_time_ms=start + 60_000)
    for bad in ({"plan": None}, {"plan": "x"}):
        with pytest.raises(ValueError, match="^br_request_invalid$"):
            prepare_br_request(operation="set_charging_plan", ssl_context=context, access_token="tok-a", **bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^br_request_invalid$"):  # a plan only belongs to this route
        prepare_br_request(
            operation="get_last_status", ssl_context=context, access_token="tok-a",
            vehicle_id=VIN, plan=ChargingPlanCommand(identifier, enable=False),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        envelope(None, code="9999", description="busy"),
        envelope(None, code="REMOTE250502", description="system busy"),
        envelope({"running": True}),
    ],
)
async def test_br_charging_busy_is_a_friendly_error_and_not_retried(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: object
) -> None:
    """Check that a charging busy reply becomes a friendly error and is not retried."""
    from custom_components.gwm_ora.gwm_client.br_request import GwmBrBusyError

    credentials, bootstrap = _bootstrap(tmp_path)
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS), response)  # type: ignore[arg-type]
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials), cloud_unique_id(credentials), bootstrap,
        state_store=_Store(), charging_control_enabled=True,
    )
    await cloud.async_get_vehicle_data()
    from custom_components.gwm_ora.gwm_client import ChargingPlanCommand

    with pytest.raises(GwmBrBusyError):
        await cloud.async_set_charging_plan(ChargingPlanCommand(VehicleIdentifier(VIN), enable=False))
    assert len(transport.requests) == 3  # no retry loop
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_guard_allows_only_the_charging_plan_and_only_with_opt_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that the BR guard allows only the charging plan and only with the opt-in."""
    from custom_components.gwm_ora.gwm_client import ChargingPlanCommand

    identifier = VehicleIdentifier(VIN)
    now = 1_800_000_000_000
    plan = ChargingPlanCommand(identifier, enable=True, start_time_ms=now, end_time_ms=now + 8 * 3600 * 1000)

    async def build(enabled: bool) -> tuple[runtime.GwmCloudClient, FakeTransport]:
        credentials, bootstrap = _bootstrap(tmp_path)
        transport = FakeTransport(envelope(VEHICLES), envelope(STATUS), envelope({}), envelope({}))
        monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
        cloud = runtime.GwmCloudClient.from_entry_data(
            cloud_entry_data(credentials), cloud_unique_id(credentials), bootstrap,
            state_store=_Store(), charging_control_enabled=enabled,
            climate_commands_enabled=True, lock_window_commands_enabled=True,
        )
        await cloud.async_get_vehicle_data()
        return cloud, transport

    cloud, transport = await build(False)
    with pytest.raises(GwmRoutePolicyError):
        await cloud.async_set_charging_plan(plan)
    assert len(transport.requests) == 2
    await cloud.aclose()

    cloud, transport = await build(True)
    await cloud.async_set_charging_plan(plan)
    await cloud.async_set_charging_plan(ChargingPlanCommand(identifier, enable=False))
    assert [r.operation for r in transport.requests[2:]] == ["set_charging_plan", "set_charging_plan"]
    assert _plan_body(transport.requests[2])["startTime"] == now
    assert _plan_body(transport.requests[3])["startTime"] == ""
    # Everything else stays forbidden, with the opt-in on.
    for call in (
        cloud.async_get_charging_plan(identifier),
        cloud.async_send_apac_control(identifier, "lock", security_password_hash="x"),
        cloud.async_get_climate_context(identifier, include_status=False),
        cloud.async_get_remote_command_results(identifier, "1"),
    ):
        with pytest.raises(GwmRoutePolicyError):
            await call
    from custom_components.gwm_ora.gwm_client import DoorLockCommand

    with pytest.raises(GwmRoutePolicyError):
        await cloud.async_send_lock_command(DoorLockCommand(identifier, lock=True), security_password_hash="x")
    # An undiscovered vehicle is refused before any request.
    with pytest.raises(GwmRoutePolicyError):
        await cloud.async_set_charging_plan(
            ChargingPlanCommand(VehicleIdentifier("OTHERVIN0000000001"), enable=False)
        )
    assert len(transport.requests) == 4
    await cloud.aclose()


async def _charging_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, charging: bool
) -> tuple[Any, Any, FakeTransport, list[Any]]:
    """Set up a BR entry with fake coordinator and transport, with the charging opt-in on or off."""
    forwarded: list[Any] = []
    credentials, bootstrap = _bootstrap(tmp_path)
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS), envelope({}), envelope({}), envelope({}))

    class Coordinator:
        def __init__(self, hass: object, api: Any, **kwargs: Any) -> None:
            self.api = api
            self.data: Any = None
            self.active: dict[str, bool] = {}
            self.region = "br"
            self.last_update_success = True

        async def async_config_entry_first_refresh(self) -> None:
            self.data = await self.api.async_get_vehicles()

        async def async_cancel_command_tasks(self) -> None:
            return None

        @property
        def vehicles(self) -> list[Any]:
            return list(self.data["vehicles"])

        def vehicle(self, vin: str) -> Any:
            """Return the vehicle with the given VIN, or None."""
            return next((v for v in self.vehicles if v["vin"] == vin), None)

        def resolve_vehicle(self, identifier: str) -> Any:
            return self.vehicle(identifier)

        def charging_plan_active(self, vin: str) -> bool | None:
            return self.active.get(vin)

        def set_charging_plan_active(self, vin: str, active: bool) -> None:
            self.active[vin] = active

        def async_add_listener(self, *args: Any) -> Any:
            return lambda: None

    class Entries:
        async def async_forward_entry_setups(self, entry: object, platforms: list[object]) -> None:
            forwarded.extend(platforms)

        def async_loaded_entries(self, domain: str) -> list[Any]:
            return [entry]

    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = Entries()  # type: ignore[assignment]
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1,
        options={CONF_ENABLE_CHARGING_CONTROL: True} if charging else {},
        source="user", subentries_data=None, title="GWM Brazil",
        unique_id=cloud_unique_id(credentials), version=1,
    )
    stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)

    async def save(self: object, credentials: object, state: object) -> None:
        return None

    async def restore(self: object, data: object) -> tuple[()]:
        return ()

    monkeypatch.setattr(integration.GwmCloudStateStore, "async_save_auth_state", save)
    monkeypatch.setattr(integration.GwmCommandApi, "async_restore", restore)
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    monkeypatch.setattr(integration, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(integration, "_async_register_services", lambda hass: None)
    assert await integration.async_setup_entry(hass, entry)
    return hass, entry, transport, forwarded


def test_br_platforms_add_switch_only_with_charging_opt_in() -> None:
    """Check that the switch platform is added only with the charging opt-in."""
    assert "switch" not in {p.value for p in platforms_for_region(REGION_BR)}
    assert {p.value for p in platforms_for_region(REGION_BR, charging_control=True)} == {
        "sensor", "binary_sensor", "device_tracker", "switch",
    }
    assert len(platforms_for_region("eu")) == len(platforms_for_region("eu", charging_control=True))


@pytest.mark.asyncio
async def test_br_switch_exists_only_with_opt_in_and_is_the_only_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that the schedule switch exists only with the opt-in and is the only switch."""
    from custom_components.gwm_ora import switch as switch_platform

    for charging in (False, True):
        hass, entry, transport, forwarded = await _charging_setup(tmp_path, monkeypatch, charging=charging)
        assert ("switch" in {p.value for p in forwarded}) is charging
        if charging:
            added: list[Any] = []
            entry.async_on_unload = lambda callback: None
            await switch_platform.async_setup_entry(hass, entry, added.extend)
            assert [type(e).__name__ for e in added] == ["GwmChargingScheduleSwitch"]
            assert added[0].available is True and added[0].is_on is None


@pytest.mark.asyncio
async def test_br_switch_sets_an_eight_hour_window_and_off_clears_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that turning the switch on sets an eight hour window and off clears it."""
    from custom_components.gwm_ora import switch as switch_platform

    hass, entry, transport, _ = await _charging_setup(tmp_path, monkeypatch, charging=True)
    monkeypatch.setattr(switch_platform.time, "time", lambda: 1_800_000_000.0)
    entity = switch_platform.GwmChargingScheduleSwitch(
        entry.runtime_data.api, entry.runtime_data.coordinator, VIN
    )

    await entity.async_turn_on()
    on = _plan_body(transport.requests[2])
    assert on["enable"] is True and on["startTime"] == 1_800_000_000_000
    assert on["endTime"] - on["startTime"] == 8 * 3600 * 1000
    assert entity.is_on is True

    await entity.async_turn_off()
    off = _plan_body(transport.requests[3])
    assert off["enable"] is False and off["startTime"] == "" and off["endTime"] == ""
    assert entity.is_on is False
    assert [r.operation for r in transport.requests] == [
        "acquire_vehicles", "get_last_status", "set_charging_plan", "set_charging_plan",
    ]


@pytest.mark.asyncio
async def test_br_services_route_set_and_clear_to_set_charging_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Check that the set and clear services both route to set_charging_plan."""
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from homeassistant.exceptions import ServiceValidationError

    hass, entry, transport, _ = await _charging_setup(tmp_path, monkeypatch, charging=True)
    handlers: dict[str, Any] = {}
    fake = SimpleNamespace(
        services=SimpleNamespace(
            has_service=lambda domain, name: False,
            async_register=lambda domain, name, handler, schema=None: handlers.__setitem__(name, handler),
        ),
        config_entries=hass.config_entries,
    )
    _REAL_REGISTER_SERVICES(fake)  # the helper stubs the module attribute; use the real one
    start = datetime(2027, 1, 15, 21, 0, tzinfo=UTC)
    end = datetime(2027, 1, 16, 5, 30, tzinfo=UTC)
    await handlers["set_charging_plan"](SimpleNamespace(data={"vin": VIN, "start_time": start, "end_time": end}))
    body = _plan_body(transport.requests[2])
    assert body["enable"] is True
    assert body["startTime"] == int(start.timestamp() * 1000) and body["endTime"] == int(end.timestamp() * 1000)

    with pytest.raises(ServiceValidationError):
        await handlers["set_charging_plan"](
            SimpleNamespace(data={"vin": VIN, "start_time": start, "end_time": start.replace(minute=4)})
        )
    assert len(transport.requests) == 3  # the short window never reached the transport

    await handlers["clear_charging_plan"](SimpleNamespace(data={"vin": VIN}))
    assert _plan_body(transport.requests[3])["enable"] is False


# ------------------------------------------- restored assumed state of the switch


class _PlanCoordinator:
    last_update_success = True

    def __init__(self, region: str) -> None:
        self.region = region
        self.active: dict[str, bool] = {}

    def vehicle(self, vin: str) -> dict[str, Any]:
        """Return the vehicle with the given VIN, or None."""
        return {"vin": vin, "capabilities": {"charging_control": True}}

    def charging_plan_active(self, vin: str) -> bool | None:
        return self.active.get(vin)

    def set_charging_plan_active(self, vin: str, active: bool) -> None:
        self.active[vin] = active


class _PlanApi:
    def __init__(self, response: Any = None) -> None:
        self.reads = 0
        self.response = response

    async def async_get_charging_plan(self, vin: str) -> Any:
        """Count the read and return or raise the configured response."""
        self.reads += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


async def _added_switch(
    monkeypatch: pytest.MonkeyPatch, region: str, api: _PlanApi, restored: str | None
) -> tuple[Any, _PlanCoordinator]:
    """Add a schedule switch to a fake coordinator with an optional restored state."""
    from unittest.mock import AsyncMock

    from homeassistant.core import State
    from homeassistant.helpers.update_coordinator import CoordinatorEntity

    from custom_components.gwm_ora import switch as switch_platform

    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    monkeypatch.setattr(
        switch_platform.GwmChargingScheduleSwitch,
        "async_get_last_state",
        AsyncMock(return_value=None if restored is None else State("switch.x", restored)),
    )
    coordinator = _PlanCoordinator(region)
    entity = switch_platform.GwmChargingScheduleSwitch(api, coordinator, VIN)
    await entity.async_added_to_hass()
    return entity, coordinator


@pytest.mark.asyncio
@pytest.mark.parametrize(("restored", "expected"), [("on", True), ("off", False), ("unknown", None), ("unavailable", None), (None, None)])
async def test_br_switch_restores_the_last_state_without_reading_the_plan(
    monkeypatch: pytest.MonkeyPatch, restored: str | None, expected: bool | None
) -> None:
    """Check that the switch restores its last state without reading the plan."""
    api = _PlanApi()
    entity, _ = await _added_switch(monkeypatch, REGION_BR, api, restored)
    assert api.reads == 0  # the blocked read is never attempted (no error, no log)
    assert entity.is_on is expected
    assert entity.assumed_state is True


@pytest.mark.asyncio
async def test_readable_region_keeps_the_live_read_and_falls_back_to_the_restored_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that a readable region keeps the live read and falls back to the restored state."""
    from custom_components.gwm_ora.gwm_client import ChargingPlanInfo, ChargingPlanItem

    live = ChargingPlanInfo((ChargingPlanItem(1, "1", 1_800_000_000_000, 1_800_000_028_800),))
    api = _PlanApi(live.as_dict())
    entity, _ = await _added_switch(monkeypatch, "eu", api, "off")
    assert api.reads == 1 and entity.is_on is True  # live value wins over the restored one

    failing = _PlanApi(GwmRoutePolicyError(operation="get_charging_plan"))
    entity, _ = await _added_switch(monkeypatch, "eu", failing, "on")
    assert failing.reads == 1 and entity.is_on is True  # read failed: restored state is used


@pytest.mark.parametrize("code", [{"x": 1}, ["9999"], 9999, None])
def test_br_busy_check_ignores_a_non_string_code(code: object) -> None:
    """Check that the busy check ignores a non-string code."""
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
    from custom_components.gwm_ora.gwm_client.br_request import decode_br_envelope
    from custom_components.gwm_ora.gwm_client.errors import GwmApiError

    body = json.dumps({"code": code, "description": "x", "data": None}).encode()
    with pytest.raises(GwmApiError) as error:  # normal API error, never a TypeError
        decode_br_envelope(_TransportResponse(200, {}, body), operation="set_charging_plan")
    assert type(error.value).__name__ != "GwmBrBusyError"
