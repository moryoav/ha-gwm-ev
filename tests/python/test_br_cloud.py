"""Brazil region wiring: config flow, runtime, storage and guards, all offline.

BR is read-only: password login (no OTP), ``acquireVehicles`` + ``getLastStatus``
and nothing else. Certificates are throwaway files generated in a temp directory.
"""

from __future__ import annotations

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
    br_material,
)
from custom_components.gwm_ora.gwm_client._auth_diagnostics import begin_request
from custom_components.gwm_ora.gwm_client._diagnostics import _DISCOVERY_GATEWAYS
from custom_components.gwm_ora.gwm_client.br_auth_client import BrTokens
from custom_components.gwm_ora.gwm_client.br_flow import BrAuthenticated
from custom_components.gwm_ora.gwm_client.br_identity import BrCredentials
from custom_components.gwm_ora.gwm_client.br_material import create_br_ssl_context, load_br_material
from custom_components.gwm_ora.gwm_client.br_request import GwmBrCredentialError, prepare_br_request
from custom_components.gwm_ora.gwm_client.br_state import BrAccountCredentials, BrAuthState
from custom_components.gwm_ora.sensor import _sensor_descriptions_for_vehicle

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


def _component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake installed component whose resources/br is empty (nothing placed yet)."""
    component = tmp_path / "config" / "custom_components" / "gwm_ora"
    (component / "gwm_client").mkdir(parents=True)
    monkeypatch.setattr(br_installed, "_SOURCE_DIRECTORY", component / "gwm_client")
    monkeypatch.setattr(br_material, "_SOURCE_DIRECTORY", component / "gwm_client")
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
    authenticator, _ = _authenticator(monkeypatch, tmp_path, envelope(None, code="308001", description="bad"))
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})

    result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    assert store.saved == []
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text


@pytest.mark.asyncio
async def test_br_missing_certificate_folder_gives_a_clear_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store, caplog: pytest.LogCaptureFixture
) -> None:
    component = _component(tmp_path, monkeypatch)
    assert not (component / "resources" / "br").exists()
    flow = _flow(monkeypatch, GwmCloudAuthenticator(br_context_loader=br_installed.load_installed_br_context))
    await flow.async_step_user({CONF_REGION: "br"})

    with caplog.at_level("ERROR"):
        result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})

    assert result["errors"] == {"base": "br_material_missing"}
    assert "resources" in caplog.text and "br" in caplog.text
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text
    en = json.loads(Path(config_flow.__file__).parent.joinpath("translations", "en.json").read_text())
    assert "custom_components/gwm_ora/resources/br/" in en["config"]["error"]["br_material_missing"]


@pytest.mark.asyncio
async def test_br_unusable_certificate_files_and_gateway_rejection_have_their_own_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
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
    authenticator, _ = _authenticator(monkeypatch, tmp_path)
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    result = await flow.async_step_account({CONF_COUNTRY: "DE", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert result["errors"] == {"base": "invalid_account"}


@pytest.mark.asyncio
async def test_br_reauth_asks_only_for_the_password_and_drops_stale_command_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
    credentials = _credentials()
    entry = ConfigEntry(
        data=cloud_entry_data(credentials),
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="br-entry",
        minor_version=1,
        options={CONF_POLL_INTERVAL_SECONDS: 90, CONF_ENABLE_REMOTE_COMMANDS: True, CONF_SECURITY_PIN: "1234"},
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
    assert updates[0]["options"] == {CONF_POLL_INTERVAL_SECONDS: 90}
    assert consume_cloud_bootstrap(flow.hass, entry.unique_id) is not None


@pytest.mark.asyncio
async def test_br_options_expose_only_polling_and_log_level() -> None:
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
    assert set(form["data_schema"].schema) == {CONF_POLL_INTERVAL_SECONDS, CONF_LOG_LEVEL}

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
    assert saved["data"] == {CONF_POLL_INTERVAL_SECONDS: 120, CONF_LOG_LEVEL: "info"}


# ------------------------------------------------------ installed material


def test_br_installed_material_lives_in_the_component_and_reports_what_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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


def test_br_material_is_refused_inside_the_source_tree_but_allowed_in_an_installed_component(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A Home Assistant config directory kept under git is NOT the project's source tree.
    config = tmp_path / "config"
    component = _component(tmp_path, monkeypatch)
    (config / ".git").mkdir()
    directory = component / "resources" / "br"
    directory.mkdir(parents=True)
    write_dummy_material(directory)
    assert br_installed.load_installed_br_material() is not None

    # The project's own checkout (git + pyproject + tests) still refuses it.
    (config / "pyproject.toml").write_text("[project]\n")
    (config / "tests").mkdir()
    with pytest.raises(br_installed.GwmBrMaterialInvalidError):
        br_installed.load_installed_br_material()


# ------------------------------------------------------------- credentials


def test_br_credentials_binding_state_and_storage_round_trip() -> None:
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
async def test_br_startup_restore_makes_no_request_and_needs_stored_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    authenticator, transport = _authenticator(monkeypatch, tmp_path)
    credentials = _credentials()
    regional = credentials.client_credentials()

    restored = await authenticator.async_authenticate(
        credentials, state=_expired_state(credentials), allow_password_login=False
    )
    assert isinstance(restored, BrAuthenticated)
    assert transport.requests == []

    with pytest.raises(GwmAuthenticationError):
        await authenticator.async_authenticate(
            credentials, state=BrAuthState.for_credentials(regional), allow_password_login=False
        )
    with pytest.raises(GwmConfigurationError):
        await authenticator.async_authenticate(credentials, verification_code="123456")


# ---------------------------------------------------------------- runtime


def _bootstrap(tmp_path: Path, state_tokens: bool = True, expired: bool = False) -> tuple[GwmCloudCredentials, runtime.GwmCloudBootstrap]:
    credentials = _credentials()
    state = BrAuthState.for_credentials(credentials.client_credentials())
    if state_tokens:
        state = _expired_state(credentials) if expired else replace(
            state, tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR))
        )
    bootstrap = runtime.GwmCloudBootstrap.from_authentication(credentials, BrAuthenticated(state, _context(tmp_path)))
    return credentials, bootstrap


def test_br_bootstrap_requires_tokens_and_an_mtls_context(tmp_path: Path) -> None:
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
    credentials, bootstrap = _bootstrap(tmp_path)
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS))
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials),
        cloud_unique_id(credentials),
        bootstrap,
        state_store=_Store(),
        # Every consent below is ignored for Brazil.
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
    assert data["charging_control_enabled"] is False
    vehicle = data["vehicles"][0]
    assert vehicle["values"]["soc"] == 80.0
    assert vehicle["location"]["latitude"] == pytest.approx(-1.25)
    capabilities = vehicle["capabilities"]
    assert not any(value is True for value in capabilities.values()), capabilities

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


@pytest.mark.asyncio
async def test_br_expired_token_relogins_by_password_and_persists_the_new_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    credentials, bootstrap = _bootstrap(tmp_path, expired=True)
    new_exp = NOW_FAR + 5
    transport = FakeTransport(_login(new_exp), envelope(VEHICLES), envelope(STATUS))
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    store = _Store()
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials), cloud_unique_id(credentials), bootstrap, state_store=store
    )

    await cloud.async_get_vehicle_data()

    assert [request.operation for request in transport.requests] == ["login", "acquire_vehicles", "get_last_status"]
    assert len(store.saved) == 1
    assert store.saved[0].tokens.expires_at == float(new_exp)
    reusable = cloud.reusable_bootstrap
    assert reusable is not None and reusable.state.tokens == store.saved[0].tokens
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_password_change_clears_state_and_asks_for_reauthentication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    credentials, bootstrap = _bootstrap(tmp_path, expired=True)
    transport = FakeTransport(envelope(None, code="308001"))
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    store = _Store()
    cloud = runtime.GwmCloudClient.from_entry_data(
        cloud_entry_data(credentials), cloud_unique_id(credentials), bootstrap, state_store=store
    )

    with pytest.raises(GwmBrCredentialError):
        await cloud.async_get_vehicle_data()

    assert store.cleared == 1 and cloud.reusable_bootstrap is None
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_setup_forwards_only_read_only_platforms_and_never_enables_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
        options={CONF_ENABLE_REMOTE_COMMANDS: True, CONF_ENABLE_CHARGING_CONTROL: True, CONF_SECURITY_PIN: "1234"},
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
    assert await integration.async_unload_entry(hass, entry)
    assert unloaded == BR_PLATFORMS and transport.closed is True


@pytest.mark.asyncio
async def test_br_startup_without_certificate_files_retries_instead_of_asking_for_reauth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
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
    assert "resources" in str(raised.value)
    assert "resources" in caplog.text
    assert PASSWORD not in caplog.text and ACCOUNT not in caplog.text


# ------------------------------------------------------ entities, diagnostics


def test_br_sensor_set_has_no_command_status() -> None:
    br_keys = {d.key for d in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "br")}
    eu_keys = {d.key for d in _sensor_descriptions_for_vehicle({"platform": "beantech"}, "eu")}
    assert "command_status" in eu_keys and "command_status" not in br_keys
    assert {"soc", "range_km"} <= br_keys


def test_br_diagnostics_know_the_hosts_and_redact_private_values(tmp_path: Path) -> None:
    assert _DISCOVERY_GATEWAYS["br-app-gateway.gwmcloud.com"] == ("br", "br_static_mtls")
    assert {"password_md5", "access_token", "refresh_token", "device_id", "vin", "latitude", "longitude", "account"} <= TO_REDACT

    request = prepare_br_request(
        operation="login",
        ssl_context=_context(tmp_path),
        credentials=BrCredentials.from_password(ACCOUNT, PASSWORD, DEVICE),
    )
    exchange = begin_request(request, connect_timeout=10.0, read_timeout=20.0, remaining=30.0)
    assert exchange is not None
    assert exchange.fields["region"] == "br" and exchange.fields["signing"] == "none"
    flattened = json.dumps(exchange.fields, default=str)
    assert ACCOUNT not in flattened and DEVICE not in flattened and PASSWORD not in flattened
    assert br_flow.BrAuthenticated is BrAuthenticated
