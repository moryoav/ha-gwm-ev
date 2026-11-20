"""Brazil region wiring: config flow, runtime, storage and guards, all offline.

BR is read-only: password login with email verification, ``acquireVehicles`` + ``getLastStatus``
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

from homeassistant.config_entries import ConfigEntry, ConfigEntryState, ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ConfigEntryAuthFailed
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
from custom_components.gwm_ora.cloud_storage import GwmCloudStateStore, _decode_auth_state, _encode_auth_state
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
    CONF_VERIFICATION_CODE,
    CONFIGURABLE_CLOUD_REGIONS,
    CONNECTION_TYPE_CLOUD,
    DOMAIN,
    PLATFORMS,
    REGION_BR,
    platforms_for_region,
)
from custom_components.gwm_ora.coordinator import GwmDataUpdateCoordinator
from custom_components.gwm_ora.diagnostics import TO_REDACT
from custom_components.gwm_ora.errors import GwmCommandForbidden
from custom_components.gwm_ora.gwm_client import (
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmNetworkError,
    GwmRoutePolicyError,
    GwmTlsError,
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
from custom_components.gwm_ora.gwm_client.br_request import GwmBrSessionRejectedError, prepare_br_request
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
    return envelope({"accessToken": fake_jwt(exp), "refreshToken": "synthetic-refresh", "gwId": "synthetic-gw-id"})


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
    return replace(state, tokens=BrTokens(fake_jwt(1), "synthetic-refresh", 1.0, gw_id="synthetic-gw-id"))


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

    # The vehicle gateway rejects the client certificate after a successful login.
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, _login(), html(400, "No required SSL certificate was sent")
    )
    tls_flow = _flow(monkeypatch, authenticator)
    await tls_flow.async_step_user({CONF_REGION: "br"})
    tls = await tls_flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert [request.operation for request in transport.requests] == ["login", "acquire_vehicles"]
    assert tls["errors"] == {"base": "br_tls_rejected"}


@pytest.mark.asyncio
async def test_br_login_tls_failure_is_a_connection_error_not_a_certificate_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store
) -> None:
    """Check that a TLS failure on the login portal is not reported as a client-certificate rejection."""
    authenticator, transport = _authenticator(monkeypatch, tmp_path)

    async def tls_failure(request: object, **kwargs: object) -> object:
        raise GwmTlsError(operation="login")

    monkeypatch.setattr(transport, "execute", tls_failure)
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    result = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert result["errors"] == {"base": "cannot_connect"}


@pytest.mark.asyncio
async def test_br_country_other_than_br_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store) -> None:
    """Check that a country other than BR is rejected for the BR region."""
    authenticator, _ = _authenticator(monkeypatch, tmp_path)
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    result = await flow.async_step_account({CONF_COUNTRY: "DE", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert result["errors"] == {"base": "invalid_account"}


@pytest.mark.asyncio
@pytest.mark.parametrize("needs_verification", [False, True])
async def test_br_reauth_asks_only_for_the_password_and_drops_stale_command_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: _Store, needs_verification: bool
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
    responses = [_login(), envelope(VEHICLES)]
    if needs_verification:
        responses = [envelope(None, code="308103"), envelope(None), envelope(None), *responses]
    authenticator, _ = _authenticator(monkeypatch, tmp_path, *responses)
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

    if needs_verification:
        assert result["step_id"] == "verification"
        result = await flow.async_step_verification({CONF_VERIFICATION_CODE: "123456"})
    assert result["reason"] == "reauth_successful"
    assert updates[0]["data"][CONF_PASSWORD] == "New-Password-2"
    assert updates[0]["options"] == {CONF_POLL_INTERVAL_SECONDS: 90, CONF_ENABLE_CHARGING_CONTROL: True}
    assert consume_cloud_bootstrap(flow.hass, entry.unique_id) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("needs_verification", [False, True])
@pytest.mark.parametrize(
    ("previous_region", "previous_account", "charging_kept"),
    [
        (REGION_BR, ACCOUNT, True),  # same Brazil account: keep the charging opt-in
        (REGION_BR, "other@example.invalid", False),  # another account: start without consent
        ("eu", ACCOUNT, False),  # switching region: never carry consent over
    ],
)
async def test_br_reconfigure_keeps_charging_consent_only_for_the_same_account(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    store: _Store,
    previous_region: str,
    previous_account: str,
    charging_kept: bool,
    needs_verification: bool,
) -> None:
    """Check that reconfiguration keeps the BR charging opt-in only for the same BR account, like APAC."""
    previous = GwmCloudCredentials(previous_region, "BR" if previous_region == REGION_BR else "DE", previous_account, PASSWORD, DEVICE)
    entry = ConfigEntry(
        data=cloud_entry_data(previous),
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
        title="GWM",
        unique_id=cloud_unique_id(previous),
        version=1,
    )
    responses = [_login(), envelope(VEHICLES)]
    if needs_verification:
        responses = [envelope(None, code="308103"), envelope(None), envelope(None), *responses]
    authenticator, _ = _authenticator(monkeypatch, tmp_path, *responses)
    flow = config_flow.GwmConfigFlow()
    flow.hass = _Hass(entry)  # type: ignore[assignment]
    flow.context = {"source": "reconfigure", "entry_id": entry.entry_id}
    flow._cloud_authenticator = authenticator
    updates: list[dict[str, Any]] = []

    def update_and_abort(updated: ConfigEntry, **kwargs: Any) -> ConfigFlowResult:
        updates.append(kwargs)
        return flow.async_abort(reason="reconfigure_successful")

    async def remove_state(hass: object, unique_id: object) -> None:
        return None

    monkeypatch.setattr(flow, "async_update_reload_and_abort", update_and_abort)
    monkeypatch.setattr(config_flow, "async_remove_cloud_state", remove_state)
    await flow.async_step_reconfigure({CONF_REGION: REGION_BR})
    result = await flow.async_step_reconfigure_account(
        {CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD}
    )

    if needs_verification:
        assert result["step_id"] == "verification"
        result = await flow.async_step_verification({CONF_VERIFICATION_CODE: "123456"})
    assert result["reason"] == "reconfigure_successful"
    expected = {CONF_POLL_INTERVAL_SECONDS: 90}
    if charging_kept:
        expected[CONF_ENABLE_CHARGING_CONTROL] = True
    assert updates[0]["options"] == expected


@pytest.mark.asyncio
async def test_reconfiguring_away_from_brazil_drops_its_charging_consent(
    monkeypatch: pytest.MonkeyPatch, store: _Store
) -> None:
    """Check that a Brazil charging opt-in never enables charging writes in another region."""
    from types import SimpleNamespace

    previous = _credentials()
    entry = ConfigEntry(
        data=cloud_entry_data(previous), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1,
        options={CONF_POLL_INTERVAL_SECONDS: 90, CONF_ENABLE_CHARGING_CONTROL: True},
        source="user", subentries_data=None, title="GWM Brazil", unique_id=cloud_unique_id(previous), version=1,
    )
    flow = config_flow.GwmConfigFlow()
    flow.hass = _Hass(entry)  # type: ignore[assignment]
    flow.context = {"source": "reconfigure", "entry_id": entry.entry_id}
    flow._cloud_mode = "reconfigure"
    flow._cloud_credentials = GwmCloudCredentials("eu", "DE", ACCOUNT, PASSWORD, DEVICE)
    updates: list[dict[str, Any]] = []

    def update_and_abort(updated: ConfigEntry, **kwargs: Any) -> ConfigFlowResult:
        updates.append(kwargs)
        return flow.async_abort(reason="reconfigure_successful")

    async def remove_state(hass: object, unique_id: object) -> None:
        return None

    monkeypatch.setattr(flow, "async_update_reload_and_abort", update_and_abort)
    monkeypatch.setattr(config_flow, "async_remove_cloud_state", remove_state)
    monkeypatch.setattr(config_flow.GwmCloudBootstrap, "from_authentication", lambda credentials, result: object())
    monkeypatch.setattr(config_flow, "stage_cloud_bootstrap", lambda hass, unique_id, bootstrap: None)

    await flow._async_finish_cloud(SimpleNamespace(state=object()))  # type: ignore[arg-type]

    assert updates[0]["options"] == {CONF_POLL_INTERVAL_SECONDS: 90}


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

    state = replace(BrAuthState.for_credentials(regional), tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR), gw_id="synthetic-gw-id"))
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
        tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR), gw_id="synthetic-gw-id"),
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


@pytest.mark.asyncio
async def test_old_brazil_session_requests_explicit_login_to_recover_gw_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    authenticator, transport = _authenticator(monkeypatch, tmp_path)
    credentials = _credentials()
    state = replace(_expired_state(credentials), tokens=BrTokens("old-access", "old-refresh"))
    with pytest.raises(GwmAuthenticationError):
        await authenticator.async_authenticate(credentials, state=state, allow_password_login=False)
    assert transport.requests == []


def _bootstrap(tmp_path: Path, state_tokens: bool = True, expired: bool = False) -> tuple[GwmCloudCredentials, runtime.GwmCloudBootstrap]:
    """Build BR credentials and a bootstrap, optionally without tokens or with an expired session."""
    credentials = _credentials()
    state = BrAuthState.for_credentials(credentials.client_credentials())
    if state_tokens:
        state = _expired_state(credentials) if expired else replace(
            state, tokens=BrTokens(fake_jwt(NOW_FAR), "synthetic-refresh", float(NOW_FAR), gw_id="synthetic-gw-id")
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
        session._tokens = BrTokens(fake_jwt(NOW_FAR), "rotated-refresh", float(NOW_FAR), gw_id="synthetic-gw-id")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await cloud._async_with_br_session(rotate_then_get_cancelled)

    assert store.cleared == 0
    assert store.saved and store.saved[-1].tokens.refresh_token == "rotated-refresh"
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_shutdown_retries_a_failed_rotated_token_save(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transport = FakeTransport(_refresh(), envelope(VEHICLES), envelope(STATUS))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)
    save = store.async_save_auth_state
    attempts = 0

    async def fail_once(credentials: object, state: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("storage unavailable")
        await save(credentials, state)

    monkeypatch.setattr(store, "async_save_auth_state", fail_once)

    # The read itself succeeded, so its result is returned; the token save stays pending.
    data = await cloud.async_get_vehicle_data()
    assert data["vehicles"][0]["values"]["soc"] == 80.0
    assert store.saved == []

    await cloud.aclose()

    assert attempts == 2
    assert store.saved and store.saved[-1].tokens.refresh_token == "rotated-refresh"
    assert transport.closed is True


@pytest.mark.asyncio
async def test_br_shutdown_closes_the_transport_even_when_the_save_fails_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transport = FakeTransport(_refresh(), envelope(VEHICLES), envelope(STATUS))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)

    async def always_fail(credentials: object, state: Any) -> None:
        raise OSError("storage unavailable")

    monkeypatch.setattr(store, "async_save_auth_state", always_fail)
    await cloud.async_get_vehicle_data()
    # The next request first retries the pending save and does not run while storage is down.
    with pytest.raises(GwmNetworkError):
        await cloud.async_get_vehicle_data()
    assert [r.operation for r in transport.requests] == ["refresh_token", "acquire_vehicles", "get_last_status"]

    await cloud.aclose()

    assert transport.closed is True


class _UnloadEntries:
    async def async_unload_platforms(self, entry: object, platforms: list[object]) -> bool:
        return True


class _UnloadCoordinator:
    async def async_cancel_command_tasks(self) -> None:
        return None


async def _unload(
    tmp_path: Path, cloud: Any, entry_credentials: GwmCloudCredentials, staged: Any = None
) -> tuple[HomeAssistant, ConfigEntry]:
    """Unload an entry whose data already names ``entry_credentials`` (as after a reconfigure)."""
    hass = HomeAssistant(str(tmp_path))
    hass.config_entries = _UnloadEntries()  # type: ignore[assignment]
    entry = ConfigEntry(
        data=cloud_entry_data(entry_credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM", unique_id=cloud_unique_id(entry_credentials), version=1,
    )
    entry.runtime_data = integration.GwmRuntimeData(
        api=None,  # type: ignore[arg-type]
        coordinator=_UnloadCoordinator(),  # type: ignore[arg-type]
        cloud=cloud,
        state_store=_Store(),  # type: ignore[arg-type]
        platforms=list(BR_PLATFORMS),
    )
    if staged is not None:
        stage_cloud_bootstrap(hass, entry.unique_id, staged)
    assert await integration.async_unload_entry(hass, entry)
    return hass, entry


@pytest.mark.asyncio
async def test_br_unload_keeps_fresh_tokens_staged_by_reauth_or_reconfigure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    credentials, running = _bootstrap(tmp_path)
    fresh = runtime.GwmCloudBootstrap(
        region=REGION_BR,
        account_binding=running.account_binding,
        state=replace(running.state, tokens=BrTokens(fake_jwt(NOW_FAR), "fresh-refresh", float(NOW_FAR), gw_id="synthetic-gw-id")),
        session=None,
        br_ssl_context=running.br_ssl_context,
    )

    async def unload_with(staged: runtime.GwmCloudBootstrap | None) -> runtime.GwmCloudBootstrap | None:
        monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: FakeTransport())
        cloud = runtime.GwmCloudClient.from_entry_data(
            cloud_entry_data(credentials), cloud_unique_id(credentials), running, state_store=_Store()
        )
        hass, entry = await _unload(tmp_path, cloud, credentials, staged)
        return consume_cloud_bootstrap(hass, entry.unique_id)

    # A plain reload hands the running session to the next setup.
    assert await unload_with(None) is running
    # A reauth or reconfigure already staged newer tokens: the old session must not replace them.
    assert await unload_with(fresh) is fresh


class _OtherRegionCloud:
    """The outgoing runtime of an entry that is being reconfigured to or from Brazil."""

    def __init__(self, region: str) -> None:
        self.region = region
        self.reusable_bootstrap = object()
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_br_unload_never_hands_a_session_across_a_region_change(tmp_path: Path) -> None:
    credentials, fresh = _bootstrap(tmp_path)

    # EU entry reconfigured to Brazil: the staged Brazil sign-in survives the EU unload.
    outgoing = _OtherRegionCloud("eu")
    hass, entry = await _unload(tmp_path, outgoing, credentials, staged=fresh)
    assert consume_cloud_bootstrap(hass, entry.unique_id) is fresh and outgoing.closed is True

    # Without a staged Brazil sign-in, the EU session is still never staged for the Brazil entry.
    outgoing = _OtherRegionCloud("eu")
    hass, entry = await _unload(tmp_path, outgoing, credentials)
    assert consume_cloud_bootstrap(hass, entry.unique_id) is None and outgoing.closed is True

    # Brazil entry reconfigured to EU: the Brazil session is not staged for the EU entry.
    outgoing = _OtherRegionCloud(REGION_BR)
    eu = GwmCloudCredentials("eu", "DE", ACCOUNT, PASSWORD, DEVICE)
    hass, entry = await _unload(tmp_path, outgoing, eu)
    assert consume_cloud_bootstrap(hass, entry.unique_id) is None and outgoing.closed is True


@pytest.mark.asyncio
async def test_other_region_reload_still_reuses_its_session(tmp_path: Path) -> None:
    """Regions without Brazil involvement keep staging their session on every unload."""
    outgoing = _OtherRegionCloud("eu")
    eu = GwmCloudCredentials("eu", "DE", ACCOUNT, PASSWORD, DEVICE)
    hass, entry = await _unload(tmp_path, outgoing, eu)
    assert consume_cloud_bootstrap(hass, entry.unique_id) is outgoing.reusable_bootstrap


@pytest.mark.asyncio
async def test_br_unload_waits_for_an_in_flight_refresh_before_handing_off_the_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class GatedTransport(FakeTransport):
        def __init__(self, *responses: object) -> None:
            super().__init__(*responses)  # type: ignore[arg-type]
            self.refreshing = asyncio.Event()
            self.release = asyncio.Event()

        async def execute(self, request: Any, **kwargs: Any) -> Any:
            if request.operation == "refresh_token":
                self.refreshing.set()
                await self.release.wait()
            return await super().execute(request, **kwargs)

    transport = GatedTransport(_refresh(), envelope(VEHICLES), envelope(STATUS))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)
    credentials = _credentials()

    poll = asyncio.create_task(cloud.async_get_vehicle_data())
    await transport.refreshing.wait()
    unload = asyncio.create_task(_unload(tmp_path, cloud, credentials))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not unload.done()  # the unload waits for the poll that is renewing the session
    transport.release.set()
    await poll
    hass, entry = await unload

    staged = consume_cloud_bootstrap(hass, entry.unique_id)
    assert staged is not None and staged.state.tokens.refresh_token == "rotated-refresh"
    assert store.saved[-1].tokens.refresh_token == "rotated-refresh"
    assert transport.closed is True


@pytest.mark.asyncio
async def test_br_refresh_reply_without_a_code_keeps_the_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse

    no_code = _TransportResponse(200, {"content-type": "application/json"}, b'{"data":null}')
    transport = FakeTransport(no_code)
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=True)

    with pytest.raises(GwmClientError) as raised:
        await cloud.async_get_vehicle_data()

    assert not isinstance(raised.value, GwmAuthenticationError)
    assert [r.operation for r in transport.requests] == ["refresh_token"]
    assert store.cleared == 0 and cloud.reusable_bootstrap is not None
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_setup_keeps_the_handoff_when_its_save_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from homeassistant.exceptions import ConfigEntryNotReady

    credentials, bootstrap = _bootstrap(tmp_path)
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=cloud_unique_id(credentials), version=1,
    )
    hass = HomeAssistant(str(tmp_path))
    stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)

    class Store:
        async def async_save_auth_state(self, *args: object) -> None:
            raise OSError("storage unavailable")

    with pytest.raises(ConfigEntryNotReady):
        await integration._async_load_cloud_bootstrap_once(hass, entry, Store())  # type: ignore[arg-type]
    assert consume_cloud_bootstrap(hass, entry.unique_id) is bootstrap


@pytest.mark.asyncio
async def test_br_startup_retries_when_saving_the_restored_session_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from homeassistant.exceptions import ConfigEntryNotReady

    credentials, bootstrap = _bootstrap(tmp_path)
    context = _context(tmp_path)
    monkeypatch.setattr(integration, "load_installed_br_context", lambda: context)
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=cloud_unique_id(credentials), version=1,
    )

    class Store:
        cleared = 0

        async def async_load_auth_state(self, data: object) -> BrAuthState:
            return bootstrap.state

        async def async_save_auth_state(self, *args: object) -> None:
            raise OSError("storage unavailable")

        async def async_clear_auth_state(self, data: object) -> None:
            Store.cleared += 1

    with pytest.raises(ConfigEntryNotReady):
        await integration._async_load_cloud_bootstrap(HomeAssistant(str(tmp_path)), entry, Store())  # type: ignore[arg-type]
    assert Store.cleared == 0


@pytest.mark.asyncio
async def test_br_expired_session_code_on_a_read_renews_and_repeats_the_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transport = FakeTransport(
        envelope(None, code="550004", description="token expired"), _refresh(), envelope(VEHICLES), envelope(STATUS)
    )
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=False)

    await cloud.async_get_vehicle_data()

    assert [r.operation for r in transport.requests] == [
        "acquire_vehicles", "refresh_token", "acquire_vehicles", "get_last_status",
    ]
    assert store.cleared == 0
    await cloud.aclose()


def test_br_state_with_an_out_of_range_expiry_is_invalid_not_a_crash() -> None:
    from custom_components.gwm_ora.gwm_client.br_state import decode_br_state

    bootstrap_state = BrAuthState.for_credentials(_credentials().client_credentials())
    record = {
        "account_binding": bootstrap_state.account_binding,
        "device_id": bootstrap_state.device_id,
        "tokens": {"access_token": "a", "refresh_token": "r", "expires_at": 10**400},
    }
    with pytest.raises(ValueError, match="br_state_invalid"):
        decode_br_state(record)


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
    assert exchange.fields["region"] == "br" and exchange.fields["signing"] == "gwm_auth"
    assert exchange.fields["base_headers_complete"] is True  # the app login includes version and channel
    incomplete = replace(request, headers={k: v for k, v in request.headers.items() if k != "channel"})
    missing = begin_request(incomplete, connect_timeout=10.0, read_timeout=20.0, remaining=30.0)
    assert missing is not None and missing.fields["base_headers_complete"] is False
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
    monkeypatch: pytest.MonkeyPatch,
    region: str,
    api: _PlanApi,
    restored: str | None,
    *,
    extra: dict[str, Any] | None = None,
    current: bool | None = None,
) -> tuple[Any, _PlanCoordinator]:
    """Add a schedule switch to a fake coordinator with an optional restored state."""
    from unittest.mock import AsyncMock

    from homeassistant.core import State
    from homeassistant.helpers.restore_state import RestoredExtraData
    from homeassistant.helpers.update_coordinator import CoordinatorEntity

    from custom_components.gwm_ora import switch as switch_platform

    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    monkeypatch.setattr(
        switch_platform.GwmChargingScheduleSwitch,
        "async_get_last_state",
        AsyncMock(return_value=None if restored is None else State("switch.x", restored)),
    )
    monkeypatch.setattr(
        switch_platform.GwmChargingScheduleSwitch,
        "async_get_last_extra_data",
        AsyncMock(return_value=None if extra is None else RestoredExtraData(extra)),
    )
    coordinator = _PlanCoordinator(region)
    if current is not None:
        coordinator.set_charging_plan_active(VIN, current)
    entity = switch_platform.GwmChargingScheduleSwitch(api, coordinator, VIN)
    await entity.async_added_to_hass()
    return entity, coordinator


@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [True, False])
async def test_br_switch_restores_an_accepted_plan_saved_while_unavailable(
    monkeypatch: pytest.MonkeyPatch, accepted: bool
) -> None:
    """Check that the accepted plan survives a restart even when the switch was shown unavailable."""
    entity, _ = await _added_switch(
        monkeypatch, REGION_BR, _PlanApi(), "unavailable", extra={"charging_plan_active": accepted}
    )
    assert entity.is_on is accepted
    assert entity.extra_restore_state_data.as_dict() == {"charging_plan_active": accepted}


@pytest.mark.asyncio
async def test_br_switch_keeps_a_newer_service_result_over_the_restored_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that a plan accepted by a service before the switch was added is not replaced."""
    entity, _ = await _added_switch(
        monkeypatch, REGION_BR, _PlanApi(), "on", extra={"charging_plan_active": True}, current=False
    )
    assert entity.is_on is False


@pytest.mark.asyncio
async def test_br_switch_keeps_a_service_result_that_lands_while_restoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that a service completing during the restore await is not overwritten by older data."""
    from homeassistant.helpers.restore_state import RestoredExtraData
    from homeassistant.helpers.update_coordinator import CoordinatorEntity

    from custom_components.gwm_ora import switch as switch_platform

    coordinator = _PlanCoordinator(REGION_BR)

    async def no_parent(self: object) -> None:
        return None

    async def restore_while_a_clear_lands(self: object) -> RestoredExtraData:
        coordinator.set_charging_plan_active(VIN, False)  # the clear service completes meanwhile
        return RestoredExtraData({"charging_plan_active": True})

    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", no_parent)
    monkeypatch.setattr(switch_platform.GwmChargingScheduleSwitch, "async_get_last_extra_data", restore_while_a_clear_lands)
    entity = switch_platform.GwmChargingScheduleSwitch(_PlanApi(), coordinator, VIN)
    await entity.async_added_to_hass()
    assert entity.is_on is False


@pytest.mark.asyncio
async def test_readable_region_switch_stores_no_extra_restore_data(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check that regions with a plan readback do not persist the assumed state."""
    from custom_components.gwm_ora.gwm_client import ChargingPlanInfo, ChargingPlanItem

    live = ChargingPlanInfo((ChargingPlanItem(1, "1", 1_800_000_000_000, 1_800_000_028_800),))
    entity, _ = await _added_switch(monkeypatch, "eu", _PlanApi(live.as_dict()), None)
    assert entity.is_on is True and entity.extra_restore_state_data is None


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
async def test_readable_region_keeps_the_live_read_and_never_uses_the_restored_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that regions with a plan readback behave exactly as before Brazil was added."""
    from custom_components.gwm_ora.gwm_client import ChargingPlanInfo, ChargingPlanItem

    live = ChargingPlanInfo((ChargingPlanItem(1, "1", 1_800_000_000_000, 1_800_000_028_800),))
    api = _PlanApi(live.as_dict())
    entity, _ = await _added_switch(monkeypatch, "eu", api, "off")
    assert api.reads == 1 and entity.is_on is True  # live value wins over the restored one

    failing = _PlanApi(GwmRoutePolicyError(operation="get_charging_plan"))
    entity, _ = await _added_switch(monkeypatch, "eu", failing, "on")
    assert failing.reads == 1 and entity.is_on is None  # read failed: state stays unknown, as before


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


@pytest.mark.asyncio
async def test_brazil_email_verification_completes_in_the_existing_form(monkeypatch, tmp_path, store, caplog) -> None:
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, envelope(None, code="308103"), envelope(None),
        envelope(None, code="308103"), envelope(None), _login(), envelope(VEHICLES),
    )
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    form = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert form["step_id"] == "verification"
    challenge = store.saved[-1]
    assert challenge.tokens is None and challenge.verification_requested_at is not None
    assert _decode_auth_state(REGION_BR, _encode_auth_state(challenge)) == challenge
    # Resume in a fresh flow, as after closing setup or restarting Home Assistant.
    store.loaded = _decode_auth_state(REGION_BR, _encode_auth_state(challenge))
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    resumed = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert resumed["step_id"] == "verification"
    caplog.set_level("DEBUG", logger="custom_components.gwm_ora.gwm_client._auth_diagnostics")
    result = await flow.async_step_verification({CONF_VERIFICATION_CODE: "123456"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [r.operation for r in transport.requests] == [
        "login", "request_verification", "login", "verify_code", "login", "acquire_vehicles",
    ]
    for request in transport.requests:
        assert request.headers["deviceId"] == request.headers["iccid"] == challenge.device_id
    checked, login = [json.loads(r.body) for r in transport.requests[3:5]]
    assert checked["verifyCode"] == login["verifyCode"] == "123456"
    assert checked["type"] == "17" and checked["validCodeMode"] == 1
    assert login["validCodeMode"] == "1"
    assert store.saved[-1].verification_requested_at is None
    assert store.saved[-1].tokens.gw_id == "synthetic-gw-id"
    assert all("123456" not in json.dumps(_encode_auth_state(s)) for s in store.saved)
    assert "123456" not in caplog.text and PASSWORD not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["308011", "308012", "550002"])
async def test_brazil_wrong_email_code_keeps_the_form_without_resending(monkeypatch, tmp_path, store, code) -> None:
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, envelope(None, code="308103"), envelope(None), envelope(None, code=code),
    )
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    first = store.saved[-1]
    result = await flow.async_step_verification({CONF_VERIFICATION_CODE: "999999"})
    assert result["step_id"] == "verification"
    assert result["errors"] == {CONF_VERIFICATION_CODE: "invalid_verification_code"}
    assert store.saved[-1].device_id == first.device_id
    assert store.saved[-1].verification_requested_at == first.verification_requested_at
    assert [r.operation for r in transport.requests] == ["login", "request_verification", "verify_code"]


@pytest.mark.asyncio
async def test_brazil_verification_cooldown_survives_storage_and_background_calls_cannot_send_codes(monkeypatch, tmp_path) -> None:
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, envelope(None, code="308103"), envelope(None), envelope(None, code="308103"),
    )
    credentials = _credentials()
    result = await authenticator.async_authenticate(credentials)
    restored = _decode_auth_state(REGION_BR, _encode_auth_state(result.state))
    again = await authenticator.async_authenticate(credentials, state=restored)
    assert again.code_requested is False
    with pytest.raises(GwmAuthenticationError):
        await authenticator.async_authenticate(credentials, state=restored, allow_password_login=False)
    assert [r.operation for r in transport.requests] == ["login", "request_verification", "login"]


@pytest.mark.asyncio
async def test_brazil_verification_form_resends_on_request_and_keeps_the_device(monkeypatch, tmp_path, store) -> None:
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, envelope(None, code="308103"), envelope(None),
        envelope(None, code="308103"), envelope(None, code="308103"), envelope(None),
    )
    flow = _flow(monkeypatch, authenticator)
    await flow.async_step_user({CONF_REGION: "br"})
    form = await flow.async_step_account({CONF_COUNTRY: "BR", CONF_ACCOUNT: ACCOUNT, CONF_PASSWORD: PASSWORD})
    assert "request_new_email_code" in form["data_schema"].schema
    initial = store.saved[-1]
    empty = await flow.async_step_verification({})
    assert empty["errors"] == {CONF_VERIFICATION_CODE: "invalid_verification_code"}
    limited = await flow.async_step_verification({"request_new_email_code": True})
    assert limited["errors"] == {"base": "rate_limited"}
    flow._auth_state = replace(initial, verification_requested_at=initial.verification_requested_at - 601)
    resent = await flow.async_step_verification({"request_new_email_code": True})
    assert resent["step_id"] == "verification" and resent["errors"] == {}
    assert store.saved[-1].device_id == initial.device_id
    assert [r.operation for r in transport.requests] == [
        "login", "request_verification", "login", "login", "request_verification",
    ]


@pytest.mark.asyncio
async def test_br_session_takeover_retires_the_session_and_requests_reauthentication(monkeypatch, tmp_path) -> None:
    transport = FakeTransport(envelope(None, code="607501"))
    cloud, store = await _br_cloud(monkeypatch, tmp_path, transport, expired=False)
    coordinator = GwmDataUpdateCoordinator(
        HomeAssistant(str(tmp_path)), None, cloud_client=cloud,
    )
    with pytest.raises(ConfigEntryAuthFailed, match="signed in on another device") as error:
        await coordinator._async_update_data()
    assert isinstance(error.value.__cause__, GwmBrSessionRejectedError)
    assert [request.operation for request in transport.requests] == ["acquire_vehicles"]
    assert store.cleared >= 1
    assert cloud.reusable_bootstrap is None
    assert cloud._pending_auth_state is None
    await cloud.aclose()


@pytest.mark.asyncio
async def test_br_entry_startup_preserves_a_pending_email_challenge_on_disk(monkeypatch, tmp_path) -> None:
    import time

    credentials = _credentials()
    unique_id = cloud_unique_id(credentials)
    pending = replace(
        BrAuthState.for_credentials(credentials.client_credentials()), verification_requested_at=time.time(),
    )
    original = GwmCloudStateStore(HomeAssistant(str(tmp_path)), unique_id)
    await original.async_save_auth_state(credentials, pending)
    restarted_hass = HomeAssistant(str(tmp_path))
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=unique_id, version=1,
    )

    def no_background_authentication(**kwargs):
        raise AssertionError("Startup must leave the pending challenge for an explicit flow")

    monkeypatch.setattr(integration, "GwmCloudAuthenticator", no_background_authentication)
    with pytest.raises(ConfigEntryAuthFailed, match="email verification"):
        await integration._async_load_cloud_bootstrap(
            restarted_hass, entry, GwmCloudStateStore(restarted_hass, unique_id),
        )
    fresh = GwmCloudStateStore(HomeAssistant(str(tmp_path)), unique_id)
    restored = await fresh.async_load_auth_state(dict(entry.data))
    assert restored == pending
    authenticator, transport = _authenticator(
        monkeypatch, tmp_path, envelope(None, code="308103"), envelope(None), _login(), envelope(VEHICLES),
    )
    challenge = await authenticator.async_authenticate(credentials, state=restored)
    assert isinstance(challenge, br_flow.BrVerificationRequired)
    assert challenge.code_requested is False
    assert challenge.state.device_id == pending.device_id
    assert challenge.state.verification_requested_at == pending.verification_requested_at
    result = await authenticator.async_authenticate(credentials, state=challenge.state, verification_code="123456")
    assert isinstance(result, BrAuthenticated)
    assert result.state.device_id == pending.device_id
    assert result.state.verification_requested_at is None
    assert [request.operation for request in transport.requests] == ["login", "verify_code", "login", "acquire_vehicles"]


@pytest.mark.asyncio
async def test_br_real_hass_shutdown_flushes_rotated_tokens_to_disk(monkeypatch, tmp_path) -> None:
    credentials, bootstrap = _bootstrap(tmp_path)
    hass = HomeAssistant(str(tmp_path))
    unique_id = cloud_unique_id(credentials)
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=unique_id, version=1,
    )
    transport = FakeTransport(envelope(VEHICLES), envelope(STATUS), _refresh(), envelope(VEHICLES), envelope(STATUS))
    monkeypatch.setattr(runtime.AiohttpTransport, "create_owned", lambda **kwargs: transport)
    monkeypatch.setattr(integration, "_async_register_services", lambda hass: None)

    class Entries:
        async def async_forward_entry_setups(self, entry, platforms):
            return None

    hass.config_entries = Entries()  # type: ignore[assignment]
    entry._async_set_state(hass, ConfigEntryState.SETUP_IN_PROGRESS, None)
    stage_cloud_bootstrap(hass, unique_id, bootstrap)
    assert await integration.async_setup_entry(hass, entry)
    cloud = entry.runtime_data.cloud
    store = entry.runtime_data.state_store
    session = cloud._client._client.session
    session.restore(replace(session.tokens, expires_at=1.0))
    writer = store._store.async_save
    attempts = 0

    async def fail_first_write(data):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("temporary storage failure")
        await writer(data)

    monkeypatch.setattr(store._store, "async_save", fail_first_write)
    await entry.runtime_data.coordinator.async_refresh()
    assert entry.runtime_data.coordinator.last_update_success is True
    assert cloud._pending_auth_state is not None
    assert transport.closed is False
    await hass.async_stop(force=True)
    assert attempts == 2
    assert cloud._pending_auth_state is None
    assert transport.closed is True
    fresh = GwmCloudStateStore(HomeAssistant(str(tmp_path)), unique_id)
    restored = await fresh.async_load_auth_state(dict(entry.data))
    assert restored.tokens.refresh_token == "rotated-refresh"
    assert restored.tokens == session.tokens


@pytest.mark.asyncio
async def test_br_cancelled_startup_keeps_the_consumed_session_handoff(monkeypatch, tmp_path) -> None:
    credentials, bootstrap = _bootstrap(tmp_path)
    hass = HomeAssistant(str(tmp_path))
    entry = ConfigEntry(
        data=cloud_entry_data(credentials), discovery_keys=MappingProxyType({}), domain=DOMAIN,
        entry_id="br-entry", minor_version=1, options={}, source="user", subentries_data=None,
        title="GWM Brazil", unique_id=cloud_unique_id(credentials), version=1,
    )
    store = GwmCloudStateStore(hass, entry.unique_id)
    stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)
    saving = asyncio.Event()
    original = store.async_save_auth_state

    async def save(*args):
        saving.set()
        await original(*args)

    monkeypatch.setattr(store, "async_save_auth_state", save)
    await store._lock.acquire()
    task = asyncio.create_task(integration._async_load_cloud_bootstrap_once(hass, entry, store))
    try:
        await asyncio.wait_for(saving.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        store._lock.release()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert consume_cloud_bootstrap(hass, entry.unique_id) is bootstrap
