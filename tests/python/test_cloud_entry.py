"""Cloud-entry lifecycle and diagnostics tests for the staged HA path."""

from __future__ import annotations

import ssl
from dataclasses import replace
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("homeassistant")

from homeassistant.components.diagnostics import REDACTED
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from custom_components import gwm_ora
from custom_components.gwm_ora import (
    async_remove_entry,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.gwm_ora.cloud_auth import (
    GwmCloudCredentials,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_runtime import (
    GwmCloudBootstrap,
    consume_cloud_bootstrap,
    stage_cloud_bootstrap,
)
from custom_components.gwm_ora.cloud_storage import cloud_state_store
from custom_components.gwm_ora.const import (
    CONF_ACCOUNT,
    CONF_CONNECTION_TYPE,
    CONF_COUNTRY,
    CONF_ENABLE_CHARGING_CONTROL,
    CONF_ENABLE_REMOTE_COMMANDS,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL_SECONDS,
    CONF_REGION,
    CONF_SECURITY_PIN,
    CONNECTION_TYPE_CLOUD,
    DOMAIN,
)
from custom_components.gwm_ora.diagnostics import async_get_config_entry_diagnostics
from gwm_client import (
    ChinaAuthenticated,
    ChinaAuthState,
    ChinaInitializationRequired,
    EuAuthenticated,
    EuAuthState,
    EuCredentials,
    GwmAuthenticationError,
    GwmNetworkError,
    GwmSession,
)

_DEVICE_ID = "0123456789abcdef0123456789abcdef"


def _cloud_entry(
    *,
    data_updates: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> ConfigEntry:
    data = {
        CONF_CONNECTION_TYPE: CONNECTION_TYPE_CLOUD,
        CONF_REGION: "eu",
        CONF_COUNTRY: "DE",
        CONF_ACCOUNT: "private-account",
        CONF_PASSWORD: "private-password",
        **(data_updates or {}),
    }
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        str(data[CONF_ACCOUNT]),
        str(data[CONF_PASSWORD]),
        _DEVICE_ID,
    )
    return ConfigEntry(
        data=data,
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="synthetic-cloud-entry",
        minor_version=1,
        options=options or {},
        source="user",
        subentries_data=None,
        title="GWM Europe",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )


def _bootstrap(entry: ConfigEntry, token: str = "synthetic-access-token") -> GwmCloudBootstrap:
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        str(entry.data[CONF_ACCOUNT]),
        str(entry.data[CONF_PASSWORD]),
        _DEVICE_ID,
    )
    regional = credentials.client_credentials()
    assert isinstance(regional, EuCredentials)
    state = EuAuthState(
        account_binding=regional.account_binding,
        country="DE",
        device_id=_DEVICE_ID,
        access_token=token,
    )
    return GwmCloudBootstrap(
        region="eu",
        account_binding=credentials.account_binding,
        state=state,
        session=GwmSession(
            "DE",
            _DEVICE_ID,
            token,
            ssl.create_default_context(),
        ),
    )


def _china_entry_and_bootstrap() -> tuple[
    ConfigEntry,
    GwmCloudCredentials,
    GwmCloudBootstrap,
]:
    data = {
        CONF_CONNECTION_TYPE: CONNECTION_TYPE_CLOUD,
        CONF_REGION: "cn",
        CONF_COUNTRY: "CN",
        CONF_ACCOUNT: "13800138000",
    }
    credentials = GwmCloudCredentials(
        "cn",
        "CN",
        str(data[CONF_ACCOUNT]),
        None,
        _DEVICE_ID,
    )
    state = replace(
        ChinaAuthState.for_credentials(credentials.client_credentials()),
        g_token="synthetic-g-token",
        g_refresh_token="synthetic-g-refresh-token",
        user_id="synthetic-g-user",
        bean_id="synthetic-g-bean",
        bean_tech_access_token="synthetic-bean-access-token",
        auto_ai_token_id="synthetic-auto-token",
        auto_ai_user_id="synthetic-auto-user",
    )
    entry = ConfigEntry(
        data=data,
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        entry_id="synthetic-china-entry",
        minor_version=1,
        options={
            CONF_ENABLE_REMOTE_COMMANDS: True,
            CONF_ENABLE_CHARGING_CONTROL: True,
        },
        source="user",
        subentries_data=None,
        title="GWM China",
        unique_id=cloud_unique_id(credentials),
        version=1,
    )
    bootstrap = GwmCloudBootstrap.from_authentication(
        credentials,
        ChinaAuthenticated(state),
    )
    return entry, credentials, bootstrap


@pytest.mark.asyncio
async def test_cloud_entry_without_memory_handoff_requests_reauthentication(
    tmp_path: Any,
) -> None:
    entry = _cloud_entry()
    hass = HomeAssistant(str(tmp_path))

    with pytest.raises(ConfigEntryAuthFailed):
        await async_setup_entry(hass, entry)


@pytest.mark.asyncio
async def test_legacy_addon_entry_requires_fresh_setup(tmp_path: Any) -> None:
    entry = _cloud_entry(data_updates={CONF_CONNECTION_TYPE: "addon"})
    hass = HomeAssistant(str(tmp_path))

    with pytest.raises(ConfigEntryAuthFailed, match="retired add-on entry"):
        await async_setup_entry(hass, entry)


@pytest.mark.asyncio
async def test_cloud_entry_setup_and_unload_own_runtime_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    entry = _cloud_entry(
        options={
            CONF_POLL_INTERVAL_SECONDS: 180,
            CONF_ENABLE_CHARGING_CONTROL: True,
        }
    )
    hass = HomeAssistant(str(tmp_path))
    bootstrap = _bootstrap(entry)
    stage_cloud_bootstrap(hass, entry.unique_id or "", bootstrap)
    shutdown_order: list[str] = []
    forwarded: list[tuple[str, ...]] = []
    unloaded: list[tuple[str, ...]] = []

    class Cloud:
        region = "eu"
        reusable_bootstrap = bootstrap

        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            shutdown_order.append("transport")
            self.closed = True

    cloud = Cloud()

    class Coordinator:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            assert kwargs["update_interval_seconds"] == 180
            assert kwargs["config_entry"] is entry
            assert kwargs["cloud_client"] is cloud
            self.data = {"region": "eu", "vehicles": []}
            self.cancelled = False

        async def async_config_entry_first_refresh(self) -> None:
            return None

        async def async_cancel_command_tasks(self) -> None:
            shutdown_order.append("commands")
            self.cancelled = True

    def cloud_runtime(*args: Any, **kwargs: Any) -> Cloud:
        assert kwargs["charging_control_enabled"] is True
        return cloud

    monkeypatch.setattr(
        gwm_ora.GwmCloudClient,
        "from_entry_data",
        classmethod(lambda cls, *args, **kwargs: cloud_runtime(*args, **kwargs)),
    )
    monkeypatch.setattr(gwm_ora, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(gwm_ora, "_async_register_services", lambda hass: None)

    class ConfigEntries:
        async def async_forward_entry_setups(
            self,
            target: ConfigEntry,
            platforms: list[Any],
        ) -> None:
            assert target is entry
            forwarded.append(tuple(str(platform) for platform in platforms))

        async def async_unload_platforms(
            self,
            target: ConfigEntry,
            platforms: list[Any],
        ) -> bool:
            assert target is entry
            unloaded.append(tuple(str(platform) for platform in platforms))
            return True

    hass.config_entries = ConfigEntries()  # type: ignore[assignment]

    assert await async_setup_entry(hass, entry) is True
    assert entry.runtime_data.cloud is cloud
    assert forwarded
    assert await async_unload_entry(hass, entry) is True
    assert unloaded
    assert cloud.closed
    assert entry.runtime_data.coordinator.cancelled
    assert shutdown_order == ["commands", "transport"]
    assert consume_cloud_bootstrap(hass, entry.unique_id) is bootstrap


@pytest.mark.asyncio
async def test_transient_first_refresh_failure_restages_handoff_for_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    entry = _cloud_entry()
    hass = HomeAssistant(str(tmp_path))
    bootstrap = _bootstrap(entry)
    stage_cloud_bootstrap(hass, entry.unique_id or "", bootstrap)
    shutdown_order: list[str] = []

    class Cloud:
        region = "eu"
        reusable_bootstrap = bootstrap

        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            shutdown_order.append("transport")
            self.closed = True

    cloud = Cloud()

    class Coordinator:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def async_config_entry_first_refresh(self) -> None:
            raise ConfigEntryNotReady("synthetic transient failure")

        async def async_cancel_command_tasks(self) -> None:
            shutdown_order.append("commands")

    monkeypatch.setattr(
        gwm_ora.GwmCloudClient,
        "from_entry_data",
        classmethod(lambda cls, *args, **kwargs: cloud),
    )
    monkeypatch.setattr(gwm_ora, "GwmDataUpdateCoordinator", Coordinator)

    with pytest.raises(ConfigEntryNotReady):
        await async_setup_entry(hass, entry)

    assert cloud.closed
    assert shutdown_order == ["commands", "transport"]
    assert consume_cloud_bootstrap(hass, entry.unique_id) is bootstrap


@pytest.mark.asyncio
async def test_process_restart_resumes_and_rotates_durable_session_without_login(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    entry = _cloud_entry()
    initial = _bootstrap(entry, "initial-access-token")
    first_hass = HomeAssistant(str(tmp_path))
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        str(entry.data[CONF_ACCOUNT]),
        str(entry.data[CONF_PASSWORD]),
        _DEVICE_ID,
    )
    await cloud_state_store(
        first_hass,
        entry.unique_id or "",
    ).async_save_auth_state(credentials, initial.state)

    rotated = _bootstrap(entry, "rotated-access-token")

    class Authenticator:
        async def async_authenticate(
            self,
            supplied: GwmCloudCredentials,
            **kwargs: Any,
        ) -> object:
            assert supplied.device_id == _DEVICE_ID
            assert kwargs["state"] == initial.state
            assert kwargs["allow_password_login"] is False
            assert kwargs["allow_session_reclaim"] is False
            return EuAuthenticated(rotated.state, rotated.session)

    class Cloud:
        region = "eu"
        reusable_bootstrap = rotated

        async def aclose(self) -> None:
            return None

    cloud = Cloud()

    class Coordinator:
        data = {"region": "eu", "vehicles": []}

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            assert kwargs["cloud_client"] is cloud

        async def async_config_entry_first_refresh(self) -> None:
            return None

    class ConfigEntries:
        async def async_forward_entry_setups(self, *args: Any) -> None:
            return None

    restarted_hass = HomeAssistant(str(tmp_path))
    restarted_hass.config_entries = ConfigEntries()  # type: ignore[assignment]
    monkeypatch.setattr(gwm_ora, "GwmCloudAuthenticator", Authenticator)
    monkeypatch.setattr(
        gwm_ora.GwmCloudClient,
        "from_entry_data",
        classmethod(lambda cls, *args, **kwargs: cloud),
    )
    monkeypatch.setattr(gwm_ora, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(gwm_ora, "_async_register_services", lambda hass: None)

    assert await async_setup_entry(restarted_hass, entry)

    third_hass = HomeAssistant(str(tmp_path))
    restored = await cloud_state_store(
        third_hass,
        entry.unique_id or "",
    ).async_load_auth_state(dict(entry.data))
    assert isinstance(restored, EuAuthState)
    assert restored.access_token == "rotated-access-token"


@pytest.mark.asyncio
async def test_china_restart_resumes_complete_state_and_enables_no_pin_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    entry, credentials, bootstrap = _china_entry_and_bootstrap()
    first_hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(
        first_hass,
        entry.unique_id or "",
    ).async_save_auth_state(credentials, bootstrap.state)

    class Cloud:
        region = "cn"
        reusable_bootstrap = bootstrap

        async def aclose(self) -> None:
            return None

    cloud = Cloud()

    def runtime(*args: Any, **kwargs: Any) -> Cloud:
        assert args[2].region == "cn"
        assert args[2].session is None
        assert kwargs["climate_commands_enabled"] is True
        assert kwargs["lock_window_commands_enabled"] is True
        assert kwargs["charging_control_enabled"] is True
        return cloud

    class Coordinator:
        data = {"region": "cn", "vehicles": []}

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            assert kwargs["cloud_client"] is cloud

        async def async_config_entry_first_refresh(self) -> None:
            return None

        def async_track_command(self, command: object) -> None:
            raise AssertionError(command)

    class ConfigEntries:
        async def async_forward_entry_setups(self, *args: Any) -> None:
            return None

    class Authenticator:
        async def async_authenticate(
            self,
            supplied: GwmCloudCredentials,
            **kwargs: Any,
        ) -> object:
            assert supplied == credentials
            assert kwargs["state"] == bootstrap.state
            assert kwargs["allow_password_login"] is False
            assert kwargs["allow_session_reclaim"] is False
            return ChinaAuthenticated(bootstrap.state)

    restarted_hass = HomeAssistant(str(tmp_path))
    restarted_hass.config_entries = ConfigEntries()  # type: ignore[assignment]
    monkeypatch.setattr(gwm_ora, "GwmCloudAuthenticator", Authenticator)
    monkeypatch.setattr(
        gwm_ora.GwmCloudClient,
        "from_entry_data",
        classmethod(lambda cls, *args, **kwargs: runtime(*args, **kwargs)),
    )
    monkeypatch.setattr(gwm_ora, "GwmDataUpdateCoordinator", Coordinator)
    monkeypatch.setattr(gwm_ora, "_async_register_services", lambda hass: None)

    assert await async_setup_entry(restarted_hass, entry)
    assert entry.runtime_data.cloud is cloud


@pytest.mark.asyncio
async def test_china_restart_preserves_rotated_partial_initialization_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    entry, credentials, bootstrap = _china_entry_and_bootstrap()
    first_hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(
        first_hass,
        entry.unique_id or "",
    ).async_save_auth_state(credentials, bootstrap.state)
    partial = replace(
        bootstrap.state,
        bean_tech_access_token=None,
        bean_tech_refresh_token=None,
        bean_tech_sso_token=None,
        bean_tech_bean_id=None,
        auto_ai_token_id=None,
        auto_ai_user_id=None,
        auto_ai_gw_id=None,
    )

    class Authenticator:
        async def async_authenticate(self, *args: Any, **kwargs: Any) -> object:
            return ChinaInitializationRequired(
                partial,
                ("bean_tech:network_error",),
            )

    restarted_hass = HomeAssistant(str(tmp_path))
    monkeypatch.setattr(gwm_ora, "GwmCloudAuthenticator", Authenticator)

    with pytest.raises(ConfigEntryNotReady, match="initialization attempt"):
        await async_setup_entry(restarted_hass, entry)

    restored_hass = HomeAssistant(str(tmp_path))
    restored = await cloud_state_store(
        restored_hass,
        entry.unique_id or "",
    ).async_load_auth_state(dict(entry.data))
    assert restored == partial


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (GwmAuthenticationError(operation="login"), ConfigEntryAuthFailed),
        (GwmNetworkError(operation="refresh_token"), ConfigEntryNotReady),
    ],
)
async def test_restart_retires_rejected_state_but_preserves_transient_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    error: Exception,
    expected: type[Exception],
) -> None:
    entry = _cloud_entry()
    initial = _bootstrap(entry, "initial-access-token")
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        str(entry.data[CONF_ACCOUNT]),
        str(entry.data[CONF_PASSWORD]),
        _DEVICE_ID,
    )
    first_hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(
        first_hass,
        entry.unique_id or "",
    ).async_save_auth_state(credentials, initial.state)

    class Authenticator:
        async def async_authenticate(self, *args: Any, **kwargs: Any) -> object:
            assert kwargs["allow_password_login"] is False
            raise error

    restarted_hass = HomeAssistant(str(tmp_path))
    monkeypatch.setattr(gwm_ora, "GwmCloudAuthenticator", Authenticator)

    with pytest.raises(expected):
        await async_setup_entry(restarted_hass, entry)

    third_hass = HomeAssistant(str(tmp_path))
    restored = await cloud_state_store(
        third_hass,
        entry.unique_id or "",
    ).async_load_auth_state(dict(entry.data))
    if isinstance(error, GwmAuthenticationError):
        assert restored is None
    else:
        assert restored == initial.state


@pytest.mark.asyncio
async def test_removing_cloud_entry_removes_its_private_state(tmp_path: Any) -> None:
    entry = _cloud_entry()
    bootstrap = _bootstrap(entry)
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        str(entry.data[CONF_ACCOUNT]),
        str(entry.data[CONF_PASSWORD]),
        _DEVICE_ID,
    )
    hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(
        hass,
        entry.unique_id or "",
    ).async_save_auth_state(credentials, bootstrap.state)
    state_files = list((tmp_path / ".storage").glob("gwm_ora.direct_cloud.*"))
    assert len(state_files) == 1

    await async_remove_entry(hass, entry)

    assert not state_files[0].exists()


@pytest.mark.asyncio
async def test_cloud_diagnostics_redact_current_and_future_account_state() -> None:
    secrets = {
        CONF_SECURITY_PIN: "private-pin",
        "access_token": "private-access-token",
        "g_refresh_token": "private-refresh-token",
        "auto_ai_user_id": "private-user-id",
        "device_id": "private-device-id",
        "certificate": "private-certificate",
        "private_key": "private-key",
        "serial_number": "private-serial",
        "vehicle_id": "private-vehicle-id",
        "vin": "private-vin",
        "location": "private-location",
    }
    entry = _cloud_entry(data_updates=secrets, options={CONF_SECURITY_PIN: "private-pin"})
    entry.runtime_data = SimpleNamespace(
        coordinator=SimpleNamespace(data={"vehicles": [secrets]}),
        state_store={
            "auth_state": "private-durable-state",
            "command_journal": "private-command-journal",
        },
    )

    result = await async_get_config_entry_diagnostics(object(), entry)  # type: ignore[arg-type]

    assert result["vehicles"]["vehicles"][0]["vin"] == REDACTED
    assert result["entry"]["data"][CONF_ACCOUNT] == REDACTED
    assert result["entry"]["data"][CONF_PASSWORD] == REDACTED
    assert result["entry"]["options"][CONF_SECURITY_PIN] == REDACTED
    assert result["entry"]["unique_id"] == REDACTED
    rendered = repr(result)
    assert "private-account" not in rendered
    assert "private-password" not in rendered
    assert all(value not in rendered for value in secrets.values())
    assert "private-durable-state" not in rendered
    assert "private-command-journal" not in rendered
