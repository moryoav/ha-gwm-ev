"""Offline tests for the Home Assistant GWM cloud authentication adapter."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("homeassistant")

from custom_components.gwm_ora.cloud_auth import (
    GwmCloudAuthenticator,
    GwmCloudCredentials,
    _load_bootstrap_material,
    cloud_entry_data,
    cloud_entry_title,
    cloud_unique_id,
)
from custom_components.gwm_ora.const import (
    ANZ_AUTHENTICATION_METHOD_CURRENT,
    ANZ_AUTHENTICATION_METHOD_LEGACY,
    CONF_ACCOUNT,
    CONF_AUTHENTICATION_METHOD,
    CONF_CONNECTION_TYPE,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    CONNECTION_TYPE_CLOUD,
)
from gwm_client import (
    AnzAuthenticationMethod,
    AnzCredentials,
    ChinaAuthState,
    ChinaClientConfig,
    EuBootstrapMaterial,
    GwmClientConfig,
    GwmNetworkError,
    RussiaBootstrapMaterial,
)

_DEVICE_ID = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    ("region", "country", "account", "password", "expected_country"),
    [
        ("eu", " de ", " account@example.invalid ", "password", "DE"),
        ("aus", "nz", " account@example.invalid ", "password", "NZ"),
        ("rus", "ru", " synthetic-account ", "password", "RU"),
        ("cn", "ignored", "synthetic-cn-account", None, "CN"),
    ],
)
def test_cloud_credentials_normalize_without_secret_repr(
    region: str,
    country: str,
    account: str,
    password: str | None,
    expected_country: str,
) -> None:
    credentials = GwmCloudCredentials(region, country, account, password, _DEVICE_ID)

    assert credentials.country == expected_country
    assert credentials.account == account.strip()
    assert repr(credentials).startswith("<custom_components.gwm_ora.cloud_auth.GwmCloudCredentials")
    assert account.strip() not in repr(credentials)
    assert password is None or password not in repr(credentials)
    assert len(credentials.account_binding) == 64


def test_entry_contract_has_pseudonymous_unique_id_and_no_transient_state() -> None:
    credentials = GwmCloudCredentials(
        "eu",
        "DE",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
    )

    data = cloud_entry_data(credentials)
    unique_id = cloud_unique_id(credentials)

    assert data == {
        CONF_CONNECTION_TYPE: CONNECTION_TYPE_CLOUD,
        CONF_REGION: "eu",
        CONF_COUNTRY: "DE",
        CONF_ACCOUNT: "account@example.invalid",
        CONF_PASSWORD: "password",
    }
    assert "account@example.invalid" not in unique_id
    assert "password" not in unique_id
    assert _DEVICE_ID not in unique_id
    assert set(data).isdisjoint(
        {
            "access_token",
            "refresh_token",
            "verification_code",
            "certificate",
            "private_key",
            "device_id",
        }
    )
    assert cloud_entry_title("eu") == "GWM Europe"


def test_anz_authentication_method_is_explicit_and_legacy_compatible() -> None:
    legacy = GwmCloudCredentials(
        "aus",
        "AU",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
    )
    current = GwmCloudCredentials(
        "aus",
        "NZ",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
        ANZ_AUTHENTICATION_METHOD_CURRENT,
    )

    assert legacy.authentication_method == ANZ_AUTHENTICATION_METHOD_LEGACY
    assert isinstance(legacy.client_credentials(), AnzCredentials)
    assert legacy.client_credentials().authentication_method is AnzAuthenticationMethod.LEGACY
    assert current.client_credentials().authentication_method is AnzAuthenticationMethod.CURRENT
    assert cloud_entry_data(current)[CONF_AUTHENTICATION_METHOD] == (ANZ_AUTHENTICATION_METHOD_CURRENT)
    assert cloud_unique_id(current) == cloud_unique_id(legacy)


def test_non_anz_credentials_reject_an_authentication_method() -> None:
    with pytest.raises(ValueError, match="^credentials_invalid$"):
        GwmCloudCredentials(
            "eu",
            "DE",
            "account@example.invalid",
            "password",
            _DEVICE_ID,
            ANZ_AUTHENTICATION_METHOD_CURRENT,
        )


def test_bundled_bootstrap_loader_is_region_scoped_and_offline() -> None:
    assert isinstance(_load_bootstrap_material("eu"), EuBootstrapMaterial)
    assert _load_bootstrap_material("aus") is None
    assert isinstance(_load_bootstrap_material("rus"), RussiaBootstrapMaterial)


class _OverseasClient:
    def __init__(self, config: GwmClientConfig, result: object) -> None:
        self.config = config
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    async def authenticate_eu(self, credentials: object, **kwargs: Any) -> object:
        self.calls.append(("eu", kwargs))
        return self.result

    async def authenticate_anz(self, credentials: object, **kwargs: Any) -> object:
        self.calls.append(("aus", kwargs))
        return self.result

    async def authenticate_russia(self, credentials: object, **kwargs: Any) -> object:
        self.calls.append(("rus", kwargs))
        return self.result

    async def aclose(self) -> None:
        self.closed = True


class _ChinaClient:
    def __init__(self, config: ChinaClientConfig, result: object) -> None:
        self.config = config
        self.result = result
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    async def authenticate(self, credentials: object, **kwargs: Any) -> object:
        self.calls.append(kwargs)
        return self.result

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("region", "country", "account", "password"),
    [
        ("eu", "DE", "account@example.invalid", "password"),
        ("aus", "AU", "account@example.invalid", "password"),
        ("rus", "RU", "synthetic-account", "password"),
    ],
)
async def test_overseas_attempt_dispatches_and_always_closes(
    region: str,
    country: str,
    account: str,
    password: str,
) -> None:
    marker = object()
    clients: list[_OverseasClient] = []

    def factory(config: GwmClientConfig) -> Any:
        client = _OverseasClient(config, marker)
        clients.append(client)
        return client

    authenticator = GwmCloudAuthenticator(overseas_client_factory=factory)
    credentials = GwmCloudCredentials(region, country, account, password, _DEVICE_ID)

    result = await authenticator.async_authenticate(
        credentials,
        verification_code="123456",
        allow_session_reclaim=region == "aus",
    )

    assert result is marker
    assert clients[0].config.region.value == region
    assert clients[0].config.anz_authentication_method == (
        ANZ_AUTHENTICATION_METHOD_LEGACY if region == "aus" else None
    )
    assert clients[0].calls[0][0] == region
    assert clients[0].calls[0][1]["verification_code"] == "123456"
    if region != "aus":
        assert clients[0].calls[0][1]["allow_password_login"] is True
    assert clients[0].closed


@pytest.mark.asyncio
async def test_current_anz_method_reaches_the_temporary_authentication_client() -> None:
    marker = object()
    clients: list[_OverseasClient] = []

    def factory(config: GwmClientConfig) -> Any:
        client = _OverseasClient(config, marker)
        clients.append(client)
        return client

    credentials = GwmCloudCredentials(
        "aus",
        "AU",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
        ANZ_AUTHENTICATION_METHOD_CURRENT,
    )

    result = await GwmCloudAuthenticator(overseas_client_factory=factory).async_authenticate(
        credentials,
        allow_session_reclaim=True,
    )

    assert result is marker
    assert clients[0].config.anz_authentication_method == ANZ_AUTHENTICATION_METHOD_CURRENT


@pytest.mark.asyncio
@pytest.mark.parametrize("region", ["eu", "rus"])
async def test_resume_only_flag_reaches_overseas_client(region: str) -> None:
    marker = object()
    clients: list[_OverseasClient] = []

    def factory(config: GwmClientConfig) -> Any:
        client = _OverseasClient(config, marker)
        clients.append(client)
        return client

    authenticator = GwmCloudAuthenticator(overseas_client_factory=factory)
    credentials = GwmCloudCredentials(
        region,
        "DE" if region == "eu" else "RU",
        "private-account",
        "private-password",
        _DEVICE_ID,
    )

    assert (
        await authenticator.async_authenticate(
            credentials,
            allow_password_login=False,
        )
        is marker
    )
    assert clients[0].calls[0][1]["allow_password_login"] is False


@pytest.mark.asyncio
async def test_china_attempt_dispatches_without_loading_overseas_material() -> None:
    marker = object()
    clients: list[_ChinaClient] = []

    def factory(config: ChinaClientConfig) -> Any:
        client = _ChinaClient(config, marker)
        clients.append(client)
        return client

    def forbidden_loader(region: str) -> None:
        pytest.fail(f"overseas resources loaded for {region}")

    authenticator = GwmCloudAuthenticator(
        china_client_factory=factory,
        resource_loader=forbidden_loader,
    )
    credentials = GwmCloudCredentials(
        "cn",
        "CN",
        "synthetic-cn-account",
        None,
        _DEVICE_ID,
    )

    result = await authenticator.async_authenticate(credentials, verification_code="123456")

    assert result is marker
    assert clients[0].calls[0]["verification_code"] == "123456"
    assert clients[0].calls[0]["allow_sms_login"] is True
    assert clients[0].closed


@pytest.mark.asyncio
async def test_china_restart_maps_no_password_login_to_no_sms_fallback() -> None:
    marker = object()
    clients: list[_ChinaClient] = []

    def factory(config: ChinaClientConfig) -> Any:
        client = _ChinaClient(config, marker)
        clients.append(client)
        return client

    authenticator = GwmCloudAuthenticator(china_client_factory=factory)
    credentials = GwmCloudCredentials(
        "cn",
        "CN",
        "13800138000",
        None,
        _DEVICE_ID,
    )
    state = ChinaAuthState.for_credentials(credentials.client_credentials())

    result = await authenticator.async_authenticate(
        credentials,
        state=state,
        allow_password_login=False,
    )

    assert result is marker
    assert clients[0].calls[0]["state"] == state
    assert clients[0].calls[0]["allow_sms_login"] is False
    assert clients[0].closed


@pytest.mark.asyncio
async def test_client_is_closed_when_authentication_fails() -> None:
    clients: list[_OverseasClient] = []

    class FailingClient(_OverseasClient):
        async def authenticate_anz(self, credentials: object, **kwargs: Any) -> object:
            raise GwmNetworkError(operation="login")

    def factory(config: GwmClientConfig) -> Any:
        client = FailingClient(config, object())
        clients.append(client)
        return client

    authenticator = GwmCloudAuthenticator(overseas_client_factory=factory)
    credentials = GwmCloudCredentials(
        "aus",
        "AU",
        "account@example.invalid",
        "password",
        _DEVICE_ID,
    )

    with pytest.raises(GwmNetworkError):
        await authenticator.async_authenticate(credentials)
    assert clients[0].closed
