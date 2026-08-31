"""GWM cloud authentication boundary for native Home Assistant flows.

Every call owns and closes a short-lived protocol client. Immutable results are
published to the Home Assistant storage boundary by the caller; this module
never writes state or retains submitted verification codes.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from gwm_client import (
    AnzAuthenticationMethod,
    AnzAuthState,
    AnzCredentials,
    ChinaAuthState,
    ChinaClient,
    ChinaClientConfig,
    ChinaCredentials,
    EuAuthState,
    EuBootstrapMaterial,
    EuCredentials,
    GwmClient,
    GwmClientConfig,
    GwmConfigurationError,
    Region,
    RussiaAuthState,
    RussiaBootstrapMaterial,
    RussiaCredentials,
)
from gwm_client.anz_auth import AnzAuthenticationResult
from gwm_client.china_client import ChinaAuthenticationResult
from gwm_client.eu_auth import EuAuthenticationResult
from gwm_client.russia_auth import RussiaAuthenticationResult

from .const import (
    ANZ_AUTHENTICATION_METHOD_LEGACY,
    CONF_ACCOUNT,
    CONF_AUTHENTICATION_METHOD,
    CONF_CONNECTION_TYPE,
    CONF_COUNTRY,
    CONF_PASSWORD,
    CONF_REGION,
    CONNECTION_TYPE_CLOUD,
    REGION_ANZ,
    REGION_CHINA,
    REGION_EU,
    REGION_RUSSIA,
    SUPPORTED_CLOUD_REGIONS,
)

type ClientCredentials = EuCredentials | AnzCredentials | RussiaCredentials | ChinaCredentials
type CloudAuthState = EuAuthState | AnzAuthState | RussiaAuthState | ChinaAuthState
type CloudAuthenticationResult = (
    EuAuthenticationResult | AnzAuthenticationResult | RussiaAuthenticationResult | ChinaAuthenticationResult
)
type BootstrapMaterial = EuBootstrapMaterial | RussiaBootstrapMaterial | None
type OverseasClientFactory = Callable[[GwmClientConfig], GwmClient]
type ChinaClientFactory = Callable[[ChinaClientConfig], ChinaClient]
type ResourceLoader = Callable[[str], BootstrapMaterial]

_RESOURCE_DIRECTORY = Path(__file__).resolve().parent / "resources"


@dataclass(frozen=True, slots=True, repr=False)
class GwmCloudCredentials:
    """Normalized account configuration plus one flow-local device identity."""

    region: str
    country: str
    account: str = field(repr=False)
    password: str | None = field(default=None, repr=False)
    device_id: str = field(default="", repr=False)
    authentication_method: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.region, str):
            raise ValueError("credentials_invalid")
        region = self.region.strip().lower()
        if region not in SUPPORTED_CLOUD_REGIONS:
            raise ValueError("credentials_invalid")
        object.__setattr__(self, "region", region)

        if region == REGION_ANZ:
            try:
                authentication_method = AnzAuthenticationMethod(
                    self.authentication_method or ANZ_AUTHENTICATION_METHOD_LEGACY
                )
            except ValueError:
                raise ValueError("credentials_invalid") from None
            object.__setattr__(self, "authentication_method", authentication_method.value)
        elif self.authentication_method not in (None, ""):
            raise ValueError("credentials_invalid")
        else:
            object.__setattr__(self, "authentication_method", None)

        credentials = self.client_credentials()
        if isinstance(credentials, ChinaCredentials):
            object.__setattr__(self, "country", "CN")
            object.__setattr__(self, "account", credentials.phone)
            object.__setattr__(self, "password", None)
        else:
            object.__setattr__(self, "country", credentials.country)
            object.__setattr__(self, "account", credentials.account)
            object.__setattr__(self, "password", credentials.password)
        object.__setattr__(self, "device_id", credentials.device_id)

    def client_credentials(self) -> ClientCredentials:
        """Return the exact regional credential model for one client call."""

        if self.region == REGION_EU:
            return EuCredentials(
                account=self.account,
                password=_required_password(self.password),
                country=self.country,
                device_id=self.device_id,
            )
        if self.region == REGION_ANZ:
            return AnzCredentials(
                account=self.account,
                password=_required_password(self.password),
                country=self.country,
                device_id=self.device_id,
                authentication_method=(self.authentication_method or ANZ_AUTHENTICATION_METHOD_LEGACY),
            )
        if self.region == REGION_RUSSIA:
            return RussiaCredentials(
                account=self.account,
                password=_required_password(self.password),
                country=self.country,
                device_id=self.device_id,
            )
        if self.region == REGION_CHINA:
            if self.password not in (None, ""):
                raise ValueError("credentials_invalid")
            return ChinaCredentials(phone=self.account, device_id=self.device_id)
        raise ValueError("credentials_invalid")

    @property
    def account_binding(self) -> str:
        """Return the regional domain-separated pseudonymous account binding."""

        return self.client_credentials().account_binding


class GwmCloudAuthenticator:
    """Run one finite regional authentication attempt with owned resources."""

    def __init__(
        self,
        *,
        overseas_client_factory: OverseasClientFactory | None = None,
        china_client_factory: ChinaClientFactory | None = None,
        resource_loader: ResourceLoader | None = None,
    ) -> None:
        self._overseas_client_factory = overseas_client_factory or GwmClient
        self._china_client_factory = china_client_factory or ChinaClient
        self._resource_loader = resource_loader or _load_bootstrap_material

    async def async_authenticate(
        self,
        credentials: GwmCloudCredentials,
        *,
        state: CloudAuthState | None = None,
        verification_code: str | None = None,
        allow_session_reclaim: bool = False,
        allow_password_login: bool = True,
    ) -> CloudAuthenticationResult:
        """Authenticate once and close the temporary protocol client."""

        if (
            type(credentials) is not GwmCloudCredentials
            or type(allow_session_reclaim) is not bool
            or type(allow_password_login) is not bool
            or (allow_session_reclaim and not allow_password_login)
        ):
            raise GwmConfigurationError(operation="login")

        regional_credentials = credentials.client_credentials()
        if credentials.region == REGION_CHINA:
            if state is not None and type(state) is not ChinaAuthState:
                raise GwmConfigurationError(operation="login")
            client = self._china_client_factory(ChinaClientConfig())
            try:
                assert isinstance(regional_credentials, ChinaCredentials)
                return await client.authenticate(
                    regional_credentials,
                    state=state,
                    verification_code=verification_code,
                    allow_sms_login=allow_password_login,
                )
            finally:
                await client.aclose()

        material = await self._async_load_material(credentials.region)
        client = self._overseas_client_factory(
            GwmClientConfig(
                _overseas_region(credentials.region),
                anz_authentication_method=(
                    credentials.authentication_method if credentials.region == REGION_ANZ else None
                ),
            )
        )
        try:
            if credentials.region == REGION_EU:
                if state is not None and type(state) is not EuAuthState:
                    raise GwmConfigurationError(operation="login")
                if type(material) is not EuBootstrapMaterial or not isinstance(regional_credentials, EuCredentials):
                    raise GwmConfigurationError(operation="login")
                return await client.authenticate_eu(
                    regional_credentials,
                    state=state,
                    verification_code=verification_code,
                    allow_password_login=allow_password_login,
                    ca_bundle=material.ca_bundle,
                    bootstrap_material=material,
                )
            if credentials.region == REGION_ANZ:
                if state is not None and type(state) is not AnzAuthState:
                    raise GwmConfigurationError(operation="login")
                if material is not None or not isinstance(regional_credentials, AnzCredentials):
                    raise GwmConfigurationError(operation="login")
                return await client.authenticate_anz(
                    regional_credentials,
                    state=state,
                    verification_code=verification_code,
                    allow_session_reclaim=allow_session_reclaim,
                )
            if credentials.region == REGION_RUSSIA:
                if state is not None and type(state) is not RussiaAuthState:
                    raise GwmConfigurationError(operation="login")
                if type(material) is not RussiaBootstrapMaterial or not isinstance(
                    regional_credentials, RussiaCredentials
                ):
                    raise GwmConfigurationError(operation="login")
                return await client.authenticate_russia(
                    regional_credentials,
                    state=state,
                    verification_code=verification_code,
                    allow_password_login=allow_password_login,
                    bootstrap_material=material,
                )
            raise GwmConfigurationError(operation="login")
        finally:
            await client.aclose()

    async def _async_load_material(self, region: str) -> BootstrapMaterial:
        try:
            return await asyncio.to_thread(self._resource_loader, region)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise GwmConfigurationError(operation="login") from None


def generate_device_id() -> str:
    """Return a cryptographically random flow-local 32-character identity."""

    return secrets.token_hex(16)


def cloud_entry_data(credentials: GwmCloudCredentials) -> dict[str, object]:
    """Return normalized user configuration without transient auth state."""

    data: dict[str, object] = {
        CONF_CONNECTION_TYPE: CONNECTION_TYPE_CLOUD,
        CONF_REGION: credentials.region,
        CONF_COUNTRY: credentials.country,
        CONF_ACCOUNT: credentials.account,
    }
    if credentials.password is not None:
        data[CONF_PASSWORD] = credentials.password
    if credentials.region == REGION_ANZ:
        data[CONF_AUTHENTICATION_METHOD] = credentials.authentication_method
    return data


def cloud_unique_id(credentials: GwmCloudCredentials) -> str:
    """Return a domain-separated pseudonymous ID for one region/account pair."""

    return f"cloud:{credentials.region}:{credentials.account_binding}"


def cloud_entry_title(region: str) -> str:
    """Return a non-personal title for one GWM cloud entry."""

    names = {
        REGION_EU: "GWM Europe",
        REGION_ANZ: "GWM Australia / New Zealand",
        REGION_RUSSIA: "GWM Russia",
        REGION_CHINA: "GWM China",
    }
    try:
        return names[region]
    except KeyError:
        raise ValueError("region_invalid") from None


def _required_password(value: str | None) -> str:
    if not isinstance(value, str):
        raise ValueError("credentials_invalid")
    return value


def _overseas_region(region: str) -> Region:
    try:
        return Region(region)
    except ValueError:
        raise GwmConfigurationError(operation="login") from None


def _load_bootstrap_material(region: str) -> BootstrapMaterial:
    if region == REGION_ANZ:
        return None
    if region == REGION_EU:
        return EuBootstrapMaterial(
            certificate_data=(_RESOURCE_DIRECTORY / "gwm_general.cer").read_bytes(),
            transformed_private_key_data=(_RESOURCE_DIRECTORY / "gwm_general.key").read_bytes(),
            ca_bundle=(_RESOURCE_DIRECTORY / "gwm_root.pem").read_bytes(),
        )
    if region == REGION_RUSSIA:
        return RussiaBootstrapMaterial(
            certificate_data=(_RESOURCE_DIRECTORY / "gwm_general_rus.cer").read_bytes(),
            transformed_private_key_data=(_RESOURCE_DIRECTORY / "gwm_general_rus.key").read_bytes(),
            ca_bundle=(_RESOURCE_DIRECTORY / "gwm_root_rus.pem").read_bytes(),
        )
    raise GwmConfigurationError(operation="login")


__all__ = [
    "CloudAuthenticationResult",
    "CloudAuthState",
    "GwmCloudAuthenticator",
    "GwmCloudCredentials",
    "cloud_entry_data",
    "cloud_entry_title",
    "cloud_unique_id",
    "generate_device_id",
]
