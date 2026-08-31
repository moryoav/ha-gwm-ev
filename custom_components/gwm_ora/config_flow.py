"""Config, verification, reauthentication, reconfigure, and options flows."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry, ConfigFlowResult
from homeassistant.helpers import selector

from gwm_client import (
    AnzAuthenticated,
    AnzSessionReclaimRequired,
    AnzVerificationRequired,
    ChinaAuthenticated,
    ChinaInitializationRequired,
    ChinaRiskControlRequired,
    ChinaVerificationRequired,
    EuAuthenticated,
    EuIdentityError,
    EuVerificationRequired,
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmRateLimitError,
    GwmTransportError,
    RussiaAuthenticated,
    RussiaIdentityError,
    RussiaVerificationRequired,
)

from .cloud_auth import (
    CloudAuthenticationResult,
    CloudAuthState,
    GwmCloudAuthenticator,
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_entry_title,
    cloud_unique_id,
    generate_device_id,
)
from .cloud_runtime import (
    GwmCloudBootstrap,
    stage_cloud_bootstrap,
)
from .cloud_storage import (
    async_remove_cloud_state,
    cloud_state_store,
    credentials_for_auth_state,
)
from .const import (
    CONF_ACCOUNT,
    CONF_ALLOW_SESSION_RECLAIM,
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
    DEFAULT_LOG_LEVEL,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DOMAIN,
    LOG_LEVELS,
    MAX_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    REGION_ANZ,
    REGION_CHINA,
    REGION_EU,
    REGION_RUSSIA,
    SUPPORTED_CLOUD_REGIONS,
)

_REGION_OPTIONS = [
    {"value": REGION_EU, "label": "Europe"},
    {"value": REGION_ANZ, "label": "Australia / New Zealand"},
    {"value": REGION_RUSSIA, "label": "Russia"},
    {"value": REGION_CHINA, "label": "Mainland China"},
]
_DEFAULT_COUNTRIES = {
    REGION_EU: "DE",
    REGION_ANZ: "AU",
    REGION_RUSSIA: "RU",
    REGION_CHINA: "CN",
}
_AUTHENTICATED_TYPES = (
    EuAuthenticated,
    AnzAuthenticated,
    RussiaAuthenticated,
    ChinaAuthenticated,
)
_VERIFICATION_TYPES = (
    EuVerificationRequired,
    AnzVerificationRequired,
    RussiaVerificationRequired,
    ChinaVerificationRequired,
)


def _password_selector(*, autocomplete: str = "current-password") -> selector.TextSelector:
    return selector.TextSelector(
        selector.TextSelectorConfig(
            type=selector.TextSelectorType.PASSWORD,
            autocomplete=autocomplete,
        )
    )


def _region_schema(default: str = REGION_EU) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_REGION, default=default): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=_REGION_OPTIONS,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            )
        }
    )


def _account_schema(
    region: str,
    defaults: dict[str, Any] | None = None,
) -> vol.Schema:
    defaults = defaults or {}
    fields: dict[vol.Marker, object] = {}
    if region == REGION_EU:
        fields[vol.Required(CONF_COUNTRY, default=defaults.get(CONF_COUNTRY, "DE"))] = (
            selector.CountrySelector()
        )
    elif region == REGION_ANZ:
        fields[vol.Required(CONF_COUNTRY, default=defaults.get(CONF_COUNTRY, "AU"))] = (
            selector.CountrySelector(selector.CountrySelectorConfig(countries=["AU", "NZ"]))
        )

    fields[vol.Required(CONF_ACCOUNT, default=defaults.get(CONF_ACCOUNT, ""))] = str
    if region != REGION_CHINA:
        fields[vol.Required(CONF_PASSWORD)] = _password_selector()
    return vol.Schema(fields)


def _verification_schema() -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_VERIFICATION_CODE): _password_selector(
                autocomplete="one-time-code"
            )
        }
    )


def _cloud_options_schema(entry: ConfigEntry, defaults: dict[str, Any] | None = None) -> vol.Schema:
    current = {**entry.options, **(defaults or {})}
    region = str(entry.data.get(CONF_REGION, ""))
    fields: dict[vol.Marker, object] = {
        vol.Required(
            CONF_POLL_INTERVAL_SECONDS,
            default=current.get(CONF_POLL_INTERVAL_SECONDS, DEFAULT_POLL_INTERVAL_SECONDS),
        ): vol.All(
            vol.Coerce(int),
            vol.Range(min=MIN_POLL_INTERVAL_SECONDS, max=MAX_POLL_INTERVAL_SECONDS),
        ),
        vol.Required(
            CONF_ENABLE_REMOTE_COMMANDS,
            default=current.get(CONF_ENABLE_REMOTE_COMMANDS, False),
        ): bool,
        vol.Required(
            CONF_ENABLE_CHARGING_CONTROL,
            default=current.get(CONF_ENABLE_CHARGING_CONTROL, False),
        ): bool,
        vol.Required(
            CONF_LOG_LEVEL,
            default=current.get(CONF_LOG_LEVEL, DEFAULT_LOG_LEVEL),
        ): vol.In(LOG_LEVELS),
    }
    if region != REGION_CHINA:
        fields[
            vol.Optional(
                CONF_SECURITY_PIN,
                # The password selector masks this value while still allowing
                # an administrator to reveal or replace the configured PIN.
                default=current.get(CONF_SECURITY_PIN, ""),
            )
        ] = _password_selector(autocomplete="off")
    return vol.Schema(fields)


def _is_cloud(data: dict[str, Any] | ConfigEntry | Any) -> bool:
    entry_data = data.data if isinstance(data, ConfigEntry) else data
    return entry_data.get(CONF_CONNECTION_TYPE) == CONNECTION_TYPE_CLOUD


class GwmConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle native GWM cloud account flows."""

    VERSION = 1

    def __init__(self) -> None:
        self._cloud_authenticator: GwmCloudAuthenticator | None = None
        self._cloud_mode = "user"
        self._cloud_region: str | None = None
        self._cloud_credentials: GwmCloudCredentials | None = None
        self._auth_state: CloudAuthState | None = None
        self._anz_session_reclaim_confirmed = False
        self._initialization_failures: tuple[str, ...] = ()

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> GwmOptionsFlow:
        """Return the GWM options flow."""

        return GwmOptionsFlow()

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Select the GWM cloud region used by the account."""

        if user_input is None:
            self._cloud_mode = "user"
            return self.async_show_form(step_id="user", data_schema=_region_schema())

        region = str(user_input.get(CONF_REGION, "")).strip().lower()
        if region not in CONFIGURABLE_CLOUD_REGIONS:
            return self.async_show_form(
                step_id="user",
                data_schema=_region_schema(),
                errors={CONF_REGION: "unsupported_region"},
            )
        self._cloud_region = region
        self._auth_state = None
        self._anz_session_reclaim_confirmed = False
        return await self.async_step_account()

    async def async_step_account(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Collect and validate the selected regional account."""

        if self._cloud_region not in SUPPORTED_CLOUD_REGIONS:
            return self.async_abort(reason="invalid_flow_state")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                self._cloud_credentials = self._credentials_from_input(
                    self._cloud_region,
                    user_input,
                )
                self._auth_state = None
                self._anz_session_reclaim_confirmed = False
                early_result = await self._async_restore_cloud_state()
            except (TypeError, ValueError):
                errors["base"] = "invalid_account"
            else:
                if early_result is not None:
                    return early_result
                result, error = await self._async_authenticate()
                if error:
                    errors["base"] = error
                elif result is not None:
                    return await self._async_route_authentication(result)

        return self.async_show_form(
            step_id="account",
            data_schema=_account_schema(self._cloud_region, user_input),
            errors=errors,
        )

    async def async_step_verification(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Submit one non-persistent verification code continuation."""

        if self._cloud_credentials is None or self._auth_state is None:
            return self.async_abort(reason="invalid_flow_state")
        errors: dict[str, str] = {}
        if user_input is not None:
            code = user_input.get(CONF_VERIFICATION_CODE)
            result, error = await self._async_authenticate(
                verification_code=code,
                allow_session_reclaim=self._anz_session_reclaim_confirmed,
            )
            if error:
                errors[CONF_VERIFICATION_CODE if error == "invalid_verification_code" else "base"] = error
            elif result is not None:
                return await self._async_route_authentication(result)
        return self._show_verification(errors)

    async def async_step_session_reclaim(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Require explicit consent before an ANZ password login claims the session."""

        if self._cloud_credentials is None or self._auth_state is None:
            return self.async_abort(reason="invalid_flow_state")
        errors: dict[str, str] = {}
        if user_input is not None:
            if user_input.get(CONF_ALLOW_SESSION_RECLAIM) is not True:
                errors[CONF_ALLOW_SESSION_RECLAIM] = "session_reclaim_not_confirmed"
            else:
                self._anz_session_reclaim_confirmed = True
                result, error = await self._async_authenticate(allow_session_reclaim=True)
                if error:
                    self._anz_session_reclaim_confirmed = False
                    errors["base"] = error
                elif result is not None:
                    return await self._async_route_authentication(result)
        return self.async_show_form(
            step_id="session_reclaim",
            data_schema=vol.Schema({vol.Optional(CONF_ALLOW_SESSION_RECLAIM, default=False): bool}),
            errors=errors,
        )

    async def async_step_initialization(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Retry a recoverable China downstream-service initialization."""

        if self._cloud_credentials is None or self._auth_state is None:
            return self.async_abort(reason="invalid_flow_state")
        errors: dict[str, str] = {}
        if user_input is not None:
            result, error = await self._async_authenticate()
            if error:
                errors["base"] = error
            elif result is not None:
                if isinstance(result, ChinaInitializationRequired):
                    errors["base"] = "initialization_failed"
                return await self._async_route_authentication(result, errors=errors)
        return self._show_initialization(errors)

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Handle GWM cloud authentication failure."""

        if not _is_cloud(entry_data):
            return self.async_abort(reason="legacy_addon_entry")
        self._cloud_mode = "reauth"
        self._cloud_region = str(entry_data.get(CONF_REGION, ""))
        self._auth_state = None
        self._anz_session_reclaim_confirmed = False
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Reconnect the current GWM cloud account."""

        entry = self._get_reauth_entry()
        if not _is_cloud(entry):
            return self.async_abort(reason="legacy_addon_entry")

        region = str(entry.data.get(CONF_REGION, ""))
        if region not in SUPPORTED_CLOUD_REGIONS:
            return self.async_abort(reason="invalid_flow_state")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                password = None if region == REGION_CHINA else user_input.get(CONF_PASSWORD)
                self._cloud_credentials = GwmCloudCredentials(
                    region=region,
                    country=str(entry.data.get(CONF_COUNTRY, _DEFAULT_COUNTRIES[region])),
                    account=str(entry.data.get(CONF_ACCOUNT, "")),
                    password=password,
                    device_id=generate_device_id(),
                )
                self._auth_state = None
                self._anz_session_reclaim_confirmed = False
                early_result = await self._async_restore_cloud_state()
            except (TypeError, ValueError):
                errors["base"] = "invalid_account"
            else:
                if early_result is not None:
                    return early_result
                result, error = await self._async_authenticate()
                if error:
                    errors["base"] = error
                elif result is not None:
                    return await self._async_route_authentication(result)

        schema = (
            vol.Schema({})
            if region == REGION_CHINA
            else vol.Schema({vol.Required(CONF_PASSWORD): _password_selector()})
        )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_reconfigure(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Reconfigure the GWM cloud account."""

        entry = self._get_reconfigure_entry()
        if not _is_cloud(entry):
            return self.async_abort(reason="legacy_addon_entry")

        self._cloud_mode = "reconfigure"
        if user_input is None:
            return self.async_show_form(
                step_id="reconfigure",
                data_schema=_region_schema(str(entry.data.get(CONF_REGION, REGION_EU))),
            )
        region = str(user_input.get(CONF_REGION, "")).strip().lower()
        if region not in CONFIGURABLE_CLOUD_REGIONS:
            return self.async_show_form(
                step_id="reconfigure",
                data_schema=_region_schema(),
                errors={CONF_REGION: "unsupported_region"},
            )
        self._cloud_region = region
        self._auth_state = None
        self._anz_session_reclaim_confirmed = False
        return await self.async_step_reconfigure_account()

    async def async_step_reconfigure_account(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Authenticate replacement account settings before applying them."""

        entry = self._get_reconfigure_entry()
        if self._cloud_region not in SUPPORTED_CLOUD_REGIONS:
            return self.async_abort(reason="invalid_flow_state")
        defaults = (
            dict(entry.data)
            if self._cloud_region == entry.data.get(CONF_REGION)
            else {CONF_COUNTRY: _DEFAULT_COUNTRIES[self._cloud_region]}
        )
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                self._cloud_credentials = self._credentials_from_input(
                    self._cloud_region,
                    user_input,
                )
                self._auth_state = None
                self._anz_session_reclaim_confirmed = False
                early_result = await self._async_restore_cloud_state()
            except (TypeError, ValueError):
                errors["base"] = "invalid_account"
            else:
                if early_result is not None:
                    return early_result
                result, error = await self._async_authenticate()
                if error:
                    errors["base"] = error
                elif result is not None:
                    return await self._async_route_authentication(result)
        return self.async_show_form(
            step_id="reconfigure_account",
            data_schema=_account_schema(self._cloud_region, {**defaults, **(user_input or {})}),
            errors=errors,
        )

    def _credentials_from_input(
        self,
        region: str,
        user_input: dict[str, Any],
    ) -> GwmCloudCredentials:
        return GwmCloudCredentials(
            region=region,
            country=str(user_input.get(CONF_COUNTRY, _DEFAULT_COUNTRIES[region])),
            account=user_input[CONF_ACCOUNT],
            password=None if region == REGION_CHINA else user_input.get(CONF_PASSWORD),
            device_id=generate_device_id(),
        )

    async def _async_authenticate(
        self,
        *,
        verification_code: object = None,
        allow_session_reclaim: bool = False,
    ) -> tuple[CloudAuthenticationResult | None, str]:
        credentials = self._cloud_credentials
        if credentials is None:
            return None, "invalid_account"
        if self._cloud_authenticator is None:
            self._cloud_authenticator = GwmCloudAuthenticator()
        try:
            result = await self._cloud_authenticator.async_authenticate(
                credentials,
                state=self._auth_state,
                verification_code=(
                    verification_code if isinstance(verification_code, str) else None
                ),
                allow_session_reclaim=allow_session_reclaim,
            )
        except GwmRateLimitError:
            return None, "rate_limited"
        except GwmAuthenticationError:
            return None, (
                "invalid_verification_code" if verification_code is not None else "invalid_auth"
            )
        except GwmTransportError:
            return None, "cannot_connect"
        except (GwmConfigurationError, EuIdentityError, RussiaIdentityError):
            return None, "local_configuration_error"
        except GwmApiError:
            return None, "service_error"
        except GwmClientError:
            return None, "service_error"
        except (TypeError, ValueError):
            return None, "invalid_account"
        return result, ""

    async def _async_route_authentication(
        self,
        result: CloudAuthenticationResult,
        *,
        errors: dict[str, str] | None = None,
    ) -> ConfigFlowResult:
        if isinstance(result, _AUTHENTICATED_TYPES):
            return await self._async_finish_cloud(result)
        if isinstance(result, _VERIFICATION_TYPES):
            await self._async_persist_auth_state(result.state)
            self._auth_state = result.state
            verification_errors = dict(errors or {})
            if result.code_rejected:
                verification_errors[CONF_VERIFICATION_CODE] = "invalid_verification_code"
            return self._show_verification(verification_errors)
        if isinstance(result, AnzSessionReclaimRequired):
            await self._async_persist_auth_state(result.state)
            self._auth_state = result.state
            self._anz_session_reclaim_confirmed = False
            return self.async_show_form(
                step_id="session_reclaim",
                data_schema=vol.Schema(
                    {vol.Optional(CONF_ALLOW_SESSION_RECLAIM, default=False): bool}
                ),
                errors=errors,
            )
        if isinstance(result, ChinaInitializationRequired):
            await self._async_persist_auth_state(result.state)
            self._auth_state = result.state
            self._initialization_failures = result.failures
            return self._show_initialization(errors)
        if isinstance(result, ChinaRiskControlRequired):
            await self._async_clear_persisted_auth_state()
            self._auth_state = None
            return self.async_abort(reason="risk_control_required")
        return self.async_abort(reason="invalid_flow_state")

    async def _async_restore_cloud_state(self) -> ConfigFlowResult | None:
        """Restore a matching continuation before one explicit flow attempt."""

        credentials = self._cloud_credentials
        if credentials is None:
            return self.async_abort(reason="invalid_flow_state")
        unique_id = cloud_unique_id(credentials)
        if self._cloud_mode == "user":
            await self.async_set_unique_id(unique_id)
            self._abort_if_unique_id_configured()
        elif self._cloud_mode == "reauth":
            if self._get_reauth_entry().unique_id != unique_id:
                return self.async_abort(reason="invalid_flow_state")
        elif self._cloud_mode == "reconfigure":
            entry = self._get_reconfigure_entry()
            duplicate = self.hass.config_entries.async_entry_for_domain_unique_id(
                DOMAIN,
                unique_id,
            )
            if duplicate is not None and duplicate.entry_id != entry.entry_id:
                return self.async_abort(reason="already_configured")
        else:
            return self.async_abort(reason="invalid_flow_state")

        state = await cloud_state_store(
            self.hass,
            unique_id,
        ).async_load_auth_state(cloud_entry_data(credentials))
        if state is not None:
            self._cloud_credentials = credentials_for_auth_state(
                cloud_entry_data(credentials),
                state,
            )
            self._auth_state = state
        return None

    async def _async_persist_auth_state(self, state: CloudAuthState) -> None:
        credentials = self._cloud_credentials
        if credentials is None:
            raise ValueError("invalid_flow_state")
        await cloud_state_store(
            self.hass,
            cloud_unique_id(credentials),
        ).async_save_auth_state(credentials, state)

    async def _async_clear_persisted_auth_state(self) -> None:
        credentials = self._cloud_credentials
        if credentials is None:
            return
        await cloud_state_store(
            self.hass,
            cloud_unique_id(credentials),
        ).async_clear_auth_state(cloud_entry_data(credentials))

    async def _async_finish_cloud(
        self,
        result: CloudAuthenticationResult,
    ) -> ConfigFlowResult:
        credentials = self._cloud_credentials
        if credentials is None:
            return self.async_abort(reason="invalid_flow_state")
        data = cloud_entry_data(credentials)
        unique_id = cloud_unique_id(credentials)
        title = cloud_entry_title(credentials.region)
        try:
            bootstrap = GwmCloudBootstrap.from_authentication(credentials, result)
        except GwmConfigurationError:
            return self.async_abort(reason="invalid_flow_state")
        self._auth_state = None
        self._anz_session_reclaim_confirmed = False

        if self._cloud_mode == "user":
            await self.async_set_unique_id(unique_id)
            self._abort_if_unique_id_configured()
            await cloud_state_store(
                self.hass,
                unique_id,
            ).async_save_auth_state(credentials, result.state)
            stage_cloud_bootstrap(self.hass, unique_id, bootstrap)
            self._cloud_credentials = None
            return self.async_create_entry(title=title, data=data)

        if self._cloud_mode == "reauth":
            entry = self._get_reauth_entry()
            if entry.unique_id != unique_id:
                return self.async_abort(reason="invalid_flow_state")
            await cloud_state_store(
                self.hass,
                unique_id,
            ).async_save_auth_state(credentials, result.state)
            stage_cloud_bootstrap(self.hass, unique_id, bootstrap)
            self._cloud_credentials = None
            return self.async_update_reload_and_abort(
                entry,
                data={**entry.data, **data},
                title=title,
            )

        if self._cloud_mode == "reconfigure":
            entry = self._get_reconfigure_entry()
            previous_unique_id = entry.unique_id
            duplicate = self.hass.config_entries.async_entry_for_domain_unique_id(
                DOMAIN,
                unique_id,
            )
            if duplicate is not None and duplicate.entry_id != entry.entry_id:
                return self.async_abort(reason="already_configured")
            await cloud_state_store(
                self.hass,
                unique_id,
            ).async_save_auth_state(credentials, result.state)
            stage_cloud_bootstrap(self.hass, unique_id, bootstrap)
            flow_result = self.async_update_reload_and_abort(
                entry,
                unique_id=unique_id,
                title=title,
                data=data,
            )
            if previous_unique_id != unique_id:
                await async_remove_cloud_state(self.hass, previous_unique_id)
            self._cloud_credentials = None
            return flow_result
        return self.async_abort(reason="invalid_flow_state")

    def _show_verification(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="verification",
            data_schema=_verification_schema(),
            errors=errors,
        )

    def _show_initialization(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="initialization",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={
                "failure_count": str(len(self._initialization_failures))
            },
        )

class GwmOptionsFlow(config_entries.OptionsFlowWithReload):
    """Configure GWM cloud polling and opt-in controls."""

    async def async_step_init(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        entry = self.config_entry
        if not _is_cloud(entry):
            return self.async_abort(reason="legacy_addon_entry")

        errors: dict[str, str] = {}
        if user_input is not None:
            normalized = dict(user_input)
            pin = normalized.get(CONF_SECURITY_PIN)
            normalized_pin = pin.strip() if isinstance(pin, str) else ""
            existing_pin = entry.options.get(CONF_SECURITY_PIN)
            preserved_pin = existing_pin.strip() if isinstance(existing_pin, str) else ""
            if (
                entry.data.get(CONF_REGION) != REGION_CHINA
                and normalized.get(CONF_ENABLE_REMOTE_COMMANDS) is True
                and not (normalized_pin or preserved_pin)
            ):
                errors[CONF_SECURITY_PIN] = "security_pin_required"
            else:
                if (
                    entry.data.get(CONF_REGION) == REGION_CHINA
                    or normalized.get(CONF_ENABLE_REMOTE_COMMANDS) is not True
                ):
                    normalized.pop(CONF_SECURITY_PIN, None)
                elif normalized_pin:
                    normalized[CONF_SECURITY_PIN] = normalized_pin
                else:
                    normalized[CONF_SECURITY_PIN] = preserved_pin
                return self.async_create_entry(data=normalized)

        return self.async_show_form(
            step_id="init",
            data_schema=_cloud_options_schema(entry, user_input),
            errors=errors,
        )
