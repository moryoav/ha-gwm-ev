"""GWM native integration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    ServiceValidationError,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.util import dt as dt_util

from gwm_client import (
    AnzAuthenticated,
    ChinaAuthenticated,
    ChinaInitializationRequired,
    EuAuthenticated,
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    RussiaAuthenticated,
)

from .cloud_auth import GwmCloudAuthenticator
from .cloud_commands import GwmCommandApi
from .cloud_runtime import (
    GwmCloudBootstrap,
    GwmCloudClient,
    consume_cloud_bootstrap,
    stage_cloud_bootstrap,
)
from .cloud_storage import (
    GwmCloudStateStore,
    async_remove_cloud_state,
    cloud_state_store,
    credentials_for_auth_state,
)
from .const import (
    ATTR_END_TIME,
    ATTR_START_TIME,
    ATTR_VIN,
    CONF_CONNECTION_TYPE,
    CONF_ENABLE_CHARGING_CONTROL,
    CONF_ENABLE_REMOTE_COMMANDS,
    CONF_POLL_INTERVAL_SECONDS,
    CONF_REGION,
    CONF_SECURITY_PIN,
    CONNECTION_TYPE_CLOUD,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DOMAIN,
    MIN_CHARGE_WINDOW_MINUTES,
    PLATFORMS,
    REGION_CHINA,
    SERVICE_CLEAR_CHARGING_PLAN,
    SERVICE_SET_CHARGING_PLAN,
)
from .coordinator import GwmDataUpdateCoordinator
from .entity import async_call_gwm_api


@dataclass(slots=True)
class GwmRuntimeData:
    """Runtime data for a GWM config entry."""

    api: GwmCommandApi
    coordinator: GwmDataUpdateCoordinator
    cloud: GwmCloudClient
    state_store: GwmCloudStateStore


GwmConfigEntry = ConfigEntry[GwmRuntimeData]


_SET_CHARGING_PLAN_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_VIN): cv.string,
        vol.Required(ATTR_START_TIME): cv.datetime,
        vol.Required(ATTR_END_TIME): cv.datetime,
    }
)
_CLEAR_CHARGING_PLAN_SCHEMA = vol.Schema({vol.Required(ATTR_VIN): cv.string})


def _charging_window_epoch_ms(start, end) -> tuple[int, int]:
    """Validate a charging window and return UTC Unix milliseconds."""
    start_utc = dt_util.as_utc(start)
    end_utc = dt_util.as_utc(end)
    if end_utc - start_utc < timedelta(minutes=MIN_CHARGE_WINDOW_MINUTES):
        raise ServiceValidationError(
            f"Charging plan window must be at least {MIN_CHARGE_WINDOW_MINUTES} minutes"
        )

    return (
        int(dt_util.as_timestamp(start_utc) * 1000),
        int(dt_util.as_timestamp(end_utc) * 1000),
    )


def _async_register_services(hass: HomeAssistant) -> None:
    """Register the charging-plan services (once)."""
    if hass.services.has_service(DOMAIN, SERVICE_SET_CHARGING_PLAN):
        return

    def _resolve_for_vin(
        vin: str,
    ) -> tuple[GwmCommandApi, GwmDataUpdateCoordinator, str]:
        """Resolve a user-supplied VIN to its (api, internal VIN).

        Accepts either the display VIN (device serial) or the encoded VIN.
        """
        identifier = vin.strip()
        fallback = None
        for entry in hass.config_entries.async_loaded_entries(DOMAIN):
            vehicle = entry.runtime_data.coordinator.resolve_vehicle(identifier)
            if vehicle is not None:
                resolved = (
                    entry.runtime_data.api,
                    entry.runtime_data.coordinator,
                    vehicle["vin"],
                )
                capabilities = vehicle.get("capabilities") or {}
                charging_available = capabilities.get("charging_control") is True
                if charging_available:
                    return resolved
                if fallback is None:
                    fallback = resolved
        if fallback is not None:
            return fallback
        raise ServiceValidationError(f"No GWM vehicle found with VIN {identifier}")

    async def _set_charging_plan(call: ServiceCall) -> None:
        api, coordinator, resolved_vin = _resolve_for_vin(call.data[ATTR_VIN])
        start_ms, end_ms = _charging_window_epoch_ms(
            call.data[ATTR_START_TIME], call.data[ATTR_END_TIME]
        )
        await async_call_gwm_api(
            api.async_set_charging_plan(
                resolved_vin,
                enable=True,
                start_time=start_ms,
                end_time=end_ms,
                plan_type=0,
            ),
            forbidden_translation_key="charging_control_unavailable",
        )
        coordinator.set_charging_plan_active(resolved_vin, True)

    async def _clear_charging_plan(call: ServiceCall) -> None:
        api, coordinator, resolved_vin = _resolve_for_vin(call.data[ATTR_VIN])
        await async_call_gwm_api(
            api.async_set_charging_plan(resolved_vin, enable=False),
            forbidden_translation_key="charging_control_unavailable",
        )
        coordinator.set_charging_plan_active(resolved_vin, False)

    hass.services.async_register(
        DOMAIN, SERVICE_SET_CHARGING_PLAN, _set_charging_plan, schema=_SET_CHARGING_PLAN_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_CLEAR_CHARGING_PLAN, _clear_charging_plan, schema=_CLEAR_CHARGING_PLAN_SCHEMA
    )


async def async_setup_entry(hass: HomeAssistant, entry: GwmConfigEntry) -> bool:
    """Set up GWM from a config entry."""
    if entry.data.get(CONF_CONNECTION_TYPE) != CONNECTION_TYPE_CLOUD:
        raise ConfigEntryAuthFailed(
            "The retired add-on entry cannot be converted; remove it and add GWM again"
        )
    return await _async_setup_cloud_entry(hass, entry)


async def async_unload_entry(hass: HomeAssistant, entry: GwmConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False
    await entry.runtime_data.coordinator.async_cancel_command_tasks()
    cloud = entry.runtime_data.cloud
    if (
        (bootstrap := cloud.reusable_bootstrap) is not None
        and entry.unique_id is not None
    ):
        stage_cloud_bootstrap(hass, entry.unique_id, bootstrap)
    await cloud.aclose()
    return True


async def _async_setup_cloud_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
) -> bool:
    """Set up one restart-safe GWM cloud runtime."""

    if entry.unique_id is None:
        raise ConfigEntryAuthFailed("GWM cloud account identity is missing")
    try:
        state_store = cloud_state_store(hass, entry.unique_id)
    except (TypeError, ValueError) as err:
        raise ConfigEntryAuthFailed(
            "GWM cloud account identity is invalid"
        ) from err
    bootstrap = await _async_load_cloud_bootstrap(hass, entry, state_store)

    try:
        command_enabled = entry.options.get(CONF_ENABLE_REMOTE_COMMANDS) is True
        charging_enabled = entry.options.get(CONF_ENABLE_CHARGING_CONTROL) is True
        security_pin = entry.options.get(CONF_SECURITY_PIN)
        commands_available = command_enabled and (
            entry.data.get(CONF_REGION) == REGION_CHINA
            or isinstance(security_pin, str)
            and bool(security_pin.strip())
        )
        cloud = GwmCloudClient.from_entry_data(
            dict(entry.data),
            entry.unique_id,
            bootstrap,
            state_store=state_store,
            options=entry.options,
            climate_commands_enabled=commands_available,
            lock_window_commands_enabled=commands_available,
            charging_control_enabled=charging_enabled,
        )
    except (GwmConfigurationError, TypeError, ValueError) as err:
        raise ConfigEntryAuthFailed(
            "GWM cloud authentication handoff is invalid"
        ) from err

    try:
        credentials = credentials_for_auth_state(dict(entry.data), bootstrap.state)
        api = GwmCommandApi(
            cloud,
            state_store,
            credentials,
            enabled=command_enabled,
            charging_enabled=charging_enabled,
            security_pin=security_pin if isinstance(security_pin, str) else None,
        )
    except (TypeError, ValueError) as err:
        await cloud.aclose()
        raise ConfigEntryAuthFailed("GWM command context is invalid") from err
    coordinator = GwmDataUpdateCoordinator(
        hass,
        api,
        config_entry=entry,
        cloud_client=cloud,
        update_interval_seconds=int(
            entry.options.get(
                CONF_POLL_INTERVAL_SECONDS,
                DEFAULT_POLL_INTERVAL_SECONDS,
            )
        ),
    )
    try:
        await coordinator.async_config_entry_first_refresh()
        for command in await api.async_restore(dict(entry.data)):
            coordinator.async_track_command(command)
        entry.runtime_data = GwmRuntimeData(
            api=api,
            coordinator=coordinator,
            cloud=cloud,
            state_store=state_store,
        )
        _async_register_services(hass)
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        await coordinator.async_cancel_command_tasks()
        if (
            (reusable := cloud.reusable_bootstrap) is not None
            and entry.unique_id is not None
        ):
            stage_cloud_bootstrap(hass, entry.unique_id, reusable)
        await cloud.aclose()
        raise
    return True


async def _async_load_cloud_bootstrap(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    state_store: GwmCloudStateStore,
) -> GwmCloudBootstrap:
    """Load or resume one account-bound session without a fresh login."""

    bootstrap = consume_cloud_bootstrap(hass, entry.unique_id)
    if bootstrap is not None:
        try:
            credentials = credentials_for_auth_state(dict(entry.data), bootstrap.state)
            await state_store.async_save_auth_state(credentials, bootstrap.state)
        except (TypeError, ValueError) as err:
            raise ConfigEntryAuthFailed(
                "GWM cloud authentication handoff is invalid"
            ) from err
        return bootstrap

    try:
        auth_state = await state_store.async_load_auth_state(dict(entry.data))
        if auth_state is None:
            raise ConfigEntryAuthFailed(
                "GWM cloud authentication must be renewed"
            )
        credentials = credentials_for_auth_state(dict(entry.data), auth_state)
    except ConfigEntryAuthFailed:
        raise
    except (TypeError, ValueError) as err:
        raise ConfigEntryAuthFailed(
            "GWM cloud authentication state is invalid"
        ) from err
    except Exception as err:
        raise ConfigEntryNotReady(
            "GWM cloud private state is temporarily unavailable"
        ) from err

    try:
        result = await GwmCloudAuthenticator().async_authenticate(
            credentials,
            state=auth_state,
            allow_session_reclaim=False,
            allow_password_login=False,
        )
        if isinstance(result, ChinaInitializationRequired):
            await state_store.async_save_auth_state(credentials, result.state)
            raise ConfigEntryNotReady(
                "GWM China downstream services require another initialization attempt"
            )
        if not isinstance(
            result,
            (
                EuAuthenticated,
                AnzAuthenticated,
                RussiaAuthenticated,
                ChinaAuthenticated,
            ),
        ):
            await state_store.async_clear_auth_state(dict(entry.data))
            raise ConfigEntryAuthFailed(
                "GWM cloud authentication requires user confirmation"
            )
        bootstrap = GwmCloudBootstrap.from_authentication(credentials, result)
        await state_store.async_save_auth_state(credentials, result.state)
        return bootstrap
    except ConfigEntryAuthFailed:
        raise
    except GwmAuthenticationError as err:
        await state_store.async_clear_auth_state(dict(entry.data))
        raise ConfigEntryAuthFailed(
            "GWM cloud authentication was rejected"
        ) from err
    except GwmClientError as err:
        raise ConfigEntryNotReady(
            f"GWM cloud {err.category} during {err.operation}"
        ) from err
    except (TypeError, ValueError) as err:
        await state_store.async_clear_auth_state(dict(entry.data))
        raise ConfigEntryAuthFailed(
            "GWM cloud authentication state is invalid"
        ) from err


async def async_remove_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
) -> None:
    """Remove private durable state with a deleted GWM config entry."""

    if entry.data.get(CONF_CONNECTION_TYPE) == CONNECTION_TYPE_CLOUD:
        await async_remove_cloud_state(hass, entry.unique_id)
