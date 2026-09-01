"""Diagnostics support for GWM."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import GwmConfigEntry
from .const import (
    CONF_ACCOUNT,
    CONF_BEANTECH_ENCRYPTED_SECURITY_PIN,
    CONF_PASSWORD,
    CONF_SECURITY_PIN,
)

TO_REDACT = {
    CONF_ACCOUNT,
    CONF_BEANTECH_ENCRYPTED_SECURITY_PIN,
    CONF_PASSWORD,
    CONF_SECURITY_PIN,
    "access_token",
    "account_binding",
    "auto_ai_gw_id",
    "auto_ai_token_id",
    "auto_ai_user_id",
    "authentication_context_binding",
    "bean_id",
    "bean_tech_access_token",
    "bean_tech_bean_id",
    "bean_tech_refresh_token",
    "bean_tech_sso_token",
    "ca_bundle",
    "certificate",
    "certificate_data",
    "cloud_command_id",
    "command_journal",
    "context_binding",
    "device_id",
    "email",
    "g_refresh_token",
    "g_token",
    "gw_id",
    "issued_identity",
    "journal_id",
    "latitude",
    "location",
    "longitude",
    "phone",
    "private_key",
    "pt_token",
    "refresh_token",
    "sso_token",
    "serial_number",
    "token",
    "unique_id",
    "user_id",
    "username",
    "vehicle_id",
    "verification_code",
    "vin",
    "transformed_private_key_data",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    data = {
        "entry": {
            "data": dict(entry.data),
            "options": dict(entry.options),
            "title": entry.title,
            "unique_id": entry.unique_id,
        },
        "vehicles": entry.runtime_data.coordinator.data,
    }
    return async_redact_data(data, TO_REDACT)
