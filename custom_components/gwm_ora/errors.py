"""Home Assistant-facing errors for the GWM integration."""

from __future__ import annotations

from .const import REGION_BR, REGION_RUSSIA
from .gwm_client.errors import GwmAuthenticationError, is_russia_session_rejected


def cloud_authentication_message(region: str, error: GwmAuthenticationError) -> str:
    """Describe a rejected session using fixed text, never a server message."""

    if region == REGION_BR and error.api_code == "607501":
        return (
            "GWM reports that this account signed in on another device (API code 607501). "
            "Reauthenticate in Home Assistant to reconnect."
        )
    if region == REGION_RUSSIA and is_russia_session_rejected(error):
        reason = (
            "GWM reports that this account signed in on another device"
            if error.api_code == "607501"
            else "GWM invalidated this Russian session after a protocol change"
        )
        return (
            f"{reason} (API code {error.api_code}). Sign in to the same account in the "
            "GWM Android mobile app, complete any pending prompts, then sign out and "
            "reauthenticate in Home Assistant. Use a separate account for Home Assistant."
        )
    return "GWM cloud authentication was rejected"


class GwmCommandError(Exception):
    """Raised when a command cannot be validated or completed."""


class GwmCommandForbidden(GwmCommandError):
    """Raised when an explicitly disabled command surface is used."""
