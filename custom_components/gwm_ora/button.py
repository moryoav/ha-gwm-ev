"""Button platform for GWM."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GwmConfigEntry
from .entity import GwmEntity, async_call_gwm_api, setup_vehicle_entities

PARALLEL_UPDATES = 0

CHINA_REMOTE_BUTTONS: tuple[tuple[str, str], ...] = (
    ("remote_start", "remote_start"),
    ("remote_stop", "remote_stop"),
    ("horn", "sound_horn"),
    ("flash_lights", "flash_lights"),
    ("horn_and_lights", "horn_and_lights"),
    ("tailgate_open", "open_tailgate"),
    ("tailgate_close", "close_tailgate"),
    ("sunroof_close", "close_sunroof"),
    ("sunroof_tilt", "tilt_sunroof"),
    ("sunroof_half", "half_open_sunroof"),
    ("sunroof_full", "fully_open_sunroof"),
    ("cabin_purge", "cabin_purge"),
    ("force_refresh", "force_refresh"),
)

BEANTECH_REMOTE_ACTIONS = {
    "horn",
    "flash_lights",
    "horn_and_lights",
    "sunroof_close",
}


def _china_remote_buttons_for_vehicle(
    vehicle: dict,
) -> tuple[tuple[str, str], ...]:
    """Return remote buttons mapped for the vehicle platform."""
    platform = str(vehicle.get("platform") or "").lower()
    if platform == "navinfo":
        return CHINA_REMOTE_BUTTONS
    if platform == "beantech":
        return tuple(
            item for item in CHINA_REMOTE_BUTTONS if item[0] in BEANTECH_REMOTE_ACTIONS
        )
    return ()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM buttons."""

    def entities_for_vehicle(vehicle):
        vin = vehicle["vin"]
        entities = [
            GwmCloseWindowsButton(
                entry.runtime_data.api,
                entry.runtime_data.coordinator,
                vin,
            ),
        ]
        if entry.runtime_data.coordinator.region != "cn":
            # The overseas air-circulation button has no BeanTech equivalent: the
            # BeanTech cabin clean is exposed as a comfort button instead.
            entities.append(
                GwmCabinCleanButton(
                    entry.runtime_data.api,
                    entry.runtime_data.coordinator,
                    vin,
                )
            )
        if entry.runtime_data.coordinator.region == "cn":
            entities.extend(
                GwmChinaRemoteButton(
                    entry.runtime_data.api,
                    entry.runtime_data.coordinator,
                    vin,
                    action,
                    translation_key,
                )
                for action, translation_key in _china_remote_buttons_for_vehicle(vehicle)
            )
            entities.extend(
                GwmBeanTechComfortButton(
                    entry.runtime_data.api,
                    entry.runtime_data.coordinator,
                    vin,
                    action,
                    translation_key,
                )
                for action, translation_key in (
                    ("comfort_warm", "comfort_warm"),
                    ("comfort_cool", "comfort_cool"),
                    ("comfort_off", "comfort_off"),
                )
            )
        return entities

    setup_vehicle_entities(
        entry,
        async_add_entities,
        entities_for_vehicle,
    )


class GwmCloseWindowsButton(GwmEntity, ButtonEntity):
    """Button that closes all windows."""

    _attr_translation_key = "close_windows"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_close_windows"

    @property
    def available(self) -> bool:
        """Return whether close-window commands are available."""
        return super().available and self.lock_window_commands_available

    async def async_press(self) -> None:
        """Close windows."""
        command = await async_call_gwm_api(self._api.async_close_windows(self.vin))
        self.coordinator.async_track_command(command)


class GwmCabinCleanButton(GwmEntity, ButtonEntity):
    """Run the overseas app's 60-second external-air circulation action."""

    _attr_translation_key = "start_air_circulation"

    def __init__(self, api, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._attr_unique_id = f"{vin}_cabin_clean"

    @property
    def available(self) -> bool:
        """Return whether this vehicle reports the air-circulation feature."""
        return super().available and self.cabin_clean_commands_available

    async def async_press(self) -> None:
        """Start the fixed 60-second air-circulation action."""
        command = await async_call_gwm_api(
            self._api.async_start_cabin_clean(self.vin)
        )
        self.coordinator.async_track_command(command)


class GwmChinaRemoteButton(GwmEntity, ButtonEntity):
    """Experimental China-only remote-control button."""

    def __init__(self, api, coordinator, vin: str, action: str, translation_key: str) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._action = action
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{action}"

    @property
    def available(self) -> bool:
        """Return whether this China command is available."""
        return (
            super().available
            and self.china_vehicle_commands_available
            and self.coordinator.region == "cn"
            and self._action
            in {
                action
                for action, _translation_key in _china_remote_buttons_for_vehicle(
                    self.vehicle or {}
                )
            }
        )

    async def async_press(self) -> None:
        """Queue the configured China remote command."""
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._action)
        )
        self.coordinator.async_track_command(command)


class GwmBeanTechComfortButton(GwmEntity, ButtonEntity):
    """BeanTech comfort action button.

    Covers the fixed-duration cabin clean and the one-touch comfort modes
    (warm, cool, and all-off). Cabin clean and the single-command comfort modes
    are PIN-exempt, so they only need the capability and platform gates. The
    one-touch ``comfort_off`` sends a multi-command ``sendType=1`` sequence that
    can only travel the PIN-gated timely path, so it still requires a configured
    PIN.
    """

    def __init__(
        self, api, coordinator, vin: str, action: str, translation_key: str
    ) -> None:
        super().__init__(coordinator, vin)
        self._api = api
        self._action = action
        self._attr_translation_key = translation_key
        self._attr_unique_id = f"{vin}_{translation_key}"

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.china_vehicle_commands_available
            and self.is_china_beantech
            and (self._action != "comfort_off" or self.security_pin_configured)
        )

    async def async_press(self) -> None:
        """Queue the configured BeanTech comfort command."""
        command = await async_call_gwm_api(
            self._api.async_vehicle_control(self.vin, self._action)
        )
        self.coordinator.async_track_command(command)
