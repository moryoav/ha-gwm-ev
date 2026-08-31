"""Base entities for GWM."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from gwm_client import GwmAuthenticationError, GwmClientError

from .const import DOMAIN
from .coordinator import GwmDataUpdateCoordinator
from .errors import GwmCommandError, GwmCommandForbidden

if TYPE_CHECKING:
    from . import GwmConfigEntry


class GwmEntity(CoordinatorEntity[GwmDataUpdateCoordinator]):
    """Base entity bound to one GWM vehicle."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: GwmDataUpdateCoordinator, vin: str) -> None:
        super().__init__(coordinator)
        self.vin = vin

    @property
    def vehicle(self) -> dict[str, Any] | None:
        """Return the current vehicle snapshot."""
        return self.coordinator.vehicle(self.vin)

    @property
    def available(self) -> bool:
        """Return whether the entity is available."""
        return super().available and self.vehicle is not None

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry info."""
        vehicle = self.vehicle or {}
        return DeviceInfo(
            identifiers={(DOMAIN, self.vin)},
            name=vehicle.get("name") or "GWM vehicle",
            manufacturer=vehicle.get("manufacturer") or "GWM",
            model=vehicle.get("model"),
            serial_number=vehicle.get("serial_number"),
        )

    @property
    def remote_commands_available(self) -> bool:
        """Return whether remote commands are available for this vehicle."""
        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return bool(capabilities.get("remote_commands"))

    @property
    def climate_commands_available(self) -> bool:
        """Return the climate-specific capability."""

        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return capabilities.get("climate_commands") is True

    @property
    def lock_window_commands_available(self) -> bool:
        """Return the lock/window capability."""

        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return capabilities.get("lock_window_commands") is True

    @property
    def front_defroster_commands_available(self) -> bool:
        """Return the capability for the overseas front-defroster control."""

        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return capabilities.get("front_defroster_commands") is True

    @property
    def cabin_clean_commands_available(self) -> bool:
        """Return the capability for the overseas air-circulation action."""

        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return capabilities.get("cabin_clean_commands") is True

    @property
    def china_vehicle_commands_available(self) -> bool:
        """Return the extended-China capability."""

        vehicle = self.vehicle or {}
        capabilities = vehicle.get("capabilities") or {}
        return capabilities.get("china_vehicle_commands") is True

    @property
    def vehicle_platform(self) -> str:
        """Return the normalized vehicle backend platform."""
        return str((self.vehicle or {}).get("platform") or "").lower()

    @property
    def is_china_beantech(self) -> bool:
        """Return whether this is a BeanTech vehicle on the China gateway."""
        return self.coordinator.region == "cn" and self.vehicle_platform == "beantech"

    @property
    def charging_control_available(self) -> bool:
        """Return whether charging control is available for this vehicle."""
        return _vehicle_charging_control_available(
            self.vehicle,
        )


def _vehicle_charging_control_available(
    vehicle: dict[str, Any] | None,
) -> bool:
    """Return the per-vehicle charging capability."""
    capabilities = (vehicle or {}).get("capabilities") or {}
    return capabilities.get("charging_control") is True


def vehicle_value(vehicle: dict[str, Any] | None, key: str) -> Any:
    """Return a value from a vehicle snapshot."""
    if vehicle is None:
        return None
    return (vehicle.get("values") or {}).get(key)


def setup_vehicle_entities(
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
    factory: Callable[[dict[str, Any]], Iterable[GwmEntity]],
) -> None:
    """Add entities for all current and newly discovered vehicles."""
    coordinator = entry.runtime_data.coordinator
    known_vins: set[str] = set()

    def add_new_vehicle_entities() -> None:
        entities: list[GwmEntity] = []
        for vehicle in coordinator.vehicles:
            vin = vehicle.get("vin")
            if not vin or vin in known_vins:
                continue
            known_vins.add(vin)
            entities.extend(factory(vehicle))
        if entities:
            async_add_entities(entities)

    add_new_vehicle_entities()
    entry.async_on_unload(coordinator.async_add_listener(add_new_vehicle_entities))


async def async_call_gwm_api(
    call,
    *,
    forbidden_translation_key: str = "remote_command_unavailable",
):
    """Call the GWM client and raise translated Home Assistant errors."""
    try:
        return await call
    except GwmAuthenticationError as err:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="cloud_auth_failed",
        ) from err
    except GwmCommandForbidden as err:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key=forbidden_translation_key,
        ) from err
    except (GwmCommandError, GwmClientError) as err:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="cloud_request_failed",
        ) from err
