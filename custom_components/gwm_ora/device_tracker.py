"""Device tracker platform for GWM."""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker.const import SourceType
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

try:
    from homeassistant.components.device_tracker import TrackerEntity
except ImportError:  # pragma: no cover - compatibility with older supported HA releases
    from homeassistant.components.device_tracker.config_entry import TrackerEntity

from . import GwmConfigEntry
from .entity import GwmEntity, setup_vehicle_entities

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GwmConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up GWM device trackers."""
    setup_vehicle_entities(
        entry,
        async_add_entities,
        lambda vehicle: (
            GwmDeviceTracker(entry.runtime_data.coordinator, vehicle["vin"]),
        ),
    )


class GwmDeviceTracker(GwmEntity, TrackerEntity):
    """A vehicle GPS tracker."""

    _attr_translation_key = "location"

    def __init__(self, coordinator, vin: str) -> None:
        super().__init__(coordinator, vin)
        self._attr_unique_id = f"{vin}_location"

    @property
    def location(self) -> dict[str, Any] | None:
        """Return the location snapshot."""
        vehicle = self.vehicle or {}
        return vehicle.get("location")

    @property
    def latitude(self) -> float | None:
        """Return latitude."""
        location = self.location
        return None if location is None else location.get("latitude")

    @property
    def longitude(self) -> float | None:
        """Return longitude."""
        location = self.location
        return None if location is None else location.get("longitude")

    @property
    def source_type(self) -> SourceType:
        """Return source type."""
        return SourceType.GPS
