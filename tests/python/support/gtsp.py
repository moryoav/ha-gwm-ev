"""Synthetic GTSP telemetry at the public status-mapping boundary."""
from custom_components.gwm_ora.gwm_client import china_gtsp
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier

VIN = "LGWTEST0000000001"

IDENTIFIER = VehicleIdentifier(VIN)

SECRET = "PRIVATE-RESPONSE-OR-TOKEN-MUST-NOT-LEAK"

LOGGER = "custom_components.gwm_ora.gwm_client.china_gtsp"

def payload(status=None, **kwargs):
    return {
        "code": "000000", "data": {
            "vehicleStatusInfo": {"powerBatteryPercent": "65", "evContnsDistance": "125"} if status is None else status,
            **kwargs,
        },
    }

def mapped(status, **kwargs):
    return china_gtsp.map_gtsp_status(
        payload(status, **kwargs)["data"], identifier=IDENTIFIER, vehicle_id=None,
    )
