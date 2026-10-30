"""Verify the APAC read-only endpoint allowlist."""

from __future__ import annotations

import pytest

from custom_components.gwm_ora.gwm_client.apac_endpoints import apac_endpoint
from custom_components.gwm_ora.gwm_client.regions import GatewayRole


def test_allowed_reads_and_authentication_are_fixed() -> None:
    """Keep authentication and vehicle-read routes fixed by operation."""
    assert apac_endpoint("login").method == "POST"
    assert apac_endpoint("login").gateway is GatewayRole.AUTH_V2
    assert apac_endpoint("enroll_certificate").gateway is GatewayRole.CERTIFICATE_V1
    assert apac_endpoint("acquire_vehicles").path == "globalapp/vehicle/acquireVehicles"
    assert apac_endpoint("get_last_status").method == "GET"
    assert apac_endpoint("get_last_status").gateway is GatewayRole.APP_V1


@pytest.mark.parametrize(
    "operation",
    ["send_command", "send_climate_command", "send_lock_command", "set_charging_plan", "charge_now", "unknown"],
)
def test_writes_and_unknown_operations_are_denied(operation: str) -> None:
    """Reject vehicle controls and unknown operations at the allowlist."""
    with pytest.raises(ValueError, match="^apac_operation_not_supported$"):
        apac_endpoint(operation)
