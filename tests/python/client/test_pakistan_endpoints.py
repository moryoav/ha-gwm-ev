"""Verify the Pakistan read-only endpoint allowlist."""

from __future__ import annotations

import pytest

from custom_components.gwm_ora.gwm_client.pakistan_endpoints import pakistan_endpoint
from custom_components.gwm_ora.gwm_client.regions import GatewayRole


def test_allowed_reads_and_authentication_are_fixed() -> None:
    assert pakistan_endpoint("login").method == "POST"
    assert pakistan_endpoint("login").gateway is GatewayRole.AUTH_V2
    assert pakistan_endpoint("enroll_certificate").gateway is GatewayRole.CERTIFICATE_V1
    assert pakistan_endpoint("acquire_vehicles").path == "globalapp/vehicle/acquireVehicles"
    assert pakistan_endpoint("get_last_status").method == "GET"
    assert pakistan_endpoint("get_last_status").gateway is GatewayRole.APP_V1


@pytest.mark.parametrize(
    "operation",
    ["send_command", "send_climate_command", "send_lock_command", "set_charging_plan", "charge_now", "unknown"],
)
def test_writes_and_unknown_operations_are_denied(operation: str) -> None:
    with pytest.raises(ValueError, match="^pakistan_operation_not_supported$"):
        pakistan_endpoint(operation)
