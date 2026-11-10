"""Offline mainland-China client behavior and protocol contracts."""

from __future__ import annotations

import pytest
from support.china import (
    BEAN_FIXTURE,
    BEAN_VIN,
    CODE,
    FIXTURE,
    UNSUPPORTED_VIN,
    VIN,
    _assert_request,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
    _response,
    _success_plans,
)

from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthenticated,
    ChinaVehicle,
    ChinaVehicleStatus,
)
from custom_components.gwm_ora.gwm_client.errors import (
    GwmAuthenticationError,
    GwmRoutePolicyError,
)
from custom_components.gwm_ora.gwm_client.models import CloudVehicle, CloudVehicleStatus, VehicleIdentifier


@pytest.mark.asyncio
async def test_discovery_and_status_return_cloud_compatible_typed_privacy_minimized_models() -> None:
    plans = _success_plans()
    plans["get_last_status"] = [
        FIXTURE["responses"]["status"],
        BEAN_FIXTURE["response"],
    ]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), verification_code=CODE)
    assert isinstance(authenticated, ChinaAuthenticated)

    status = await client.get_last_status(VehicleIdentifier(VIN))
    assert isinstance(status, ChinaVehicleStatus)
    assert isinstance(status, CloudVehicleStatus)
    values = {item.code: item.value for item in status.items}
    assert values["2013021"] == "78"
    assert values["2011501"] == "204"
    assert values["2103010"] == "56040"
    assert values["2208001"] == "0"
    assert status.latitude == 0.0
    assert status.longitude == 0.0
    assert "vehicleSts" not in repr(status)
    assert VIN not in repr(status)
    _assert_request(transport.calls[-1], "get_last_status")

    bean_status = await client.get_last_status(VehicleIdentifier(BEAN_VIN))
    bean_values = {item.code: item.value for item in bean_status.items}
    assert bean_values["2013021"] == "71"
    assert bean_values["2011501"] == "75"
    assert bean_values["2103010"] == "22883"
    assert bean_values["9000011"] == "82.5"
    assert bean_values["9000024"] == "90"
    assert bean_values["9000025"] == "68"
    assert bean_status.latitude == 1.25
    assert bean_status.longitude == -2.5
    assert BEAN_VIN not in repr(bean_status)
    expected = BEAN_FIXTURE["request"]
    request = transport.calls[-1]
    assert request.method == expected["method"]
    assert request.service == expected["service"]
    assert request.url == expected["url"]
    assert dict(request.headers) == expected["headers"]
    assert request.body is None


@pytest.mark.asyncio
async def test_discovery_models_retain_only_safe_mapping_metadata_and_navinfo_is_enforced() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[
            FIXTURE["responses"]["discovery"],
            FIXTURE["responses"]["discovery"],
        ]
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    vehicles = await client.acquire_vehicles()
    assert all(isinstance(vehicle, ChinaVehicle | CloudVehicle) for vehicle in vehicles)
    assert vehicles[0].platform == "navinfo"
    assert vehicles[0].network_type == 2
    assert vehicles[0].tank_capacity == 56.0
    assert vehicles[2].platform == "beantech"
    assert VIN not in repr(vehicles[0])

    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_last_status(VehicleIdentifier(UNSUPPORTED_VIN))
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("tank_capacity", ["not-a-number", -1, True, [], "NaN", 10**400])
async def test_optional_tank_capacity_quirks_do_not_reject_discovery(tank_capacity: object) -> None:
    discovery = {
        "code": "000000",
        "data": {
            "acquireVehiclesList": [
                {
                    "vin": VIN,
                    "vehicleId": "synthetic-vehicle-1",
                    "belongPlatform": "navinfo",
                    "vehicleNetworkType": 2,
                    "tankCapacity": tank_capacity,
                }
            ]
        },
    }
    transport = _FakeTransport(acquire_vehicles=[discovery, discovery])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)

    vehicles = await client.acquire_vehicles()

    assert vehicles[0].tank_capacity is None


@pytest.mark.asyncio
async def test_status_auth_rejection_revokes_read_eligibility_and_session() -> None:
    plans = _success_plans()
    plans["get_last_status"] = [_response({}, status=401)]
    transport = _FakeTransport(**plans)
    client = _client(transport)
    await client.authenticate(_credentials(), verification_code=CODE)
    with pytest.raises(GwmAuthenticationError):
        await client.get_last_status(VehicleIdentifier(VIN))
    assert not client.authenticated
    with pytest.raises(GwmAuthenticationError):
        await client.acquire_vehicles()
