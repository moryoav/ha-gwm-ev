"""Synthetic APAC tailgate, steering and charging request contracts."""

import asyncio
import json
import ssl
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.gwm_ora.button import GwmApacControlButton
from custom_components.gwm_ora.cloud_runtime import GwmCloudClient
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_controls import control_payload, validate_control_payload
from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.errors import GwmRoutePolicyError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.models import CloudVehicle, VehicleIdentifier, parse_cloud_vehicles
from custom_components.gwm_ora.gwm_client.regions import TlsMode


@pytest.mark.parametrize(("action", "instruction", "value"), [
    ("tailgate_open", "0x09", {"switchOrder": "1", "operationTime": "0"}),
    ("tailgate_close", "0x09", {"switchOrder": "2", "operationTime": "0"}),
    ("charge_now", "0x01", {"switchOrder": "1"}),
    ("charge_off", "0x01", {"switchOrder": "2"}),
    ("steering_wheel_heating", "0x19", {"operationTime": "15", "switchOrder": "1"}),
    ("steering_wheel_heatless", "0x19", {"operationTime": "0", "switchOrder": "2"}),
    ("lock", "0x05", {"operationTime": "0", "switchOrder": "2"}),
    ("unlock", "0x05", {"operationTime": "0", "switchOrder": "1"}),
    ("close_windows", "0x08", {"switchOrder": "2", "window": {"leftFront": "0", "leftBack": "0", "rightFront": "0", "rightBack": "0", "skyLight": ""}}),
    ("horn", "0x06", {"search": {"whistle": "1", "flashing": "0"}}),
    ("flash_lights", "0x06", {"search": {"whistle": "0", "flashing": "1"}}),
    ("horn_and_lights", "0x06", {"search": {"whistle": "1", "flashing": "1"}}),
    ("sunroof_close", "0x08", {"window": {"skyLight": 0}}),
    ("defrost_front_start", "0x0B", {"defrost": {"defrostFront": 1, "operationTime": "15", "switchOrder": "1"}}),
    ("defrost_front_stop", "0x0B", {"defrost": {"defrostFront": 0, "operationTime": "0", "switchOrder": "2"}}),
    ("defrost_back_start", "0x0B", {"defrost": {"switchOrder": "1", "operationTime": "15", "defrostBack": "1"}}),
    ("defrost_back_stop", "0x0B", {"defrost": {"switchOrder": "2", "defrostBack": "1"}}),
    ("cabin_clean", "0x11", {"operationTime": "60", "switchOrder": "1"}),
    ("remote_start", "0x04", {"airConditioner": {"operationTime": "15", "switchOrder": "1", "temperature": "22"}}),
    ("remote_stop", "0x04", {"airConditioner": {"operationTime": "0", "switchOrder": "2"}}),
])
def test_control_payload_matches_prior_apac_contract(action, instruction, value):
    """Compare the result with the corresponding prior working request."""
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    payload = control_payload(vehicle, action, security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")
    assert payload == {
        "instructions": {instruction: value}, "remoteType": "0", "securityPassword": "a" * 32,
        "seqNo": "b" * 32 + "1234", "type": 2, "vin": vehicle.value,
    }
    validate_control_payload(payload, vehicle.value)


def test_unknown_or_modified_control_is_rejected():
    """Reject unknown actions and mixed vehicle instructions before dispatch."""
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    with pytest.raises(ValueError):
        control_payload(vehicle, "unknown", security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")
    payload = control_payload(vehicle, "charge_now", security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")
    payload["instructions"]["0x09"] = {"switchOrder": "1", "operationTime": "0"}
    with pytest.raises(ValueError):
        validate_control_payload(payload, vehicle.value)


@pytest.mark.parametrize(("driver_right", "action", "key"), [
    (True, "seat_heating_start", "rightFront"), (True, "seat_heating_start_passenger", "leftFront"),
    (False, "seat_heating_start", "leftFront"), (False, "seat_heating_start_passenger", "rightFront"),
])
def test_seat_heating_follows_reported_driver_side(driver_right, action, key):
    """Use the same driver/passenger mapping as the earlier APAC package."""
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    payload = control_payload(vehicle, action, security_password_hash="a" * 32, sequence_number="b" * 32 + "1234", driver_right=driver_right)
    assert payload["instructions"]["0x0A"]["seat"][key] == "3"
    validate_control_payload(payload, vehicle.value)
    with pytest.raises(ValueError):
        control_payload(vehicle, action, security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")


def test_seat_stop_matches_prior_all_seat_payload():
    """Document that the previous app contract stops front and rear seats together."""
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    payload = control_payload(vehicle, "seat_heating_stop", security_password_hash="a" * 32, sequence_number="b" * 32 + "1234", driver_right=True)
    assert payload["instructions"]["0x0A"]["seat"] == {
        "operationMode": "1", "switchOrder": "2", "operationTime": "0",
        "leftFront": "0", "rightFront": "0", "leftBack": "0", "rightBack": "0",
    }


def test_driver_side_is_only_parsed_when_apac_requests_it():
    """Keep the other regions' discovery behavior unchanged."""
    data = [{"vin": "SYNTHETIC-VEHICLE", "rudder": "2"}]
    assert parse_cloud_vehicles(data, allow_numbers_for_strings=True, include_rudder=True)[0].rudder == "2"
    assert parse_cloud_vehicles(data, allow_numbers_for_strings=True)[0].rudder is None


@pytest.mark.asyncio
async def test_charging_and_remote_opt_ins_are_independent():
    """Charging consent must not grant tailgate access, or vice versa."""
    class Transport:
        def __init__(self): self.requests = []
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": {}}).encode())
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_charging_enabled=True)
    cloud._vehicles[vehicle.value] = CloudVehicle(vehicle, platform="beantech")
    with pytest.raises(GwmRoutePolicyError):
        await cloud.async_send_apac_control(vehicle, "tailgate_open", security_password_hash="a" * 32)
    assert not transport.requests
    accepted = await cloud.async_send_apac_control(vehicle, "charge_now", security_password_hash="a" * 32)
    assert json.loads(transport.requests[0].body)["instructions"] == {"0x01": {"switchOrder": "1"}}
    assert accepted.command_id


@pytest.mark.asyncio
async def test_seat_command_rejects_unknown_driver_side_without_sending():
    """Never guess the physical seat when discovery omits steering position."""
    class Transport:
        def __init__(self): self.requests = []
        async def execute(self, request, **kwargs): self.requests.append(request)
    context = ssl.create_default_context()
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_remote_enabled=True)
    cloud._vehicles[vehicle.value] = CloudVehicle(vehicle, platform="beantech")
    with pytest.raises(GwmRoutePolicyError):
        await cloud.async_send_apac_control(vehicle, "seat_heating_start", security_password_hash="a" * 32)
    assert transport.requests == []


@pytest.mark.asyncio
async def test_direct_charging_timeout_does_not_resend():
    """An uncertain charging response must never trigger a duplicate write."""
    from custom_components.gwm_ora.gwm_client.errors import GwmDeadlineExceededError

    class Transport:
        def __init__(self): self.calls = 0
        async def execute(self, request, **kwargs):
            self.calls += 1
            raise TimeoutError
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_charging_enabled=True)
    cloud._vehicles[vehicle.value] = CloudVehicle(vehicle, platform="beantech")
    with pytest.raises(GwmDeadlineExceededError):
        await cloud.async_send_apac_control(vehicle, "charge_now", security_password_hash="a" * 32)
    assert transport.calls == 1


@pytest.mark.asyncio
async def test_shutdown_waits_for_active_apac_control():
    """Do not close the transport while an accepted write is still in flight."""
    class Transport:
        def __init__(self):
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.closed = False
        async def execute(self, request, **kwargs):
            self.started.set()
            await self.release.wait()
            assert not self.closed
            return _TransportResponse(200, {}, b'{"code":"000000","data":{}}')
        async def aclose(self): self.closed = True
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport, owns_transport=True)
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_charging_enabled=True)
    cloud._vehicles[vehicle.value] = CloudVehicle(vehicle, platform="beantech")
    write = asyncio.create_task(cloud.async_send_apac_control(vehicle, "charge_now", security_password_hash="a" * 32))
    await transport.started.wait()
    shutdown = asyncio.create_task(cloud.aclose())
    await asyncio.sleep(0)
    assert not shutdown.done() and not transport.closed
    transport.release.set()
    assert (await write).command_id
    await shutdown
    assert transport.closed


@pytest.mark.asyncio
async def test_apac_charging_button_requires_its_own_capability():
    """Test button visibility and dispatch without sending any vehicle request."""
    vehicle = {"capabilities": {"apac_remote_controls": True, "apac_direct_charging": False}}
    coordinator = SimpleNamespace(last_update_success=True, vehicle=lambda vin: vehicle, async_track_command=lambda command: None)
    api = SimpleNamespace(async_apac_control=AsyncMock(return_value={"id": "synthetic"}))
    button = GwmApacControlButton(api, coordinator, "SYNTHETIC-VEHICLE", "charge_now", "apac_charge_start")
    assert not button.available
    vehicle["capabilities"]["apac_direct_charging"] = True
    assert button.available
    await button.async_press()
    api.async_apac_control.assert_awaited_once_with("SYNTHETIC-VEHICLE", "charge_now")

@pytest.mark.asyncio
@pytest.mark.parametrize("platform", [None, "unknown", "navinfo", "BeanTech"])
@pytest.mark.parametrize("action", ["lock", "unlock", "charge_now", "seat_heating_start"])
async def test_apac_controls_require_the_supported_vehicle_platform(platform, action):
    """Reject unsupported platforms before any control request reaches transport."""
    class Transport:
        """Record calls without sending traffic to a real service."""
        def __init__(self):
            """Start with an empty transport history."""
            self.requests = []

        async def execute(self, request, **kwargs):
            """Return a synthetic acceptance for a permitted platform."""
            self.requests.append(request)
            return _TransportResponse(200, {}, b'{"code":"000000","data":{}}')

    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_remote_enabled=True, apac_charging_enabled=True)
    cloud._vehicles[identifier.value] = CloudVehicle(identifier, platform=platform, rudder="2")
    permitted = platform == "BeanTech" or platform == "navinfo" and not action.startswith("seat_")
    try:
        if permitted:
            await cloud.async_send_apac_control(identifier, action, security_password_hash="a" * 32)
        else:
            with pytest.raises(GwmRoutePolicyError):
                await cloud.async_send_apac_control(identifier, action, security_password_hash="a" * 32)
        assert len(transport.requests) == int(permitted)
    finally:
        await cloud.aclose()
