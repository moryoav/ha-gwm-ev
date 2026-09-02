"""Offline regional climate write, result correlation, and rejection tests."""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from gwm_client import (
    BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS,
    NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS,
    CabinCleanCommand,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    FrontDefrosterCommand,
    GwmApiError,
    GwmClient,
    GwmClientConfig,
    GwmConfigurationError,
    GwmSession,
    Region,
    RemoteCommandResultItem,
    VehicleIdentifier,
    create_gwm_ssl_context,
    select_remote_command_result,
)
from gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "command_contracts_v1.json"


class _RecordingTransport:
    def __init__(self, responses: list[_TransportResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[_TransportRequest] = []

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        assert deadline.remaining(0) > 0
        assert connect_timeout > 0
        assert read_timeout > 0
        self.requests.append(request)
        return self.responses.pop(0)

    async def aclose(self) -> None:
        return None


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _response(data: object = None, *, code: str = "000000") -> _TransportResponse:
    return _TransportResponse(
        200,
        {"content-type": "application/json"},
        json.dumps({"code": code, "data": data}, separators=(",", ":")).encode(),
    )


def _context(region: Region) -> ssl.SSLContext:
    return ssl.create_default_context() if region is Region.ANZ else create_gwm_ssl_context()


def _body(request: _TransportRequest) -> dict[str, Any]:
    assert request.body is not None
    return json.loads(request.body)


@pytest.mark.asyncio
@pytest.mark.parametrize("region", list(Region))
async def test_regional_climate_contracts_are_closed_and_header_exact(region: Region) -> None:
    fixture = _fixture()
    case = fixture["regions"][region.value]
    sequence = fixture["sequence_number"]
    result_data = [
        {
            "hwCommandId": sequence,
            "remoteType": "0x04",
            "resultCode": "0",
            "resultMsg": "Success",
        }
    ]
    response_count = 4 if case["security_check"] else 3
    responses = [_response() for _ in range(response_count - 1)] + [_response(result_data)]
    transport = _RecordingTransport(responses)
    client = GwmClient(
        GwmClientConfig(region),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(region),
        ),
        transport=transport,
        sequence_source=lambda: sequence,
    )
    identifier = VehicleIdentifier(fixture["vin"])

    await client.update_climate_defaults(
        identifier,
        temperature=21,
        operation_time_minutes=10,
    )
    acceptance = await client.send_climate_command(
        ClimateCommand(identifier, "cool", 21, 10),
        security_password_hash=fixture["security_password_hash"],
    )
    results = await client.get_remote_command_results(identifier, acceptance.command_id)

    assert acceptance.command_id == sequence
    assert results[0].result_code == "0"
    modify = transport.requests[0]
    assert urlsplit(modify.url).scheme + "://" + urlsplit(modify.url).netloc == case["modify_origin"]
    assert urlsplit(modify.url).path.endswith("/vehicle/modifyVehicleRemoteCtlInfo")
    assert (modify.headers.get("vin") == fixture["vin"]) is case["modify_vin_header"]
    assert _body(modify) == {
        "airConditionerTemperature": "21",
        "airConditionerTime": "600",
        "vin": fixture["vin"],
    }

    send_index = 2 if case["security_check"] else 1
    if case["security_check"]:
        check = transport.requests[1]
        assert urlsplit(check.url).path.endswith("/userAuth/checkSecurityPassword")
        assert "vin" not in check.headers
        assert _body(check) == {
            "securityPassword": fixture["security_password_hash"],
            "type": "3",
        }
    send = transport.requests[send_index]
    assert urlsplit(send.url).scheme + "://" + urlsplit(send.url).netloc == case["send_origin"]
    assert urlsplit(send.url).path.endswith("/vehicle/T5/sendCmd")
    assert (send.headers.get("vin") == fixture["vin"]) is case["send_vin_header"]
    assert _body(send) == {
        "instructions": {
            "0x04": {
                "airConditioner": {
                    "operationTime": "10",
                    "switchOrder": "1",
                    "temperature": "21",
                }
            }
        },
        "remoteType": "0",
        "securityPassword": fixture["security_password_hash"],
        "seqNo": sequence,
        "type": case["type"],
        "vin": fixture["vin"],
    }
    result_request = transport.requests[-1]
    assert urlsplit(result_request.url).path.endswith("/vehicle/getRemoteCtrlResultT5")
    assert urlsplit(result_request.url).query == "seqNo=" + sequence
    assert (result_request.headers.get("vin") == fixture["vin"]) is case["result_vin_header"]


@pytest.mark.asyncio
async def test_current_anz_commands_and_result_poll_keep_current_app_policy() -> None:
    fixture = _fixture()
    device_id = "0123456789abcdef0123456789abcdef"
    identifier = VehicleIdentifier("SYNTHETIC+CURRENT/ANZ")
    transport = _RecordingTransport([_response(), _response(), _response([])])
    client = GwmClient(
        GwmClientConfig(
            Region.ANZ,
            anz_authentication_method="current_v2",
        ),
        GwmSession(
            country="AU",
            device_id=device_id,
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(Region.ANZ),
            gw_id="SYNTHETIC-GW-ID",
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )

    await client.update_climate_defaults(
        identifier,
        temperature=21,
        operation_time_minutes=10,
    )
    acceptance = await client.send_climate_command(
        ClimateCommand(identifier, "cool", 21, 10),
        security_password_hash=fixture["security_password_hash"],
    )
    await client.get_remote_command_results(identifier, acceptance.command_id)

    assert len(transport.requests) == 3
    for request in transport.requests:
        assert request.headers["deviceId"] == request.headers["iccid"] == device_id
        assert request.headers["accessToken"] == "SYNTHETIC-COMMAND-TOKEN"
        assert request.headers["gwId"] == "SYNTHETIC-GW-ID"
        assert request.headers["language"] == "en"
        assert request.headers["cVer"] == "1.0.6"
        assert request.headers["ip"] == "0.0.0.0"
        assert request.headers["secVersion"] == "2.0"
        assert len(request.headers["bt-auth-nonce"]) == 32
    for request in transport.requests[:2]:
        assert request.headers["Content-Type"] == "application/json"
        assert b'"vin":"SYNTHETIC+CURRENT/ANZ"' in (request.body or b"")
    assert "Content-Type" not in transport.requests[2].headers


@pytest.mark.asyncio
@pytest.mark.parametrize("region", list(Region))
async def test_regional_lock_and_close_window_contracts_are_exact(region: Region) -> None:
    fixture = _fixture()
    case = fixture["regions"][region.value]
    response_count = 6 if case["security_check"] else 3
    transport = _RecordingTransport([_response() for _ in range(response_count)])
    client = GwmClient(
        GwmClientConfig(region),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(region),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )
    identifier = VehicleIdentifier(fixture["vin"])

    locked = await client.send_lock_command(
        DoorLockCommand(identifier, True),
        security_password_hash=fixture["security_password_hash"],
    )
    unlocked = await client.send_lock_command(
        DoorLockCommand(identifier, False),
        security_password_hash=fixture["security_password_hash"],
    )
    closed = await client.send_close_windows_command(
        CloseWindowsCommand(identifier),
        security_password_hash=fixture["security_password_hash"],
    )

    assert locked.command_id == unlocked.command_id == closed.command_id == fixture["sequence_number"]
    sends = [request for request in transport.requests if request.url.endswith("/vehicle/T5/sendCmd")]
    assert len(sends) == 3
    assert all((request.headers.get("vin") == fixture["vin"]) is case["send_vin_header"] for request in sends)
    common = {
        "remoteType": "0",
        "securityPassword": fixture["security_password_hash"],
        "seqNo": fixture["sequence_number"],
        "type": case["type"],
        "vin": fixture["vin"],
    }
    assert _body(sends[0]) == {
        "instructions": {"0x05": {"operationTime": "0", "switchOrder": "2"}},
        **common,
    }
    assert _body(sends[1]) == {
        "instructions": {"0x05": {"operationTime": "0", "switchOrder": "1"}},
        **common,
    }
    expected_window = {
        "leftFront": "0",
        "leftBack": "0",
        "rightFront": "0",
        "rightBack": "0",
    }
    if region is not Region.RUSSIA:
        expected_window["skyLight"] = ""
    assert _body(sends[2]) == {
        "instructions": {
            "0x08": {
                "switchOrder": "2" if region is Region.RUSSIA else "0",
                "window": expected_window,
            }
        },
        **common,
    }
    if case["security_check"]:
        checks = [request for request in transport.requests if request.url.endswith("/userAuth/checkSecurityPassword")]
        assert len(checks) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("region", list(Region))
async def test_regional_front_defrost_and_cabin_clean_contracts_are_exact(
    region: Region,
) -> None:
    fixture = _fixture()
    case = fixture["regions"][region.value]
    response_count = 6 if case["security_check"] else 3
    transport = _RecordingTransport([_response() for _ in range(response_count)])
    client = GwmClient(
        GwmClientConfig(region),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(region),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )
    identifier = VehicleIdentifier(fixture["vin"])

    started = await client.send_front_defroster_command(
        FrontDefrosterCommand(identifier, True),
        security_password_hash=fixture["security_password_hash"],
    )
    stopped = await client.send_front_defroster_command(
        FrontDefrosterCommand(identifier, False),
        security_password_hash=fixture["security_password_hash"],
    )
    cleaned = await client.send_cabin_clean_command(
        CabinCleanCommand(identifier),
        security_password_hash=fixture["security_password_hash"],
    )

    assert started.command_id == stopped.command_id == cleaned.command_id == fixture["sequence_number"]
    sends = [request for request in transport.requests if request.url.endswith("/vehicle/T5/sendCmd")]
    assert len(sends) == 3
    common = {
        "remoteType": "0",
        "securityPassword": fixture["security_password_hash"],
        "seqNo": fixture["sequence_number"],
        "type": case["type"],
        "vin": fixture["vin"],
    }
    assert _body(sends[0]) == {
        "instructions": {
            "0x0B": {
                "defrost": {
                    "defrostFront": 1,
                    "operationTime": "900",
                    "switchOrder": "1",
                }
            }
        },
        **common,
    }
    assert _body(sends[1]) == {
        "instructions": {
            "0x0B": {
                "defrost": {
                    "defrostFront": 0,
                    "operationTime": "0",
                    "switchOrder": "1",
                }
            }
        },
        **common,
    }
    assert _body(sends[2]) == {
        "instructions": {
            "0x11": {
                "operationTime": "60",
                "switchOrder": "1",
            }
        },
        **common,
    }
    assert all((request.headers.get("vin") == fixture["vin"]) is case["send_vin_header"] for request in sends)
    if case["security_check"]:
        checks = [request for request in transport.requests if request.url.endswith("/userAuth/checkSecurityPassword")]
        assert len(checks) == 3


@pytest.mark.asyncio
async def test_provider_rejection_does_not_return_an_accepted_identifier() -> None:
    fixture = _fixture()
    case = fixture["regions"]["aus"]
    transport = _RecordingTransport([_response(code="607777")])
    client = GwmClient(
        GwmClientConfig(Region.ANZ),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(Region.ANZ),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )
    command = ClimateCommand(VehicleIdentifier(fixture["vin"]), "cool", 22, 15)
    with pytest.raises(GwmApiError):
        await client.send_climate_command(
            command,
            security_password_hash=fixture["security_password_hash"],
        )
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_overseas_heat_is_rejected_before_transport() -> None:
    fixture = _fixture()
    case = fixture["regions"]["aus"]
    transport = _RecordingTransport([])
    client = GwmClient(
        GwmClientConfig(Region.ANZ),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-COMMAND-TOKEN",
            app_ssl_context=_context(Region.ANZ),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )
    with pytest.raises(GwmConfigurationError):
        await client.send_climate_command(
            ClimateCommand(VehicleIdentifier(fixture["vin"]), "heat", 24, 15),
            security_password_hash=fixture["security_password_hash"],
        )
    assert transport.requests == []


def test_result_selection_preserves_russian_and_default_semantics() -> None:
    sequence = _fixture()["sequence_number"]
    stale = RemoteCommandResultItem("stale", "0x04", "0", "Success")
    current = RemoteCommandResultItem(sequence, "0x04", "1000", "Waiting")
    assert select_remote_command_result((stale, current), command_id=sequence, region=Region.RUSSIA).state == "pending"
    success = RemoteCommandResultItem(None, "0x04", "6", "Done")
    assert (
        select_remote_command_result((stale, success), command_id=sequence, region=Region.RUSSIA).state == "completed"
    )
    assert select_remote_command_result((stale, current), command_id=sequence, region=Region.EU).state == "failed"


def test_china_vehicle_control_contract_is_closed_and_platform_filtered() -> None:
    identifier = VehicleIdentifier(_fixture()["vin"])
    assert len(NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS) == 13
    assert {
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "horn_and_lights",
        "sunroof_close",
        "seat_heating_start",
        "seat_heating_stop",
        "seat_heating_start_passenger",
        "seat_heating_stop_passenger",
        "seat_ventilation_start",
        "seat_ventilation_stop",
        "seat_ventilation_start_passenger",
        "seat_ventilation_stop_passenger",
        "steering_wheel_heating",
        "steering_wheel_heatless",
        "defrost_front_start",
        "defrost_front_stop",
        "defrost_back_start",
        "defrost_back_stop",
        "cabin_clean",
        "comfort_warm",
        "comfort_cool",
        "comfort_off",
        "battery_gun_heat",
        "battery_gun_heat_stop",
        "battery_initiative_heat",
        "battery_initiative_heat_stop",
    } == BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS
    assert (
        ChinaVehicleControlCommand(
            identifier,
            "remote_start",
            20,
        ).run_time_minutes
        == 20
    )
    assert ChinaVehicleControlCommand(identifier, "horn").action == "horn"

    for action, run_time in (
        ("future_action", None),
        ("remote_start", 4),
        ("remote_start", 31),
        ("remote_start", True),
        ("horn", 15),
    ):
        with pytest.raises(ValueError, match="china_vehicle_control_command_invalid"):
            ChinaVehicleControlCommand(  # type: ignore[arg-type]
                identifier,
                action,
                run_time,
            )
