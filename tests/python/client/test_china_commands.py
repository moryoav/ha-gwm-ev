"""Offline mainland-China commands behavior and protocol contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    FIXTURE,
    SENSITIVE,
    UNSUPPORTED_VIN,
    VIN,
    _auto_ai_payload,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
)

from custom_components.gwm_ora.gwm_client._dotnet_json import encode_dotnet_json
from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthenticated,
)
from custom_components.gwm_ora.gwm_client.china_crypto import bean_tech_sign
from custom_components.gwm_ora.gwm_client.china_transport import (
    _ChinaTransportRequest,
)
from custom_components.gwm_ora.gwm_client.commands import (
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    RemoteCommandResultItem,
    select_remote_command_result,
)
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmClientError,
    GwmConfigurationError,
    GwmNetworkError,
    GwmRoutePolicyError,
    GwmSchemaError,
)
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier

_SYNTHETIC_LOCK_CREDENTIAL = "A" * 64
_BEAN_IDENTIFIER = VehicleIdentifier(BEAN_VIN)


@pytest.mark.asyncio
@pytest.mark.parametrize(("operation", "command", "wire_command", "invalid_command"), [
    ("send_lock_command", DoorLockCommand(_BEAN_IDENTIFIER, True), {"controlType": "VEHICLE_LOCK"},
     {"controlType": "VEHICLE_LOCK", "cmdBody": None}),
    ("send_lock_command", DoorLockCommand(_BEAN_IDENTIFIER, False), {"controlType": "VEHICLE_UNLOCK"},
     {"controlType": "VEHICLE_UNLOCK", "cmdBody": None}),
    ("send_close_windows_command", CloseWindowsCommand(_BEAN_IDENTIFIER),
     {"controlType": "WINDOW_CLOSE", "cmdBody": {"leftFront": 0, "leftBack": 0, "rightFront": 0, "rightBack": 0}},
     {"controlType": "WINDOW_CLOSE", "cmdBody": {"leftFront": False, "leftBack": 0, "rightFront": 0, "rightBack": 0}}),
    ("send_vehicle_control_command", ChinaVehicleControlCommand(_BEAN_IDENTIFIER, "remote_start", 5),
     {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 300}},
     {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 301}}),
    ("send_vehicle_control_command", ChinaVehicleControlCommand(_BEAN_IDENTIFIER, "remote_start", 30),
     {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 1800}},
     {"controlType": "ENGINE_STOP"}),
])
async def test_beantech_authorized_command_uses_v3_sequence(
    operation: str,
    command: DoorLockCommand | CloseWindowsCommand | ChinaVehicleControlCommand,
    wire_command: dict[str, object],
    invalid_command: dict[str, object],
) -> None:
    """Correlate one token and sequence across authorization, submission, and polling."""
    token = "G_A(synthetic-opaque-token)"
    is_lock = operation == "send_lock_command"
    auth_operation = "authorize_bean_tech_lock" if is_lock else "authorize_bean_tech_command"
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        **{auth_operation: [{"code": "000000", "data": token}], operation: [{"code": "000000"}]},
        get_remote_command_result=[
            {"code": "000000", "data": {"messageList": [{"messageData": {"resultCode": code}}]}}
            for code in ("2", "0")
        ],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)

    accepted = await getattr(client, operation)(
        command, bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL,
    )
    assert accepted.result_action == ("authorized_lock" if is_lock else "authorized_command")
    for state in ("pending", "completed"):
        candidates = await client.get_remote_command_results(
            identifier, accepted.command_id, control_action=accepted.result_action,
        )
        result = select_remote_command_result(candidates, command_id=accepted.command_id, region=None)
        assert result is not None and result.state == state

    auth, submit, *polls = transport.calls[-4:]
    base = "/app-api/api/v3.0/vehicle/"
    assert [(req.method, urlsplit(req.url).path) for req in (auth, submit, *polls)] == [
        ("POST", base + "security/generate-token"),
        ("POST", base + "remote-ctrl/timely"),
        ("GET", base + "remote-ctrl/result"),
        ("GET", base + "remote-ctrl/result"),
    ]
    assert json.loads(auth.body or b"null") == {"securityPwd": _SYNTHETIC_LOCK_CREDENTIAL, "eventType": 2, "version": 1}
    assert json.loads(submit.body or b"null") == {
        "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID, "sendType": 0, "commands": [wire_command],
    }
    assert submit.headers["securityToken"] == token
    assert token not in repr(submit) and _SYNTHETIC_LOCK_CREDENTIAL not in repr(auth)
    for request in polls:
        assert parse_qs(urlsplit(request.url).query) == {"vin": [BEAN_VIN], "seqNo": [BEAN_COMMAND_ID], "msgType": ["remote"]}
        assert "securityToken" not in request.headers
    with pytest.raises(ValueError, match="route_invalid"):
        replace(submit, headers={key: val for key, val in submit.headers.items() if key != "securityToken"})
    with pytest.raises(ValueError, match="route_invalid"):
        replace(submit, operation="send_close_windows_command" if is_lock else "send_lock_command")
    body = json.loads(submit.body or b"null")
    body["commands"] = [invalid_command]
    signed_body = encode_dotnet_json(body)
    headers = dict(submit.headers)
    headers["bt-auth-sign"] = bean_tech_sign(
        "POST", base + "remote-ctrl/timely", headers["bt-auth-nonce"],
        headers["bt-auth-timestamp"], "json=" + signed_body,
    )
    with pytest.raises(ValueError, match="route_invalid"):
        replace(submit, headers=headers, body=signed_body.encode("utf-8"))


@pytest.mark.asyncio
@pytest.mark.parametrize(("send_operation", "command"), [
    ("send_lock_command", DoorLockCommand(_BEAN_IDENTIFIER, False)),
    ("send_close_windows_command", CloseWindowsCommand(_BEAN_IDENTIFIER)),
    ("send_vehicle_control_command", ChinaVehicleControlCommand(_BEAN_IDENTIFIER, "remote_start")),
])
@pytest.mark.parametrize(("auth_failure", "response", "error"), [
    (True, {"code": "550002"}, GwmApiError),
    (True, {"data": "synthetic-security-token"}, GwmSchemaError),
    (True, {"code": "000000", "data": {"token": "nested"}}, GwmSchemaError),
    (True, {"code": "000000", "data": "bad\r\nheader"}, GwmSchemaError),
    (False, {"code": "550002"}, GwmApiError),
    (False, {"data": None}, GwmSchemaError),
])
async def test_beantech_authorized_command_does_not_fall_back_or_resend(
    send_operation: str,
    command: DoorLockCommand | CloseWindowsCommand | ChinaVehicleControlCommand,
    auth_failure: bool,
    response: dict[str, object],
    error: type[GwmClientError],
) -> None:
    """Stop after the failed stage without sending a replacement command."""
    auth_operation = "authorize_bean_tech_lock" if send_operation == "send_lock_command" else "authorize_bean_tech_command"
    operation = auth_operation if auth_failure else send_operation
    replies = {auth_operation: [{"code": "000000", "data": "synthetic-security-token"}]}
    replies[operation] = [response]
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], **replies)
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())

    with pytest.raises(error) as raised:
        await getattr(client, send_operation)(
            command, bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL,
        )
    assert raised.value.operation == operation
    calls = [req for req in transport.calls if req.operation != "acquire_vehicles"]
    assert [req.operation for req in calls] == (
        [auth_operation] if auth_failure else [auth_operation, send_operation]
    )
    assert all("T5" not in req.url for req in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("result_action", ["authorized_lock", "authorized_command"])
async def test_beantech_authorized_command_rejects_result_without_envelope_code(result_action: str) -> None:
    """Require a successful envelope before using a completed result."""
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[
            {"data": {"messageList": [{"messageData": {"resultCode": "0"}}]}},
        ],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())

    with pytest.raises(GwmSchemaError) as raised:
        await client.get_remote_command_results(
            VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=result_action,
        )
    assert raised.value.operation == "get_remote_command_result"


@pytest.mark.asyncio
async def test_navinfo_climate_start_update_stop_and_result_contracts() -> None:
    transaction_ids = ("TX-START-1", "TX-UPDATE-2", "TX-STOP-3")
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"header": {"c": "0"}, "body": {"transactionId": value}}
            for value in transaction_ids
        ],
        save_climate_config=[
            {"code": "000000", "data": None},
            {"code": "000000", "data": None},
        ],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": json.dumps(
                                {
                                    "transactionId": transaction_ids[1],
                                    "resultCode": "3",
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier(VIN)

    started = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 21, 10, currently_on=False)
    )
    updated = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 26, 20, currently_on=True)
    )
    stopped = await client.send_climate_command(
        ClimateCommand(identifier, "off", 22, 15, currently_on=True)
    )
    results = await client.get_remote_command_results(identifier, updated.command_id)

    assert (started.command_id, updated.command_id, stopped.command_id) == transaction_ids
    command_requests = [
        request for request in transport.calls if request.operation == "send_climate_command"
    ]
    start_payload, update_payload, stop_payload = map(_auto_ai_payload, command_requests)
    assert start_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert start_payload["body"]["cmdCode"] == 6
    assert start_payload["body"]["airParams"] == {
        "engineControl": 1,
        "runTime": 10,
        "temperature": 21,
    }
    assert update_payload["header"]["fn"] == "GW.M.SET_AND_OPEN_COMMAND"
    assert update_payload["body"]["cmdCode"] == 6
    assert update_payload["body"]["airParams"] == {
        "engineControl": 1,
        "runTime": 20,
        "temperature": 26,
    }
    assert stop_payload["header"]["fn"] == "GW.M.SEND_COMMON_COMMAND"
    assert stop_payload["body"]["cmdCode"] == 7
    assert "airParams" not in stop_payload["body"]
    paired_operations = [
        request.operation
        for request in transport.calls
        if request.operation in {"send_climate_command", "save_climate_config"}
    ]
    assert paired_operations == [
        "send_climate_command",
        "save_climate_config",
        "send_climate_command",
        "save_climate_config",
        "send_climate_command",
    ]
    config_requests = [
        request for request in transport.calls if request.operation == "save_climate_config"
    ]
    assert [urlsplit(request.url).path for request in config_requests] == [
        "/app-api/api/v3.0/vehicle/remote-ctrl/config",
        "/app-api/api/v3.0/vehicle/remote-ctrl/config",
    ]
    assert [json.loads(request.body or b"null") for request in config_requests] == [
        {
            "configs": {
                "cmdBody": {
                    "allowStartEng": 1,
                    "operationTime": 600,
                    "temperature": 21,
                },
                "controlType": "AIR_CONDITIONER_START",
            },
            "vin": VIN,
        },
        {
            "configs": {
                "cmdBody": {
                    "allowStartEng": 1,
                    "operationTime": 1200,
                    "temperature": 26,
                },
                "controlType": "AIR_CONDITIONER_START",
            },
            "vin": VIN,
        },
    ]

    result_request = transport.calls[-1]
    assert result_request.service == "bean_tech"
    assert urlsplit(result_request.url).path == "/app-api/api/v3.0/vehicle/remote-ctrl/result"
    assert urlsplit(result_request.url).query == (
        "seqNo=TX-UPDATE-2&vin=" + VIN + "&msgType=remote"
    )
    assert results[0].command_id == transaction_ids[1]
    assert results[0].result_code == "2000"
    assert results[0].result_message == "Command is still running"


@pytest.mark.asyncio
async def test_navinfo_climate_config_failure_preserves_accepted_command(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"header": {"c": "0"}, "body": {"transactionId": "TX-ACCEPTED"}}
        ],
        save_climate_config=[GwmNetworkError(operation="send_climate_command")],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    accepted = await client.send_climate_command(
        ClimateCommand(VehicleIdentifier(VIN), "auto", 22, 10)
    )

    assert accepted.command_id == "TX-ACCEPTED"
    assert "companion configuration request failed" in caplog.text


@pytest.mark.asyncio
async def test_navinfo_climate_rejects_temperatures_outside_captured_range() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)

    for temperature in (16, 32):
        with pytest.raises(GwmConfigurationError):
            await client.send_climate_command(
                ClimateCommand(VehicleIdentifier(VIN), "auto", temperature, 10)
            )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_unknown_platform_climate_is_rejected_before_command_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.send_climate_command(
            ClimateCommand(VehicleIdentifier("LGWTEST0000000002"), "auto", 22, 15)
        )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_navinfo_lock_unlock_close_windows_and_result_need_no_pin() -> None:
    """Keep NavInfo on AutoAI even when the entry has a BeanTech credential."""
    transactions = ("TX-LOCK-1", "TX-UNLOCK-2", "TX-WINDOW-3")
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_lock_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transactions[0]}},
            {"header": {"c": "0"}, "body": {"transactionId": transactions[1]}},
        ],
        send_close_windows_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transactions[2]}}
        ],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "remote",
                            "messageData": json.dumps(
                                {
                                    "transactionId": transactions[2],
                                    "resultCode": "0",
                                    "resultMessage": "Success",
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                },
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(VIN)

    locked = await client.send_lock_command(
        DoorLockCommand(identifier, True), bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL,
    )
    unlocked = await client.send_lock_command(DoorLockCommand(identifier, False))
    closed = await client.send_close_windows_command(
        CloseWindowsCommand(identifier), bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL,
    )
    results = await client.get_remote_command_results(identifier, closed.command_id)

    assert (locked.command_id, unlocked.command_id, closed.command_id) == transactions
    assert locked.result_action is closed.result_action is None
    requests = [
        request
        for request in transport.calls
        if request.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    assert [_auto_ai_payload(request)["body"]["cmdCode"] for request in requests] == [2, 1, 3]
    assert all(
        _auto_ai_payload(request)["header"]["fn"] == "GW.M.SEND_COMMON_COMMAND"
        for request in requests
    )
    assert results[0].command_id == transactions[2]
    assert results[0].result_code == "0"


@pytest.mark.asyncio
async def test_beantech_lock_close_windows_and_legacy_result_are_isolated() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_lock_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
        send_close_windows_command=[{"code": "000000", "data": {}}],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": [
                    {
                        "remoteType": "0x08",
                        "resultCode": 6,
                        "resultMsg": "Success",
                    }
                ],
            }
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    locked = await client.send_lock_command(DoorLockCommand(identifier, True))
    unlocked = await client.send_lock_command(DoorLockCommand(identifier, False))
    closed = await client.send_close_windows_command(CloseWindowsCommand(identifier))
    results = await client.get_remote_command_results(identifier, closed.command_id)

    assert locked.command_id == unlocked.command_id == closed.command_id == BEAN_COMMAND_ID
    sends = [
        request
        for request in transport.calls
        if request.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    command_bodies = [json.loads(request.body or b"null") for request in sends]
    assert command_bodies[0]["commands"] == [
        {"controlType": "VEHICLE_LOCK", "cmdBody": None}
    ]
    assert command_bodies[1]["commands"] == [
        {"controlType": "VEHICLE_UNLOCK", "cmdBody": None}
    ]
    assert command_bodies[2]["commands"] == [
        {
            "controlType": "WINDOW_CLOSE",
            "cmdBody": {
                "leftFront": 0,
                "leftBack": 0,
                "rightFront": 0,
                "rightBack": 0,
            },
        }
    ]
    result_request = transport.calls[-1]
    assert urlsplit(result_request.url).path == "/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
    assert urlsplit(result_request.url).query == "seqNo=" + BEAN_COMMAND_ID
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, "0x08", "6", "Success"),)


@pytest.mark.asyncio
async def test_task18_commands_reject_unknown_china_platform_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.send_lock_command(
            DoorLockCommand(VehicleIdentifier(UNSUPPORTED_VIN), True)
        )

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_navinfo_extended_vehicle_controls_use_exact_app_command_shapes() -> None:
    actions = (
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "horn_and_lights",
        "tailgate_open",
        "tailgate_close",
        "sunroof_close",
        "sunroof_tilt",
        "sunroof_half",
        "sunroof_full",
        "cabin_purge",
        "force_refresh",
    )
    transaction_ids = tuple(f"TX-CONTROL-{index}" for index in range(len(actions)))
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"header": {"c": "0"}, "body": {"transactionId": transaction_id}}
            for transaction_id in transaction_ids
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(VIN)

    acceptances = [
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(
                identifier,
                action,  # type: ignore[arg-type]
                20 if action == "remote_start" else None,
            ),
            bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL if action == "remote_start" else None,
        )
        for action in actions
    ]

    assert tuple(item.command_id for item in acceptances) == transaction_ids
    assert all(item.result_action is None for item in acceptances)
    requests = [
        request
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    payloads = [_auto_ai_payload(request) for request in requests]
    assert [payload["header"]["fn"] for payload in payloads] == [
        "GW.M.SET_AND_OPEN_COMMAND",
        *("GW.M.SEND_COMMON_COMMAND" for _ in range(11)),
        "GW.M.REFRESH_VEHICLE_STATE",
    ]
    assert [payload["body"].get("cmdCode") for payload in payloads] == [
        15,
        16,
        19,
        20,
        5,
        17,
        18,
        28,
        29,
        29,
        29,
        34,
        None,
    ]
    assert payloads[0]["body"]["engineParams"] == {"runTime": 20}
    assert [payloads[index]["body"]["openAngle"] for index in (8, 9, 10)] == [
        11,
        5,
        10,
    ]
    assert payloads[-1]["body"] == {"vin": VIN}


@pytest.mark.asyncio
async def test_beantech_extended_controls_are_exact_and_unsupported_actions_fail_locally() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(5)
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    for action in (
        "remote_start",
        "remote_stop",
        "horn",
        "flash_lights",
        "sunroof_close",
    ):
        accepted = await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(
                identifier,
                action,  # type: ignore[arg-type]
                10 if action == "remote_start" else None,
            )
        )
        assert accepted.command_id == BEAN_COMMAND_ID

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {"controlType": "ENGINE_START", "cmdBody": {"operationTime": 600}},
        {"controlType": "ENGINE_STOP", "cmdBody": None},
        {"controlType": "WHISTLE"},
        {"controlType": "FLASH"},
        {"controlType": "SKYLIGNT_CLOSE", "cmdBody": {"skyLight": 0}},
    ]
    requests = [request for request in transport.calls if request.operation == "send_vehicle_control_command"]
    assert [urlsplit(request.url).path for request in requests] == [
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
        "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        "/app-api/api/v1.0/vehicle/T5/sendCmd",
    ]
    for index in (0, 1, 4):
        assert list(sends[index]) == ["vin", "seqNo", "sendType", "commands", "isSaveConfig"]
        assert sends[index]["isSaveConfig"] is None

    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(identifier, "tailgate_open")
        )
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("action,control_type", [
    ("horn", "WHISTLE"), ("flash_lights", "FLASH"), ("horn_and_lights", "WHISTLE_FLASH")
])
async def test_beantech_horn_lights_send_exact_pin_exempt_timely_request(
    action: str, control_type: str,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    accepted = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action),  # type: ignore[arg-type]
        bean_tech_lock_credential=_SYNTHETIC_LOCK_CREDENTIAL,
    )
    request = transport.calls[-1]
    expected_body = (
        '{"vin":"' + BEAN_VIN + '","seqNo":"' + BEAN_COMMAND_ID
        + '","sendType":0,"commands":[{"controlType":"' + control_type + '"}]}'
    )
    assert accepted.command_id == BEAN_COMMAND_ID
    assert request.service == "bean_tech"
    assert request.method == "POST"
    assert request.url == "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/timely"
    assert request.body == expected_body.encode()
    assert request.headers["vin"] == BEAN_VIN
    assert "securityToken" not in request.headers
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
        FIXTURE["nonce"], request.headers["bt-auth-timestamp"], "json=" + expected_body,
    )
    assert len(transport.calls) == 2


async def _horn_request() -> _ChinaTransportRequest:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_vehicle_control_command=[{"code": "000000"}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn"))
    return transport.calls[-1]


@pytest.mark.parametrize("mutation", [
    "service", "method", "host", "path", "operation", "token", "signature", "header",
    "missing_body", "invalid_json", "list_body", "vin", "sequence", "sequence_type",
    "send_type", "boolean_send_type", "float_send_type", "extra_key", "missing_key",
    "command_body", "security_command", "climate_command", "multiple_commands", "format",
    "content_type", "auth_header",
])
@pytest.mark.asyncio
async def test_beantech_horn_transport_rejects_unapproved_routes_and_payloads(mutation: str) -> None:
    request = await _horn_request()
    headers = dict(request.headers)
    body = json.loads(request.body or b"null")
    changes: dict[str, Any] = {}
    if mutation == "service":
        changes["service"] = "auto_ai"
    elif mutation == "method":
        changes["method"] = "GET"
    elif mutation == "host":
        changes["url"] = request.url.replace("gw-app-gateway.gwmapp-h.com", "example.invalid")
    elif mutation == "path":
        changes["url"] = request.url + "/unexpected"
    elif mutation == "operation":
        changes["operation"] = "send_lock_command"
    elif mutation == "token":
        headers["securityToken"] = SENSITIVE
    elif mutation == "signature":
        headers["bt-auth-sign"] = "0" * 32
    elif mutation == "header":
        headers["Unexpected"] = "value"
    elif mutation == "content_type":
        headers["Content-Type"] = "text/plain"
    elif mutation == "auth_header":
        headers["rs"] = "9"
    elif mutation == "missing_body":
        changes["body"] = None
    elif mutation == "invalid_json":
        changes["body"] = b"{"
    elif mutation == "list_body":
        changes["body"] = b"[]"
    elif mutation == "format":
        changes["body"] = json.dumps(body, indent=2).encode()
    else:
        if mutation == "vin":
            body["vin"] = VIN
        elif mutation == "sequence":
            body["seqNo"] = "invalid"
        elif mutation == "sequence_type":
            body["seqNo"] = 123
        elif mutation == "send_type":
            body["sendType"] = 1
        elif mutation == "boolean_send_type":
            body["sendType"] = False
        elif mutation == "float_send_type":
            body["sendType"] = 0.0
        elif mutation == "extra_key":
            body["isSaveConfig"] = None
        elif mutation == "missing_key":
            del body["sendType"]
        elif mutation == "command_body":
            body["commands"][0]["cmdBody"] = None
        elif mutation == "security_command":
            body["commands"] = [{"controlType": "VEHICLE_UNLOCK"}]
        elif mutation == "climate_command":
            body["commands"] = [{"controlType": "AIR_CONDITIONER_START"}]
        elif mutation == "multiple_commands":
            body["commands"].append({"controlType": "FLASH"})
        changes["body"] = json.dumps(body, separators=(",", ":")).encode()
    # Re-sign mutated bodies so schema checks cannot pass merely because the
    # original signature no longer matches.
    if changes.get("body") is not None:
        headers["bt-auth-sign"] = bean_tech_sign(
            "POST", "/app-api/api/v3.0/vehicle/remote-ctrl/timely",
            headers["bt-auth-nonce"], headers["bt-auth-timestamp"],
            "json=" + changes["body"].decode(),
        )
    with pytest.raises(ValueError):
        replace(request, headers=headers, **changes)


@pytest.mark.asyncio
@pytest.mark.parametrize("code,expected", [(2, "pending"), ("2", "pending"), (3.0, "pending"),
    ("3", "pending"), (0, "completed"), ("0", "completed"), (6, "completed"), (7, "failed")])
@pytest.mark.parametrize("shape", ["object", "json", "inline"])
async def test_beantech_horn_results_map_pending_success_and_failure(
    code: object, expected: str, shape: str,
) -> None:
    data = {"resultCode": code, "resultMessage": "Synthetic result", "transactionId": "server-generated-id"}
    message = data if shape == "inline" else {
        "messageType": "remote", "messageData": json.dumps(data) if shape == "json" else data,
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [message]}}],
    )
    # A fresh client has no in-memory knowledge of the original submission.
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(
        VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="horn",
    )
    assert results == (RemoteCommandResultItem(
        BEAN_COMMAND_ID, None if shape == "inline" else "remote",
        "2000" if expected == "pending" else str(code), "Synthetic result",
    ),)
    result = select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None, expected_remote_type="china")
    assert result is not None and result.state == expected
    request = transport.calls[-1]
    assert request.url == (
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/result"
        + "?seqNo=" + BEAN_COMMAND_ID + "&vin=" + BEAN_VIN + "&msgType=remote"
    )
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET", "/app-api/api/v3.0/vehicle/remote-ctrl/result", FIXTURE["nonce"],
        request.headers["bt-auth-timestamp"], "msgtype=remote" + "seqno=" + BEAN_COMMAND_ID + "vin=" + BEAN_VIN,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    {}, {"messageList": None}, {"messageList": []},
    {"messageList": [None, {}, {"messageData": " "}, {"messageData": []}, {"messageData": "null"},
        {"messageData": {"resultCode": ""}}, {"messageData": {"resultCode": None}}]},
], ids=["absent", "null", "empty", "incomplete_messages"])
async def test_beantech_horn_incomplete_results_keep_polling(data: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": data}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_remote_command_results(
        VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="flash_lights",
    ) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    [], "invalid", {"messageList": {}}, {"messageList": "invalid"},
    {"messageList": [{"messageData": "{"}]},
    *({"messageList": [{"messageData": {"resultCode": code}}]} for code in (True, [], {})),
], ids=["list_root", "string_root", "object_messages", "string_messages", "broken_json", "bool_code", "list_code", "object_code"])
async def test_beantech_horn_malformed_results_raise_typed_errors(data: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": data}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_remote_command_results(
            VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action="horn_and_lights",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["unknown", "", True, [], 123])
async def test_invalid_result_action_is_rejected_before_transport(action: Any) -> None:
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await _client(transport).get_remote_command_results(
            VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action,
        )
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    {"code": "551210"}, {"code": "607777"}, GwmNetworkError(operation="send_vehicle_control_command"),
], ids=["busy", "rejected", "network"])
async def test_beantech_horn_send_is_not_retried_or_rerouted(error: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_vehicle_control_command=[error],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn"))
    assert len(transport.calls) == 2
    assert transport.calls[-1].url.endswith("/remote-ctrl/timely")


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [{}, {"code": None}, {"code": True}, {"code": []}, {"code": {}}])
async def test_beantech_horn_requires_an_explicit_acceptance_code(response: object) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_vehicle_control_command=[response],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn"))
    assert len(transport.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("vin", [UNSUPPORTED_VIN, "LGWTEST0000000099"])
@pytest.mark.parametrize("action", ["horn", "flash_lights", "horn_and_lights"])
async def test_horn_lights_reject_unknown_vehicle_or_platform_locally(vin: str, action: Any) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmRoutePolicyError):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(VehicleIdentifier(vin), action))
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_results(VehicleIdentifier(vin), BEAN_COMMAND_ID, control_action=action)
    assert len(transport.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["horn", "flash_lights", "horn_and_lights"])
async def test_navinfo_horn_result_correlation_is_unchanged(action: Any) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [
            {"messageData": {"transactionId": "other-command", "resultCode": "0"}},
            {"messageData": {"transactionId": "TX-HORN", "resultCode": "2"}},
        ]}}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(VehicleIdentifier(VIN), "TX-HORN", control_action=action)
    assert len(results) == 1
    assert results[0].command_id == "TX-HORN"
    assert results[0].result_code == "2000"
