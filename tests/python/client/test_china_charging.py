"""Offline mainland-China charging behavior and protocol contracts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    FIXTURE,
    VIN,
    _auto_ai_payload,
    _charging_setting,
    _client,
    _complete_state,
    _credentials,
    _empty_state,
    _FakeTransport,
    _partial_state,
    _response,
)

from custom_components.gwm_ora.gwm_client.charging import ChargingPlanCommand
from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthenticated,
)
from custom_components.gwm_ora.gwm_client.china_crypto import bean_tech_sign
from custom_components.gwm_ora.gwm_client.commands import (
    ChinaVehicleControlCommand,
    RemoteCommandResultItem,
    select_remote_command_result,
)
from custom_components.gwm_ora.gwm_client.errors import (
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmRoutePolicyError,
    GwmSchemaError,
)
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier


@pytest.mark.asyncio
async def test_navinfo_charging_schedule_read_write_clear_and_china_weekday_contract() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_charging_plan=[
            {
                "header": {"c": "0"},
                "body": {
                    "vehicleSts": {
                        "chargeSettings": {
                            "mode": "0",
                            "phoneStrtHourMin": "23:30",
                            "phoneEndHourMin": "06:15",
                            "sundayUseTime": True,
                            "thurdayUseTime": 1,
                        }
                    }
                },
            }
        ],
        set_charging_plan=[
            {"header": {"c": "0"}, "body": {}},
            {"header": {"c": "0"}, "body": {}},
        ],
    )
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier(VIN)

    current = await client.get_charging_plan(identifier)
    assert current.items[0].start_time_ms == int(
        datetime(2024, 8, 12, 15, 30, tzinfo=UTC).timestamp() * 1000
    )
    assert current.items[0].end_time_ms == int(
        datetime(2024, 8, 12, 22, 15, tzinfo=UTC).timestamp() * 1000
    )
    assert current.items[0].weeks == "1001000"

    start = int(datetime(2024, 8, 17, 18, 0, tzinfo=UTC).timestamp() * 1000)
    end = int(datetime(2024, 8, 17, 19, 0, tzinfo=UTC).timestamp() * 1000)
    await client.set_charging_plan(
        ChargingPlanCommand(identifier, True, start, end)
    )
    written = await client.get_charging_plan(identifier)
    assert written.items[0].start_time_ms == start
    assert written.items[0].end_time_ms == end
    assert written.items[0].weeks == "1000000"
    await client.set_charging_plan(ChargingPlanCommand(identifier, False))

    read_payload = _auto_ai_payload(
        next(call for call in transport.calls if call.operation == "get_charging_plan")
    )
    assert read_payload["header"]["fn"] == "GW.M.GET_VEHICLE_STATE"
    assert read_payload["body"] == {"vin": VIN}
    write_requests = [
        call for call in transport.calls if call.operation == "set_charging_plan"
    ]
    enabled_body = _auto_ai_payload(write_requests[0])["body"]
    assert enabled_body["chargeingMode"] == "0"
    assert enabled_body["chargingStartTime"] == "02:00"
    assert enabled_body["chargingEndTime"] == "03:00"
    assert enabled_body["repeatTimes"] == "1000000"
    clear_body = _auto_ai_payload(write_requests[1])["body"]
    assert clear_body["chargeingMode"] == "1"
    assert clear_body["chargingStartTime"] == "00:00"
    assert clear_body["chargingEndTime"] == "00:00"
    assert clear_body["repeatTimes"] == "0000000"


@pytest.mark.asyncio
async def test_beantech_charging_is_rejected_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    authenticated = await client.authenticate(_credentials(), state=_complete_state())
    assert isinstance(authenticated, ChinaAuthenticated)
    identifier = VehicleIdentifier("LGWTEST0000000003")
    before = len(transport.calls)

    with pytest.raises(GwmRoutePolicyError):
        await client.get_charging_plan(identifier)
    with pytest.raises(GwmRoutePolicyError):
        await client.set_charging_plan(ChargingPlanCommand(identifier, False))

    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_battery_heat_commands_have_empty_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(4)
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    for action in (
        "battery_gun_heat",
        "battery_gun_heat_stop",
        "battery_initiative_heat",
        "battery_initiative_heat_stop",
    ):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(identifier, action)  # type: ignore[arg-type]
        )

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert [body["commands"][0] for body in sends] == [
        {"controlType": "BATTERY_GUN_HEAT_START"},
        {"controlType": "BATTERY_GUN_HEAT_STOP"},
        {"controlType": "BATTERY_INITIATIVE_HEAT_START"},
        {"controlType": "BATTERY_INITIATIVE_HEAT_STOP"},
    ]
    for call in transport.calls:
        if call.operation == "send_vehicle_control_command":
            assert call.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in call.headers


@pytest.mark.asyncio
async def test_beantech_charge_setting_read_request_shape_and_signature() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting()}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    await client.get_bean_tech_charge_setting(VehicleIdentifier(BEAN_VIN))
    request = transport.calls[-1]
    assert request.method == "GET"
    assert request.service == "bean_tech"
    assert request.url == (
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/charge/setting/"
        + BEAN_VIN
        + "?strategy=5"
    )
    assert request.body is None
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET",
        "/app-api/api/v3.0/vehicle/charge/setting/" + BEAN_VIN,
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "strategy=5",
    )


@pytest.mark.asyncio
async def test_beantech_charging_mode_write_reads_then_preserves_charge_set_param() -> None:
    charge_setting = {
        "chargingMode": 1,
        "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:00", "endTime": "07:00"},
            "drivingPlanTimes": [{"day": 1}],
        },
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": charge_setting}],
        set_bean_tech_charging_mode=[
            {"code": "000000", "data": BEAN_COMMAND_ID},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    seq_no = await client.set_bean_tech_charging_mode(identifier, enable=True)

    assert seq_no == BEAN_COMMAND_ID
    read_request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_charge_setting"
    )
    assert (
        urlsplit(read_request.url).path
        == "/app-api/api/v3.0/vehicle/charge/setting/" + BEAN_VIN
    )
    assert urlsplit(read_request.url).query == "strategy=5"

    write_request = next(
        call
        for call in transport.calls
        if call.operation == "set_bean_tech_charging_mode"
    )
    assert urlsplit(write_request.url).path == "/app-api/api/v3.0/vehicle/charge/setting"
    body = json.loads(write_request.body or b"null")
    assert body["vin"] == BEAN_VIN
    assert body["seqNo"] == BEAN_COMMAND_ID
    assert body["chargingMode"] == 0
    assert body["chargeStrategy"] == 5
    assert body["chargeSetParam"] == {
        "customTime": {"startTime": "23:00", "endTime": "07:00"},
        "drivingPlanTimes": [{"day": 1}],
    }


@pytest.mark.asyncio
async def test_beantech_charging_mode_write_aborts_when_setting_incomplete() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[
            {"code": "000000", "data": {"chargingMode": 1}},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_charging_mode(
            VehicleIdentifier(BEAN_VIN), enable=True
        )
    assert [call.operation for call in transport.calls[before:]] == [
        "get_bean_tech_charge_setting"
    ]


@pytest.mark.asyncio
async def test_beantech_charge_setting_rejects_non_beantech_before_transport() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_bean_tech_charge_setting(VehicleIdentifier(VIN))
    with pytest.raises(GwmRoutePolicyError):
        await client.set_bean_tech_charging_mode(VehicleIdentifier(VIN), enable=True)
    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_battery_heating_appointment_read_parses_switch_type() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[
            {
                "code": "000000",
                "data": [
                    {
                        "type": "BATTERY_HEATING_APPOINTMENT",
                        "cmd": "BATTERY_HEATING_APPOINTMENT",
                        "cmdContent": {"switchType": 0},
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

    enabled = await client.get_bean_tech_battery_heating_appointment(
        VehicleIdentifier(BEAN_VIN)
    )

    assert enabled is True
    request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_battery_heating_appointment"
    )
    assert json.loads(request.body or b"null") == {
        "sendType": 0,
        "types": ["BATTERY_HEATING_APPOINTMENT"],
        "userId": "SYNTHETIC-AUTO-USER",
        "vin": BEAN_VIN,
    }
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST",
        "/app-api/api/v3.0/vehicle/remote-ctrl/config/query",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "json=" + (request.body or b"").decode(),
    )


@pytest.mark.asyncio
async def test_beantech_battery_heating_appointment_set_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_battery_heating_appointment=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    await client.set_bean_tech_battery_heating_appointment(
        identifier, enable=True, use_car_time_ms=1735689600000
    )
    await client.set_bean_tech_battery_heating_appointment(identifier, enable=False)

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "set_bean_tech_battery_heating_appointment"
    ]
    assert [body["commands"][0] for body in sends] == [
        {
            "controlType": "BATTERY_HEATING_APPOINTMENT",
            "cmdBody": {"useCarTime": 1735689600000},
        },
        {"controlType": "BATTERY_TC_STOP"},
    ]
    for request in transport.calls:
        if request.operation == "set_bean_tech_battery_heating_appointment":
            assert "securityToken" not in request.headers


@pytest.mark.asyncio
async def test_beantech_charge_soc_cmdbody() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_charge_soc=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    await client.set_bean_tech_charge_soc(VehicleIdentifier(BEAN_VIN), percent=80)

    request = next(
        call for call in transport.calls if call.operation == "set_bean_tech_charge_soc"
    )
    body = json.loads(request.body or b"null")
    assert body["commands"][0] == {
        "controlType": "CTRL_CHARGE_SOC",
        "cmdBody": {"chargeSoc": 80},
    }
    assert "securityToken" not in request.headers


@pytest.mark.asyncio
async def test_beantech_charge_window_write_updates_custom_time() -> None:
    charge_setting = {
        "chargingMode": 0,
        "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:00", "endTime": "07:00"},
            "drivingPlanTimes": [{"day": 1}],
        },
    }
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": charge_setting}],
        set_bean_tech_charge_window=[{"code": "000000", "data": BEAN_COMMAND_ID}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    seq_no = await client.set_bean_tech_charge_window(
        VehicleIdentifier(BEAN_VIN), start_time="22:00", end_time="06:30"
    )

    assert seq_no == BEAN_COMMAND_ID
    write_request = next(
        call for call in transport.calls if call.operation == "set_bean_tech_charge_window"
    )
    body = json.loads(write_request.body or b"null")
    assert body["chargingMode"] == 0
    assert body["chargeStrategy"] == 5
    assert body["chargeSetParam"]["customTime"] == {
        "startTime": "22:00",
        "endTime": "06:30",
    }
    assert body["chargeSetParam"]["drivingPlanTimes"] == [{"day": 1}]


@pytest.mark.asyncio
async def test_beantech_charge_window_rejects_malformed_clock_time() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    before = len(transport.calls)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_charge_window(
            VehicleIdentifier(BEAN_VIN), start_time="25:00", end_time="07:00"
        )
    assert len(transport.calls) == before


@pytest.mark.asyncio
async def test_beantech_charge_result_request_uses_msg_type_charge() -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_remote_command_result=[{"code": "000000", "data": {"beanTechMesg": []}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    command_id = "0" * 32 + "9359"
    await client.get_remote_command_results(VehicleIdentifier(BEAN_VIN), command_id, control_action="charging_mode")
    request = transport.calls[-1]
    assert "/app-api/api/v3.0/vehicle/remote-ctrl/result" in request.url
    assert "msgType=charge" in request.url
    assert BEAN_VIN in request.url
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "GET",
        "/app-api/api/v3.0/vehicle/remote-ctrl/result",
        request.headers["bt-auth-nonce"],
        request.headers["bt-auth-timestamp"],
        "msgtype=charge" + "seqno=" + command_id + "vin=" + BEAN_VIN,
    )


@pytest.mark.asyncio
async def test_beantech_charge_result_polling_uses_msg_type_charge() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[
            {
                "code": "000000",
                "data": {
                    "messageList": [
                        {
                            "messageType": "charge",
                            "messageData": {
                                "resultCode": "0",
                                "resultMessage": "充电设置成功",
                            },
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
    identifier = VehicleIdentifier(BEAN_VIN)
    results = await client.get_remote_command_results(
        identifier, BEAN_COMMAND_ID, control_action="charging_mode"
    )
    assert results == (
        RemoteCommandResultItem(BEAN_COMMAND_ID, "charge", "0", "充电设置成功"),
    )
    request = transport.calls[-1]
    assert "msgType=charge" in request.url


_CHARGING_CLIENT_CALLS = [
    ("get_bean_tech_charge_setting", {}),
    ("set_bean_tech_charging_mode", {"enable": True}),
    ("get_bean_tech_battery_heating_appointment", {}),
    ("get_bean_tech_switch_status", {}),
    ("set_bean_tech_battery_heating_appointment", {"enable": True, "use_car_time_ms": 1790000000000}),
    ("set_bean_tech_charge_soc", {"percent": 70}),
    ("set_bean_tech_charge_window", {"start_time": "22:00"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", _CHARGING_CLIENT_CALLS)
@pytest.mark.parametrize("identifier", [VIN, "LGWUNKNOWN0000001"])
async def test_charging_client_rejects_other_platforms_before_io(method, kwargs, identifier):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    count = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await getattr(client, method)(VehicleIdentifier(identifier), **kwargs)
    assert len(transport.calls) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", _CHARGING_CLIENT_CALLS)
@pytest.mark.parametrize("identifier", [None, BEAN_VIN, {}, 123])
async def test_charging_client_validates_identifier_before_authentication(method, kwargs, identifier):
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await getattr(_client(transport), method)(identifier, **kwargs)
    assert not transport.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", [
    *[("set_bean_tech_charge_soc", {"percent": value}) for value in (True, 70.0, "70", 49, 101, 55, None, [], {})],
    *[("set_bean_tech_charging_mode", {"enable": value}) for value in (0, 1, "0", None, [], {})],
    *[("set_bean_tech_battery_heating_appointment", {"enable": True, "use_car_time_ms": value})
      for value in (True, 0, -1, 1790000000000.0, "1790000000000", 253402214399001, None, [], {})],
    ("set_bean_tech_battery_heating_appointment", {"enable": 1, "use_car_time_ms": 1790000000000}),
    ("set_bean_tech_battery_heating_appointment", {"enable": False, "use_car_time_ms": 1790000000000}),
    *[("set_bean_tech_charge_window", {"start_time": value}) for value in (None, True, 800, [], {}, "8:00", "24:00", "08:60", "")],
    ("set_bean_tech_charge_window", {"end_time": "bad"}),
])
async def test_charging_client_validates_values_without_network(method, kwargs):
    transport = _FakeTransport()
    with pytest.raises(GwmConfigurationError):
        await getattr(_client(transport), method)(VehicleIdentifier(BEAN_VIN), **kwargs)
    assert not transport.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    *[("chargingMode", value) for value in (None, True, False, 0.0, 1.0, 2, "2", " 0", "", [], {})],
    *[("chargeStrategy", value) for value in (None, True, False, 5.0, -1, "-1", "5.5", "", [], {})],
    *[("chargeSetParam", value) for value in (None, [], False, "invalid", {"customTime": []}, {"customTime": {}},
      {"customTime": {"startTime": "23:00"}}, {"customTime": {"startTime": "23:00", "endTime": "25:00"}})],
])
async def test_charging_settings_reject_ambiguous_values_and_abort_writes(field, value):
    data = _charging_setting(**{field: value})
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=True)
    assert [request.operation for request in transport.calls[before:]] == ["get_bean_tech_charge_setting"]


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, [], False, 0, "setting", {}])
async def test_charging_setting_missing_or_malformed_is_not_a_default_schedule(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_charge_setting(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,strategy", [(0, 5), (1, 3), ("0", "5"), ("1", "0")])
async def test_charging_setting_normalizes_mode_and_preserves_the_complete_plan(mode, strategy):
    data = _charging_setting(chargingMode=mode, chargeStrategy=strategy)
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
                               get_bean_tech_charge_setting=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.get_bean_tech_charge_setting(VehicleIdentifier(BEAN_VIN))
    assert result == _charging_setting(chargingMode=int(mode), chargeStrategy=int(strategy))
    assert result["chargeSetParam"] == data["chargeSetParam"]


@pytest.mark.asyncio
@pytest.mark.parametrize("enable,mode", [(True, 0), (False, 1)])
async def test_smart_charging_changes_only_mode_preserving_app_fields(enable, mode):
    data = _charging_setting(chargingMode=1 - mode)
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": data}],
        set_bean_tech_charging_mode=[{"code": "000000", "data": {}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=enable) == BEAN_COMMAND_ID
    body = json.loads(transport.calls[-1].body)
    assert body == {"vin": BEAN_VIN, "chargingMode": mode, "chargeStrategy": 5,
                    "chargeSetParam": data["chargeSetParam"], "seqNo": BEAN_COMMAND_ID}


@pytest.mark.asyncio
@pytest.mark.parametrize("updates,start,end", [({"start_time": "22:00"}, "22:00", "07:07"),
    ({"end_time": "08:00"}, "23:03", "08:00"), ({"start_time": "21:00", "end_time": "06:00"}, "21:00", "06:00")])
async def test_charging_window_edits_only_requested_bounds_from_fresh_app_settings(updates, start, end):
    data = _charging_setting(chargingMode=0, chargeStrategy="3")
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": data}],
        set_bean_tech_charge_window=[{"code": "000000", "data": {}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.set_bean_tech_charge_window(VehicleIdentifier(BEAN_VIN), **updates) == BEAN_COMMAND_ID
    expected_params = {**data["chargeSetParam"], "customTime": {"startTime": start, "endTime": end, "extension": "keep"}}
    assert json.loads(transport.calls[-1].body) == {"vin": BEAN_VIN, "chargingMode": 0, "chargeStrategy": 3,
        "chargeSetParam": expected_params, "seqNo": BEAN_COMMAND_ID}
    assert data["chargeSetParam"]["customTime"]["startTime"] == "23:03"


@pytest.mark.asyncio
@pytest.mark.parametrize("params,updates,error", [({}, {"start_time": "22:00"}, GwmSchemaError),
    ({"customTime": None}, {"end_time": "08:00"}, GwmSchemaError),
    ({"customTime": {"startTime": "22:00", "endTime": "08:00"}}, {"end_time": "22:00"}, GwmConfigurationError)])
async def test_charging_window_never_invents_a_missing_bound_or_ambiguous_full_day(params, updates, error):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting(chargeSetParam=params)}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(error):
        await client.set_bean_tech_charge_window(VehicleIdentifier(BEAN_VIN), **updates)
    assert transport.calls[-1].operation == "get_bean_tech_charge_setting"


@pytest.mark.asyncio
@pytest.mark.parametrize("value,expected", [(0, True), ("0", True), (1, False), ("1", False)])
async def test_battery_appointment_inverted_switch_values(value, expected):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": [{"cmdContent": {"switchType": value}}]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN)) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, {}, [None], [{}], [{"cmdContent": None}],
    *[[{"cmdContent": {"switchType": value}}] for value in (None, True, False, 0.0, 1.0, "2", 2, [], {})]])
async def test_battery_appointment_schema_rejects_ambiguous_state(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,expected", [({}, {"insertGunKeepWarm": None, "activeKeepWarm": None}),
    ({"insertGunKeepWarm": 1, "activeKeepWarm": "0"}, {"insertGunKeepWarm": True, "activeKeepWarm": False}),
    ({"insertGunKeepWarm": "0", "activeKeepWarm": 1}, {"insertGunKeepWarm": False, "activeKeepWarm": True})])
async def test_battery_switch_status_maps_exact_values_and_missing_fields(raw, expected):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_switch_status=[{"code": "000000", "data": {"switchStatus": raw}}],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": []}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_switch_status(VehicleIdentifier(BEAN_VIN)) == expected
    assert await client.get_bean_tech_battery_heating_appointment(VehicleIdentifier(BEAN_VIN)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, [], {}, {"switchStatus": None}, {"switchStatus": []},
    *[{"switchStatus": {"insertGunKeepWarm": value}} for value in (True, False, 0.0, 1.0, 2, "on", [], {})]])
async def test_battery_switch_status_rejects_unrecognized_state(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_switch_status=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_switch_status(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("method,kwargs", [case for case in _CHARGING_CLIENT_CALLS if case[0].startswith("set_")])
@pytest.mark.parametrize("failure", [{}, {"data": {}}, {"code": "551210"}, {"code": "7"}, OSError("synthetic network failure")])
async def test_charging_writes_require_explicit_acceptance_without_retry(method, kwargs, failure):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting()}], **{method: [failure]})
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await getattr(client, method)(VehicleIdentifier(BEAN_VIN), **kwargs)
    assert sum(request.operation == method for request in transport.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["battery_gun_heat", "battery_gun_heat_stop", "battery_initiative_heat", "battery_initiative_heat_stop",
    "charging_mode", "charge_window", "charge_soc", "battery_appointment"])
@pytest.mark.parametrize("code,state", [("2", "pending"), ("3", "pending"), ("0", "completed"), ("7", "failed")])
async def test_charging_results_use_typed_routes_and_pending_semantics(action, code, state):
    family = "charge" if action in {"charging_mode", "charge_window"} else "remote"
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_remote_command_result=[{"code": "000000", "data": {"messageList": [{"messageType": family,
            "messageData": {"resultCode": code, "transactionId": "provider-different-id"}}]}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_results(VehicleIdentifier(VIN), BEAN_COMMAND_ID, control_action=action)
    results = await client.get_remote_command_results(VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action)
    expected_code = "2000" if code in {"2", "3"} else code
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, family, expected_code, None),)
    result = select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None, expected_remote_type="charge" if family == "charge" else "china")
    assert result.state == state
    assert transport.calls[-1].url.endswith("&msgType=" + family)


@pytest.mark.asyncio
async def test_concurrent_charge_window_edits_preserve_each_other_and_app_fields():
    started, release = asyncio.Event(), asyncio.Event()
    settings = _charging_setting()
    operations = []
    class Transport(_FakeTransport):
        async def execute(self, request, **kwargs):
            if request.operation == "get_bean_tech_charge_setting":
                operations.append("read")
                if not started.is_set():
                    started.set()
                    await release.wait()
                return _response({"code": "000000", "data": settings})
            if request.operation == "set_bean_tech_charge_window":
                operations.append("write")
                settings.update(json.loads(request.body))
                return _response({"code": "000000"})
            return await super().execute(request, **kwargs)
    transport = Transport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    start = asyncio.create_task(client.set_bean_tech_charge_window(identifier, start_time="22:00"))
    tasks = [start]
    try:
        await asyncio.wait_for(started.wait(), 5)
        tasks.append(asyncio.create_task(client.set_bean_tech_charge_window(identifier, end_time="08:00")))
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 5)
    finally:
        release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert operations == ["read", "write", "read", "write"]
    expected = _charging_setting()
    expected["chargeSetParam"]["customTime"].update(startTime="22:00", endTime="08:00")
    assert settings == {**expected, "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID}


@pytest.mark.asyncio
async def test_cancelled_charge_setting_read_never_submits_a_write():
    started = asyncio.Event()
    class Transport(_FakeTransport):
        async def execute(self, request, **kwargs):
            if request.operation == "get_bean_tech_charge_setting":
                started.set()
                await asyncio.Event().wait()
            return await super().execute(request, **kwargs)
    transport = Transport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    task = asyncio.create_task(client.set_bean_tech_charging_mode(VehicleIdentifier(BEAN_VIN), enable=True))
    try:
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert not any(call.operation == "set_bean_tech_charging_mode" for call in transport.calls)


@pytest.mark.parametrize("failure", [None, "bad", RuntimeError("private-source-error")])
def test_charge_result_builder_rejects_invalid_nonce_without_exposing_source(failure):
    client = _client(_FakeTransport())
    def nonce():
        if isinstance(failure, Exception):
            raise failure
        return failure
    client._nonce_source = nonce
    with pytest.raises(GwmConfigurationError) as raised:
        client._build_bean_tech_charge_result_request(_complete_state(), VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID)
    assert "private-source-error" not in str(raised.value)


@pytest.mark.parametrize("state", [_empty_state(), _partial_state()])
def test_charge_result_builder_rejects_incomplete_authentication(state):
    with pytest.raises(GwmAuthenticationError):
        _client(_FakeTransport())._build_bean_tech_charge_result_request(state, VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID)


def test_battery_appointment_query_builder_requires_user_id():
    with pytest.raises(GwmAuthenticationError):
        _client(_FakeTransport())._build_bean_tech_config_query_request(
            _partial_state(), VehicleIdentifier(BEAN_VIN),
            types=["BATTERY_HEATING_APPOINTMENT"], operation="get_bean_tech_battery_heating_appointment",
        )
