"""Offline mainland-China comfort behavior and protocol contracts."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from support.china import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    FIXTURE,
    SENSITIVE,
    UNSUPPORTED_VIN,
    VIN,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
    _Wait,
)

from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthenticated,
    ChinaClient,
)
from custom_components.gwm_ora.gwm_client.china_crypto import bean_tech_sign
from custom_components.gwm_ora.gwm_client.commands import (
    ChinaVehicleControlCommand,
    ClimateCommand,
    RemoteCommandResultItem,
    select_remote_command_result,
)
from custom_components.gwm_ora.gwm_client.errors import (
    GwmAuthenticationError,
    GwmClientError,
    GwmConfigurationError,
    GwmNetworkError,
    GwmRateLimitError,
    GwmRoutePolicyError,
    GwmSchemaError,
)
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier


@pytest.mark.asyncio
async def test_beantech_climate_start_and_stop_use_timely_without_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[
            {"code": "000000", "data": {}},
            {"code": "000000", "data": {}},
        ],
        set_bean_tech_ac_temperature=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)

    started = await client.send_climate_command(
        ClimateCommand(identifier, "auto", 22, 15)
    )
    stopped = await client.send_climate_command(
        ClimateCommand(identifier, "off", 22, 15)
    )

    assert started.command_id == stopped.command_id == BEAN_COMMAND_ID
    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_climate_command"
    ]
    assert sends[0]["commands"] == [
        {
            "controlType": "AIR_CONDITIONER_START",
            "cmdBody": {
                "allowStartEng": 1,
                "operationTime": 900,
                "temperature": 22,
            },
        }
    ]
    assert sends[1]["commands"] == [{"controlType": "AIR_CONDITIONER_STOP"}]
    for request in transport.calls:
        if request.operation == "send_climate_command":
            assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in request.headers
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


@pytest.mark.asyncio
async def test_beantech_comfort_off_multicommand_shape() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "comfort_off")
    )

    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert "securityToken" not in sent.headers
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )
    body = json.loads(sent.body or b"null")
    assert body["sendType"] == 1
    assert body["commands"] == [
        {"controlType": "AIR_CONDITIONER_STOP"},
        {
            "controlType": "SEAT_HEATING_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 1, "rightFront": 0},
        },
        {
            "controlType": "SEAT_VENTILATION_STOP",
            "cmdBody": {"leftFront": 0, "operationMode": 2, "rightFront": 0},
        },
        {"controlType": "STEERING_WHEEL_HEATLESS"},
    ]


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_request_shape() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        set_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )

    await client.set_bean_tech_cabin_clean_appointment(
        VehicleIdentifier(BEAN_VIN), time_ms=1735689600000
    )

    request = next(
        call
        for call in transport.calls
        if call.operation == "set_bean_tech_cabin_clean_appointment"
    )
    assert json.loads(request.body or b"null") == {
        "commands": [
            {
                "controlType": "CABIN_CLEANING_START",
                "cmdBody": {"operationTime": 60},
            }
        ],
        "subscribeType": 0,
        "time": 1735689600000,
        "vin": BEAN_VIN,
    }


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_read_parses_time() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_cabin_clean_appointment=[
            {
                "code": "000000",
                "data": [
                    {
                        "subscribeType": 0,
                        "controlType": "CABIN_CLEANING_START",
                        "cmd": "CABIN_CLEANING_START",
                        "cmdContent": {"operationTime": 60},
                        "time": 1788375600000,
                        "takeEffect": 2,
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

    time_ms = await client.get_bean_tech_cabin_clean_appointment(
        VehicleIdentifier(BEAN_VIN)
    )

    assert time_ms == 1788375600000
    request = next(
        call
        for call in transport.calls
        if call.operation == "get_bean_tech_cabin_clean_appointment"
    )
    assert request.method == "GET"
    assert request.url.endswith(
        "/app-api/api/v3.0/vehicle/remote-ctrl/subscribe/"
        + BEAN_VIN
        + "?cmds=CABIN_CLEANING_START&type=0"
    )
    assert request.body is None


@pytest.mark.asyncio
async def test_beantech_comfort_modes_reject_non_mapping_entries() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[
            {"code": "000000", "data": ["not-a-mapping"]},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_comfort_modes(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
async def test_beantech_comfort_mode_rejects_missing_mode_id() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[
            {"code": "000000", "data": [{"type": "1"}]},
        ],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(
            VehicleIdentifier(BEAN_VIN), mode_type="warm"
        )


@pytest.mark.asyncio
async def test_beantech_cabin_clean_appointment_read_returns_none_when_unset() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": []}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    assert (
        await client.get_bean_tech_cabin_clean_appointment(
            VehicleIdentifier(BEAN_VIN)
        )
        is None
    )


_COMFORT_CONTRACTS = (
    ("seat_heating_start", "SEAT_HEATING_START", {"leftFront": 3, "operationTime": 600}),
    ("seat_heating_stop", "SEAT_HEATING_STOP", {"leftFront": 0, "operationMode": 1}),
    ("seat_heating_start_passenger", "SEAT_HEATING_START", {"rightFront": 3, "operationTime": 600}),
    ("seat_heating_stop_passenger", "SEAT_HEATING_STOP", {"rightFront": 0, "operationMode": 1}),
    ("seat_ventilation_start", "SEAT_VENTILATION_START", {"leftFront": 3, "operationTime": 600}),
    ("seat_ventilation_stop", "SEAT_VENTILATION_STOP", {"leftFront": 0, "operationMode": 2}),
    ("seat_ventilation_start_passenger", "SEAT_VENTILATION_START", {"rightFront": 3, "operationTime": 600}),
    ("seat_ventilation_stop_passenger", "SEAT_VENTILATION_STOP", {"rightFront": 0, "operationMode": 2}),
    ("steering_wheel_heating", "STEERING_WHEEL_HEATING", {"operationTime": 600}),
    ("steering_wheel_heatless", "STEERING_WHEEL_HEATLESS", None),
    ("defrost_front_start", "DEFROST_FRONT_START", {"operationTime": 900}),
    ("defrost_front_stop", "DEFROST_FRONT_STOP", None),
    ("defrost_back_start", "DEFROST_BACK_START", {"operationTime": 900}),
    ("defrost_back_stop", "DEFROST_BACK_STOP", None),
    ("cabin_clean", "CABIN_CLEANING_START", {"operationTime": 60}),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("action,control_type,command_body", _COMFORT_CONTRACTS)
async def test_beantech_comfort_captured_payloads_and_navinfo_isolation(
    action: str, control_type: str, command_body: object,
) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    acceptance = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action)  # type: ignore[arg-type]
    )
    assert acceptance.command_id == BEAN_COMMAND_ID
    request = transport.calls[-1]
    command = {"controlType": control_type}
    if command_body is not None:
        command["cmdBody"] = command_body
    assert json.loads(request.body) == {
        "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID, "sendType": 0, "commands": [command],
    }
    assert request.url == "https://gw-app-gateway.gwmapp-h.com/app-api/api/v3.0/vehicle/remote-ctrl/timely"
    assert "securityToken" not in request.headers
    assert request.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", urlsplit(request.url).path, FIXTURE["nonce"], request.headers["bt-auth-timestamp"],
        "json=" + request.body.decode(),
    )
    before = len(transport.calls)
    for vin in (VIN, UNSUPPORTED_VIN):
        with pytest.raises(GwmRoutePolicyError):
            await client.send_vehicle_control_command(
                ChinaVehicleControlCommand(VehicleIdentifier(vin), action)  # type: ignore[arg-type]
            )
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("minutes,temperature", [(5, 17), (6, 22), (30, 31)])
async def test_beantech_climate_companion_config_preserves_units(minutes: int, temperature: int) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000"}],
        set_bean_tech_ac_temperature=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    accepted = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", temperature, minutes))
    assert accepted.command_id == BEAN_COMMAND_ID
    control = {"controlType": "AIR_CONDITIONER_START", "cmdBody": {
        "allowStartEng": 1, "operationTime": minutes * 60, "temperature": temperature,
    }}
    send, config = transport.calls[-2:]
    assert json.loads(send.body)["commands"] == [control]
    assert json.loads(config.body) == {"configs": [control], "vin": BEAN_VIN}
    assert config.url.endswith("/remote-ctrl/config")
    assert config.headers["bt-auth-sign"] == bean_tech_sign(
        "POST", urlsplit(config.url).path, FIXTURE["nonce"], config.headers["bt-auth-timestamp"],
        "json=" + config.body.decode(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [GwmNetworkError(), GwmAuthenticationError(), {"code": "551210"}, {}])
async def test_beantech_climate_companion_failure_retains_accepted_command(failure: object, caplog) -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000"}], set_bean_tech_ac_temperature=[failure],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15))
    assert result.command_id == BEAN_COMMAND_ID
    assert Counter(call.operation for call in transport.calls)["send_climate_command"] == 1
    assert "was accepted" in caplog.text
    assert BEAN_VIN not in caplog.text
    assert BEAN_COMMAND_ID not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("mode_type,expected_id,expected_type", [("warm", "123", "1"), ("cool", "456", "2"), ("common", "456", "2")])
async def test_beantech_comfort_modes_normalize_and_send_dynamic_selection(mode_type, expected_id, expected_type) -> None:
    modes = [{"modeId": 123, "type": 1, "commonUseMode": "0"}, {"modeId": "456", "type": "2", "commonUseMode": 1}]
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_comfort_modes=[{"code": "000000", "data": modes}] * 2,
        set_bean_tech_comfort_mode=[{"code": "000000"}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    assert await client.get_bean_tech_comfort_modes(identifier) == (
        {"modeId": "123", "type": "1", "commonUseMode": 0},
        {"modeId": "456", "type": "2", "commonUseMode": 1},
    )
    command_id = await client.set_bean_tech_comfort_mode(identifier, mode_type=mode_type)
    assert command_id == BEAN_COMMAND_ID
    request = transport.calls[-1]
    assert json.loads(request.body) == {
        "vin": BEAN_VIN, "seqNo": BEAN_COMMAND_ID, "sendType": 0,
        "commands": [{"controlType": "COMFORT_MODE_CTRL", "cmdBody": {
            "action": 1, "modeId": expected_id, "type": expected_type,
        }}],
    }
    assert "securityToken" not in request.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("modeId", None), ("modeId", ""), ("modeId", " "), ("modeId", True), ("modeId", 0),
    ("modeId", 1.0), ("modeId", []), ("modeId", "private\nvalue"),
    pytest.param("modeId", "x" * 129, id="oversized-mode-id"),
    ("type", None), ("type", 0), ("type", 3), ("type", True), ("type", 1.0), ("type", []),
    ("commonUseMode", None), ("commonUseMode", 2), ("commonUseMode", True), ("commonUseMode", 1.0), ("commonUseMode", []),
])
async def test_beantech_comfort_mode_schema_rejects_before_command(field, value) -> None:
    mode = {"modeId": "123", "type": "1", "commonUseMode": 1, field: value}
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [mode]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type="common")
    assert not any(call.operation == "set_bean_tech_comfort_mode" for call in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, {}, "bad", [None], [{"time": True}], [{"time": 0}], [{"time": -1}], [{"time": 1.5}], [{"time": "1735689600000"}], [{"time": 253402214399001}]])
async def test_beantech_appointment_read_rejects_malformed_data(data: object) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.get_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, True, 0, -1, "1735689600000", 1.5, [], 253402214399001])
async def test_beantech_appointment_rejects_invalid_timestamp_before_io(value: object) -> None:
    transport = _FakeTransport()
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN), time_ms=value)  # type: ignore[arg-type]
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, True, "", "invalid", []])
async def test_beantech_comfort_rejects_invalid_mode_before_io(value: object) -> None:
    transport = _FakeTransport()
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type=value)  # type: ignore[arg-type]
    assert transport.calls == []


async def _submit_beantech_feature(client: ChinaClient, feature: str, vin: str = BEAN_VIN):
    identifier = VehicleIdentifier(vin)
    if feature == "climate":
        return await client.send_climate_command(ClimateCommand(identifier, "off", 22, 15))
    if feature == "comfort_mode":
        return await client.set_bean_tech_comfort_mode(identifier, mode_type="warm")
    if feature == "appointment":
        return await client.set_bean_tech_cabin_clean_appointment(identifier, time_ms=1735689600000)
    return await client.send_vehicle_control_command(ChinaVehicleControlCommand(identifier, "comfort_off"))


@pytest.mark.asyncio
@pytest.mark.parametrize("feature,operation", [("climate", "send_climate_command"), ("comfort_mode", "set_bean_tech_comfort_mode"), ("appointment", "set_bean_tech_cabin_clean_appointment"), ("comfort_off", "send_vehicle_control_command")])
@pytest.mark.parametrize("failure", [{}, {"data": {}}, {"code": None}, {"code": "551210"}, GwmNetworkError(), GwmRateLimitError()])
async def test_beantech_new_submissions_require_acceptance_and_never_retry(feature, operation, failure) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [{"modeId": "123", "type": "1"}]}], **{operation: [failure]})
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmClientError):
        await _submit_beantech_feature(client, feature)
    assert Counter(call.operation for call in transport.calls)[operation] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("feature", ["comfort_mode", "appointment", "comfort_off"])
@pytest.mark.parametrize("vin", [VIN, UNSUPPORTED_VIN])
async def test_beantech_new_writes_reject_other_platforms_before_transport(feature: str, vin: str) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmRoutePolicyError):
        await _submit_beantech_feature(client, feature, vin)
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["climate", "comfort_mode", "comfort_off"] + [row[0] for row in _COMFORT_CONTRACTS])
@pytest.mark.parametrize("code,state", [(2, "pending"), (3, "pending"), (0, "completed"), (7, "failed")])
async def test_beantech_new_actions_use_timely_result_semantics(action, code, state) -> None:
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_remote_command_result=[{"code": "000000", "data": {"messageList": [{"messageType": "remote", "messageData": {"transactionId": "provider-internal", "resultCode": code}}]}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    results = await client.get_remote_command_results(VehicleIdentifier(BEAN_VIN), BEAN_COMMAND_ID, control_action=action)
    assert results == (RemoteCommandResultItem(BEAN_COMMAND_ID, "remote", "2000" if code in {2, 3} else str(code), None),)
    assert select_remote_command_result(results, command_id=BEAN_COMMAND_ID, region=None).state == state
    assert urlsplit(transport.calls[-1].url).path == "/app-api/api/v3.0/vehicle/remote-ctrl/result"


async def _beantech_feature_request(kind):
    """Capture a valid request from the public client before testing wire mutations."""
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_climate_command=[{"code": "000000"}],
        set_bean_tech_ac_temperature=[{"code": "000000"}],
        send_vehicle_control_command=[{"code": "000000"}],
        get_bean_tech_comfort_modes=[{"code": "000000", "data": [{"modeId": "123", "type": "1"}]}],
        set_bean_tech_comfort_mode=[{"code": "000000"}],
        set_bean_tech_cabin_clean_appointment=[{"code": "000000"}],
        get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": []}],
    )
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    if kind in {"climate", "climate_stop", "config"}:
        await client.send_climate_command(ClimateCommand(identifier, "off" if kind == "climate_stop" else "auto", 22, 15))
        operation = "set_bean_tech_ac_temperature" if kind == "config" else "send_climate_command"
    elif kind == "subscribe":
        await client.set_bean_tech_cabin_clean_appointment(identifier, time_ms=1735689600000)
        operation = "set_bean_tech_cabin_clean_appointment"
    elif kind == "subscribe_get":
        await client.get_bean_tech_cabin_clean_appointment(identifier)
        operation = "get_bean_tech_cabin_clean_appointment"
    elif kind == "comfort_get":
        await client.get_bean_tech_comfort_modes(identifier)
        operation = "get_bean_tech_comfort_modes"
    elif kind == "comfort_mode":
        await client.set_bean_tech_comfort_mode(identifier, mode_type="warm")
        operation = "set_bean_tech_comfort_mode"
    else:
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(identifier, "seat_heating_stop" if kind == "seat" else "comfort_off"))
        operation = "send_vehicle_control_command"
    return next(request for request in transport.calls if request.operation == operation)


@pytest.mark.parametrize("kind", ["climate", "climate_stop", "seat", "comfort_mode", "comfort_off", "config", "subscribe", "subscribe_get", "comfort_get"])
@pytest.mark.parametrize("mutation", ["host", "path", "method", "service", "operation", "token", "signature", "content_type", "vin_header"])
@pytest.mark.asyncio
async def test_beantech_new_routes_reject_wrong_destinations_and_headers(kind, mutation):
    request = await _beantech_feature_request(kind)
    headers, changes = dict(request.headers), {}
    if mutation == "host":
        changes["url"] = request.url.replace("gw-app-gateway.gwmapp-h.com", "example.invalid")
    elif mutation == "path":
        changes["url"] = request.url + "/unexpected"
    elif mutation == "method":
        changes["method"] = "POST" if request.method == "GET" else "GET"
    elif mutation == "service":
        changes["service"] = "auto_ai"
    elif mutation == "operation":
        changes["operation"] = "send_lock_command"
    elif mutation == "token":
        headers["securityToken"] = SENSITIVE
    elif mutation == "signature":
        headers["bt-auth-sign"] = "0" * 32
    elif mutation == "content_type":
        headers["Content-Type"] = "text/plain"
    else:
        headers["vin"] = VIN
    with pytest.raises(ValueError, match="route_invalid"):
        replace(request, headers=headers, **changes)


@pytest.mark.parametrize("kind", ["climate", "climate_stop", "seat", "comfort_mode", "comfort_off", "config", "subscribe"])
@pytest.mark.parametrize("mutation", ["list", "null", "malformed", "missing", "extra", "wrong_vin", "boolean", "command", "command_body"])
@pytest.mark.asyncio
async def test_beantech_new_post_schemas_reject_resigned_malformed_payloads(kind, mutation):
    request = await _beantech_feature_request(kind)
    headers = dict(request.headers)
    body = json.loads(request.body)
    if mutation == "list":
        raw = b"[]"
    elif mutation == "null":
        raw = b"null"
    elif mutation == "malformed":
        raw = b"{"
    else:
        if mutation == "missing":
            body.pop(next(iter(body)))
        elif mutation == "extra":
            body["isSaveConfig"] = None
        elif mutation == "wrong_vin":
            body["vin"] = VIN
        elif mutation == "boolean":
            if "sendType" in body:
                body["sendType"] = bool(body["sendType"])
            elif "subscribeType" in body:
                body["subscribeType"] = False
            else:
                body["configs"][0]["cmdBody"]["allowStartEng"] = True
        elif mutation == "command":
            key = "configs" if kind == "config" else "commands"
            body[key] = [{"controlType": "VEHICLE_UNLOCK"}]
        else:
            key = "configs" if kind == "config" else "commands"
            body[key][0]["cmdBody"] = {"unexpected": 1}
        raw = json.dumps(body, separators=(",", ":")).encode()
    headers["bt-auth-sign"] = bean_tech_sign("POST", urlsplit(request.url).path, headers["bt-auth-nonce"], headers["bt-auth-timestamp"], "json=" + raw.decode())
    with pytest.raises(ValueError, match="route_invalid"):
        replace(request, body=raw, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [16, 32])
async def test_beantech_climate_rejects_out_of_range_temperature_before_send(temperature):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    with pytest.raises(GwmConfigurationError):
        await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", temperature, 15))
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get_bean_tech_comfort_modes", "get_bean_tech_cabin_clean_appointment"])
async def test_beantech_new_reads_reject_bad_identifiers_and_other_platforms(method):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]])
    client = _client(transport)
    with pytest.raises(GwmConfigurationError):
        await getattr(client, method)(BEAN_VIN)
    assert transport.calls == []
    await client.authenticate(_credentials(), state=_complete_state())
    before = len(transport.calls)
    for vin in (VIN, UNSUPPORTED_VIN):
        with pytest.raises(GwmRoutePolicyError):
            await getattr(client, method)(VehicleIdentifier(vin))
    assert len(transport.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [[], [{"modeId": "123", "type": "2", "commonUseMode": 0}]])
@pytest.mark.parametrize("mode", ["warm", "common"])
async def test_beantech_missing_requested_comfort_mode_is_a_schema_error(data, mode):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    with pytest.raises(GwmSchemaError):
        await client.set_bean_tech_comfort_mode(VehicleIdentifier(BEAN_VIN), mode_type=mode)
    assert not any(call.operation == "set_bean_tech_comfort_mode" for call in transport.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [[{}], [{"time": None}]])
async def test_beantech_missing_appointment_time_is_unset(data):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_cabin_clean_appointment=[{"code": "000000", "data": data}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    assert await client.get_bean_tech_cabin_clean_appointment(VehicleIdentifier(BEAN_VIN)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sequence", [None, "invalid", 1, "raise"])
@pytest.mark.parametrize("feature", ["climate", "comfort_off", "comfort_mode"])
async def test_beantech_sequence_failure_prevents_physical_command(sequence, feature):
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], get_bean_tech_comfort_modes=[{"code": "000000", "data": [{"modeId": "123", "type": "1"}]}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    def source():
        if sequence == "raise":
            raise ValueError(SENSITIVE)
        return sequence
    client._sequence_source = source
    with pytest.raises(GwmConfigurationError) as error:
        await _submit_beantech_feature(client, feature)
    assert SENSITIVE not in str(error.value)
    assert all(not call.operation.startswith(("send_", "set_")) for call in transport.calls)


@pytest.mark.parametrize("kind,changes", [
    ("config", {"configs": [{"controlType": "AIR_CONDITIONER_START", "cmdBody": None}]}),
    ("comfort_mode", {"commands": [{"controlType": "COMFORT_MODE_CTRL", "cmdBody": None}]}),
    ("comfort_mode", {"commands": []}),
    ("comfort_mode", {"commands": [None]}),
])
@pytest.mark.asyncio
async def test_beantech_new_schemas_reject_incomplete_commands(kind, changes):
    request = await _beantech_feature_request(kind)
    body = json.loads(request.body)
    body.update(changes)
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = dict(request.headers)
    headers["bt-auth-sign"] = bean_tech_sign("POST", urlsplit(request.url).path, headers["bt-auth-nonce"], headers["bt-auth-timestamp"], "json=" + raw.decode())
    with pytest.raises(ValueError):
        replace(request, body=raw, headers=headers)


@pytest.mark.asyncio
async def test_beantech_climate_companion_timeout_keeps_the_accepted_id():
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_climate_command=[{"code": "000000"}], set_bean_tech_ac_temperature=[_Wait()])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    # Leave room for command acceptance on slow CI while the companion save stalls.
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15), timeout=2.0)
    assert result.command_id == BEAN_COMMAND_ID
    assert Counter(call.operation for call in transport.calls)["send_climate_command"] == 1
    assert Counter(call.operation for call in transport.calls)["set_bean_tech_ac_temperature"] == 1


@pytest.mark.asyncio
async def test_beantech_climate_skips_optional_save_when_deadline_is_almost_used():
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]], send_climate_command=[{"code": "000000"}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    result = await client.send_climate_command(ClimateCommand(VehicleIdentifier(BEAN_VIN), "auto", 22, 15), timeout=0.08)
    assert result.command_id == BEAN_COMMAND_ID
    assert not any(call.operation == "set_bean_tech_ac_temperature" for call in transport.calls)
