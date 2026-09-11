"""Mutation tests for captured BeanTech charging routes and signed payloads."""

from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from test_china_client import (
    BEAN_COMMAND_ID,
    BEAN_VIN,
    FIXTURE,
    _charging_setting,
    _client,
    _complete_state,
    _credentials,
    _FakeTransport,
)

from gwm_client._dotnet_json import encode_dotnet_json
from gwm_client.china_crypto import bean_tech_sign
from gwm_client.commands import ChinaVehicleControlCommand
from gwm_client.models import VehicleIdentifier


@pytest_asyncio.fixture(params=[
    "get_bean_tech_charge_setting", "set_bean_tech_charging_mode", "set_bean_tech_charge_window",
    "get_bean_tech_battery_heating_appointment", "get_bean_tech_switch_status", "set_bean_tech_charge_soc",
    "appointment_on", "appointment_off", "battery_gun_heat", "battery_gun_heat_stop",
    "battery_initiative_heat", "battery_initiative_heat_stop", "charge_result",
])
async def charging_request(request):
    kind = request.param
    transport = _FakeTransport(acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        get_bean_tech_charge_setting=[{"code": "000000", "data": _charging_setting()}],
        set_bean_tech_charging_mode=[{"code": "000000"}], set_bean_tech_charge_window=[{"code": "000000"}],
        get_bean_tech_battery_heating_appointment=[{"code": "000000", "data": []}],
        get_bean_tech_switch_status=[{"code": "000000", "data": {"switchStatus": {}}}],
        set_bean_tech_charge_soc=[{"code": "000000"}], set_bean_tech_battery_heating_appointment=[{"code": "000000"}],
        send_vehicle_control_command=[{"code": "000000"}], get_remote_command_result=[{"code": "000000", "data": {"beanTechMesg": []}}])
    client = _client(transport)
    await client.authenticate(_credentials(), state=_complete_state())
    identifier = VehicleIdentifier(BEAN_VIN)
    if kind.startswith("battery_"):
        await client.send_vehicle_control_command(ChinaVehicleControlCommand(identifier, kind))
    elif kind.startswith("appointment_"):
        enable = kind == "appointment_on"
        await client.set_bean_tech_battery_heating_appointment(identifier, enable=enable, use_car_time_ms=1789200000000 if enable else None)
    elif kind == "charge_result":
        await client.get_remote_command_results(identifier, BEAN_COMMAND_ID, control_action="charging_mode")
    else:
        kwargs = {"set_bean_tech_charging_mode": {"enable": True}, "set_bean_tech_charge_soc": {"percent": 80},
            "set_bean_tech_charge_window": {"start_time": "21:00"}}.get(kind, {})
        await getattr(client, kind)(identifier, **kwargs)
    return transport.calls[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["http", "host", "port", "path", "query", "fragment", "method", "service", "body", "signature", "pin", "vin", "nonce", "token", "content_type"])
async def test_charging_transport_rejects_cross_route_and_authentication_mutations(charging_request, mutation):
    request = charging_request
    changes = {}
    headers = dict(request.headers)
    if mutation == "http":
        changes["url"] = request.url.replace("https://", "http://")
    elif mutation == "host":
        changes["url"] = request.url.replace("gw-app-gateway.gwmapp-h.com", "navinfo.example")
    elif mutation == "port":
        changes["url"] = request.url.replace(".com/", ".com:443/")
    elif mutation == "path":
        changes["url"] = request.url.replace("/api/v3.0/", "/api/v2.0/")
    elif mutation == "query":
        changes["url"] = request.url + ("&" if "?" in request.url else "?") + "strategy=6"
    elif mutation == "fragment":
        changes["url"] = request.url + "#fragment"
    elif mutation == "method":
        changes["method"] = "POST" if request.method == "GET" else "GET"
    elif mutation == "service":
        changes["service"] = "g_app"
    elif mutation == "body":
        changes["body"] = b"{}" if request.body is None else None
    else:
        key, value = {"signature": ("bt-auth-sign", "0" * 32), "pin": ("securityToken", "unrequested-pin"),
            "vin": ("vin", "LGWOTHER000000001"), "nonce": ("bt-auth-nonce", "bad"),
            "token": ("accessToken", ""), "content_type": ("Content-Type", "text/plain")}[mutation]
        headers[key] = value
        changes["headers"] = headers
    with pytest.raises(ValueError):
        replace(request, **changes)


def _resigned(request, body):
    raw = encode_dotnet_json(body)
    headers = dict(request.headers)
    headers["bt-auth-sign"] = bean_tech_sign("POST", urlsplit(request.url).path, headers["bt-auth-nonce"], headers["bt-auth-timestamp"], "json=" + raw)
    return replace(request, headers=headers, body=raw.encode("utf-8"))


@pytest.mark.asyncio
async def test_charging_transport_rejects_signed_malformed_schemas(charging_request):
    request = charging_request
    if request.body is None:
        if request.operation == "get_remote_command_result":
            for query in ("seqNo=x&msgType=charge", "bad=x&vin=x&msgType=charge", "seqNo=%FF&vin=x&msgType=charge"):
                with pytest.raises(ValueError):
                    replace(request, url=request.url.split("?")[0] + "?" + query)
        return
    original = json.loads(request.body)
    bad_bodies = [None, [], {}, {**original, "unexpected": 1}]
    for field in original:
        bad = dict(original)
        del bad[field]
        bad_bodies.append(bad)
    if "chargingMode" in original:
        bad_bodies += [{**original, key: value} for key, values in {
            "chargingMode": [True, 0.0, 2, [], "0"], "chargeStrategy": [True, -1, 5.0, "5"],
            "chargeSetParam": [None, []], "seqNo": [True, "bad"],
        }.items() for value in values]
    elif "types" in original:
        bad_bodies += [{**original, key: value} for key, values in {
            "sendType": [False, 0.0, 1], "types": [[], ["AIR_CONDITIONER_START"]], "userId": [None, "", 1],
        }.items() for value in values]
    else:
        bad_bodies += [{**original, "commands": value} for value in (None, [], [None], [{}, {}])]
        command = original["commands"][0]
        bad_bodies += [{**original, "commands": [{**command, "controlType": "LOCK_DOOR"}]},
            {**original, "commands": [{**command, "extra": 1}]}]
        if "cmdBody" in command:
            field = next(iter(command["cmdBody"]))
            values = [True, -1, 0, "80", 80.5, 253402214399001] if field == "useCarTime" else [True, 0, 110, 65, "80", 80.0]
            for body in (None, {}, {**command["cmdBody"], "unexpected": 1}, *({field: value} for value in values)):
                bad_bodies.append({**original, "commands": [{**command, "cmdBody": body}]})
        else:
            bad_bodies.append({**original, "commands": [{**command, "cmdBody": {}}]})
    for bad in bad_bodies:
        with pytest.raises(ValueError):
            _resigned(request, bad)
