"""Synthetic GTSP contracts; private contributor vectors are not published."""

from __future__ import annotations

import gzip
import json
import logging
import ssl
from dataclasses import replace

import pytest
from test_china_client import CLOCK, _complete_state, _FakeTransport, _partial_state, _response
from test_china_transport import _deadline, _FakeResponse, _FakeSession

from gwm_client import china_gtsp
from gwm_client.charging import ChargingPlanCommand
from gwm_client.china_client import ChinaClient, ChinaClientConfig, ChinaVehicle
from gwm_client.china_transport import ChinaAiohttpTransport
from gwm_client.commands import (
    BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS,
    NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS,
    ChinaVehicleControlCommand,
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
)
from gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmConfigurationError,
    GwmHttpError,
    GwmRedirectError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from gwm_client.models import VehicleIdentifier

VIN = "LGWTEST0000000001"
IDENTIFIER = VehicleIdentifier(VIN)
SECRET = "PRIVATE-RESPONSE-OR-TOKEN-MUST-NOT-LEAK"
LOGGER = "gwm_client.china_gtsp"


def client_for(transport, *, platform="gtsp", **kwargs):
    client = ChinaClient(
        ChinaClientConfig(), transport=transport, authenticated_state=_complete_state(),
        clock=lambda: CLOCK, nonce_source=lambda: "0123456789abcdef", **kwargs,
    )
    client._commit_vehicles((ChinaVehicle(identifier=IDENTIFIER, platform=platform),))
    return client


def request():
    return client_for(_FakeTransport())._build_gtsp_status_request(_complete_state(), IDENTIFIER)


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


@pytest.mark.parametrize("method,path,parameter,expected", [
    ("get", china_gtsp.STATUS_PATH, "vin=LGWTEST0000000001", "fa2be1936ca8105d86f19a9902a834792c33dd05f3fab887b1a647f4d896bf01"),
    ("GET", "/space%20here/%E9%9B%AA~*", "a=hello + world\t\r\n", "31421e503b426982416d808a5a52c27d1c83fe81241ef41b4e41d2842e93d798"),
])
def test_synthetic_signing_vectors(monkeypatch, method, path, parameter, expected):
    monkeypatch.setattr(china_gtsp, "BEAN_TECH_APP_KEY", "synthetic-app")
    monkeypatch.setattr(china_gtsp, "_BEAN_TECH_SECRET", "synthetic-secret")
    assert china_gtsp.gtsp_sign(method, path, "0123456789abcdef", "1760000000000", parameter) == expected


def test_request_contract_uses_shared_tokens_but_gtsp_headers_and_host():
    req = request()
    assert req.service == "gtsp"
    assert req.url == china_gtsp.STATUS_URL + "?vin=" + VIN
    assert req.method == "GET" and req.body is None
    assert req.headers["ampToken"] == _complete_state().pt_token
    assert req.headers["accessToken"] == _complete_state().bean_tech_access_token
    assert req.headers["tokenId"] == _complete_state().auto_ai_token_id
    assert req.headers["requestfrom"] == "poll"
    assert req.headers["requestForm"] == "android"
    assert req.headers["brand"] == "10"
    assert req.headers["terminal"] == "GW_APP_GWM"
    assert "beanId" not in req.headers and "bt-auth-sign" not in req.headers
    assert VIN not in repr(req)


@pytest.mark.parametrize("changes", [
    {"method": "POST"}, {"body": b"{}"}, {"operation": "get_charging_plan"},
    {"operation": "send_climate_command"}, {"service": "bean_tech"}, {"service": "auto_ai"},
    {"url": "https://evil.example/"},
    {"url": china_gtsp.STATUS_URL + "?vin=" + VIN + "&extra=1"},
    {"url": china_gtsp.STATUS_URL.replace("https:", "http:") + "?vin=" + VIN},
    {"url": china_gtsp.STATUS_URL + "?vin=" + VIN + "#fragment"},
])
def test_transport_rejects_route_confusion(changes):
    with pytest.raises(ValueError):
        replace(request(), **changes)


@pytest.mark.parametrize("name,value", [
    ("vin", "BAD"), ("gwm-auth-nonce", "bad"), ("gwm-auth-timestamp", "1"),
    ("gwm-auth-appkey", "wrong"), ("gwm-auth-sign", "0" * 64),
    ("requestfrom", "widget"), ("brand", "99"), ("terminal", "unknown"),
    ("ampToken", " "), ("accessToken", "\r\n"), ("tokenId", ""),
    ("extra", "value"),
])
def test_transport_rejects_invalid_headers(name, value):
    req = request()
    with pytest.raises(ValueError):
        replace(req, headers={**req.headers, name: value})


@pytest.mark.parametrize("state", [replace(_complete_state(), pt_token=None), _partial_state()])
def test_missing_token_cannot_build_request(state):
    with pytest.raises(GwmAuthenticationError):
        client_for(_FakeTransport())._build_gtsp_status_request(
            state, IDENTIFIER,
        )


@pytest.mark.parametrize("nonce", [None, "wrong", RuntimeError(SECRET)])
def test_nonce_failure_is_sanitized(nonce):
    client = client_for(_FakeTransport())

    def source():
        if isinstance(nonce, Exception):
            raise nonce
        return nonce

    client._nonce_source = source
    with pytest.raises(GwmConfigurationError) as exc:
        client._build_gtsp_status_request(_complete_state(), IDENTIFIER)
    assert SECRET not in str(exc.value)


@pytest.mark.asyncio
async def test_read_only_status_maps_soc_range_and_discards_private_fields(caplog):
    transport = _FakeTransport(get_last_status=[payload(
        acquisitionTime=1760000000000, latitude=12.345, longitude=23.456, deviceId=SECRET,
    )])
    client = client_for(transport, platform=" GTSP ")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = await client.get_last_status(IDENTIFIER)
    assert [(item.code, item.value, item.unit) for item in result.items] == [
        ("2013021", "65", "%"), ("2011501", "125", "km"),
    ]
    assert result.acquisition_time_ms == 1760000000000
    assert result.latitude == 12.345 and result.longitude == 23.456
    assert "12.345" not in caplog.text and "23.456" not in caplog.text
    assert "tls=established http_status=200" in caplog.text
    assert "data_present=True" in caplog.text and "soc_mapped=True" in caplog.text
    assert SECRET not in caplog.text and VIN not in caplog.text
    assert len(transport.calls) == 1


@pytest.mark.parametrize("status,expected", [
    ({"powerBatteryPercent": "0,%", "evContnsDistance": "0,km"}, {"2013021": "0", "2011501": "0"}),
    ({"charge": {"powerBatteryPercent": "72", "evContnsDistance": "123.5,KM"}}, {"2013021": "72", "2011501": "123.5"}),
    ({"powerBatteryPercent": "-1", "remainElectricPercent": "67"}, {"2013021": "67"}),
    ({"powerBatteryPercent": "21", "charge": {"powerBatteryPercent": "22"}, "remainElectricPercent": "23"}, {"2013021": "21"}),
    ({"preMileage": "800"}, {"gtsp_reported_range_raw": "800"}),
])
def test_field_precedence_and_no_guessed_combined_range(status, expected):
    result = mapped(status)
    assert {item.code: item.value for item in result.items} == expected
    assert result.acquisition_time_ms is None


@pytest.mark.parametrize("value", [None, True, {}, [], "", "--", "NaN", "Infinity", "-1", "65535", "1" * 129, "20,miles"])
def test_unavailable_or_malformed_values_do_not_become_measurements(value):
    assert mapped({"powerBatteryPercent": value, "evContnsDistance": value}).items == ()


@pytest.mark.parametrize("value", [0, -1, True, "1760000000000", 1760000000, None, 10**30])
def test_unknown_timestamp_does_not_claim_freshness(value):
    assert mapped({"powerBatteryPercent": "60"}, acquisitionTime=value).acquisition_time_ms is None


@pytest.mark.parametrize("data", [None, {}, {"vehicleStatusInfo": []}, {"vehicleStatusInfo": {}},
    {"vehicleStatusInfo": {"charge": []}},
    {"vehicleStatusInfo": {"powerBatteryPercent": "1", "POWERBATTERYPERCENT": "2"}},
])
def test_unknown_or_ambiguous_schema_is_rejected(data):
    with pytest.raises(ValueError):
        china_gtsp.map_gtsp_status(data, identifier=IDENTIFIER, vehicle_id=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("response,error", [
    ({"code": "000000", "data": {}}, GwmSchemaError),
    ({"code": "000000", "data": None}, GwmSchemaError),
    ({"code": "000000", "data": SECRET}, GwmSchemaError),
    ({"code": "7654", "description": SECRET}, GwmApiError),
    ({"code": 0, "data": {}}, GwmSchemaError),
    ({"code": "", "data": {}}, GwmSchemaError),
    ({"data": {}}, GwmSchemaError),
    (_response({}, status=401), GwmAuthenticationError),
    (_response({}, status=500), GwmHttpError),
    (GwmTlsError(operation="get_last_status"), GwmTlsError),
])
async def test_errors_are_sanitized_without_fallback_or_extra_requests(response, error, caplog):
    transport = _FakeTransport(get_last_status=[response])
    with caplog.at_level(logging.DEBUG, logger=LOGGER), pytest.raises(error) as exc:
        await client_for(transport).get_last_status(IDENTIFIER)
    assert SECRET not in caplog.text + str(exc.value)
    assert VIN not in caplog.text
    assert len(transport.calls) == 1 and transport.calls[0].service == "gtsp"


@pytest.mark.asyncio
async def test_undiscovered_vehicle_never_sends_gtsp_request():
    transport = _FakeTransport()
    with pytest.raises(GwmRoutePolicyError):
        await client_for(transport).get_last_status(VehicleIdentifier("LGWTEST0000000002"))
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS | NAVINFO_CHINA_VEHICLE_CONTROL_ACTIONS))
async def test_all_vehicle_commands_remain_blocked_for_gtsp(action):
    transport = _FakeTransport()
    with pytest.raises(GwmRoutePolicyError):
        await client_for(transport).send_vehicle_control_command(ChinaVehicleControlCommand(IDENTIFIER, action))
    assert transport.calls == []


@pytest.mark.asyncio
async def test_climate_lock_windows_charging_and_result_polling_are_blocked():
    transport = _FakeTransport()
    client = client_for(transport)
    calls = (
        (client.send_climate_command, ClimateCommand(IDENTIFIER, "auto", 22, 15)),
        (client.send_lock_command, DoorLockCommand(IDENTIFIER, True)),
        (client.send_close_windows_command, CloseWindowsCommand(IDENTIFIER)),
        (client.get_charging_plan, IDENTIFIER),
        (client.set_charging_plan, ChargingPlanCommand(IDENTIFIER, False)),
        (client.get_bean_tech_charge_setting, IDENTIFIER),
    )
    for method, arg in calls:
        with pytest.raises(GwmRoutePolicyError):
            await method(arg)
    with pytest.raises(GwmRoutePolicyError):
        await client.get_remote_command_results(IDENTIFIER, "synthetic-command")
    assert transport.calls == []


def test_diagnostics_never_log_server_messages_or_arbitrary_labels(caplog):
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        china_gtsp.log_response(200, json.dumps({"code": SECRET, "message": SECRET, "data": {"vin": VIN}}).encode())
        china_gtsp.log_failure(SECRET)
    assert SECRET not in caplog.text and VIN not in caplog.text
    assert "category=client_error" in caplog.text


def test_diagnostics_disabled_and_logging_failure_cannot_break_protocol(monkeypatch):
    monkeypatch.setattr(china_gtsp._LOGGER, "isEnabledFor", lambda _: False)
    china_gtsp.log_response(200, b"{}")

    def broken(*args, **kwargs):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(china_gtsp._LOGGER, "isEnabledFor", lambda _: True)
    monkeypatch.setattr(china_gtsp._LOGGER, "debug", broken)
    china_gtsp.log_response(200, b"{}")
    china_gtsp.log_failure("tls_error")
    assert mapped({"powerBatteryPercent": "2"}).items[0].value == "2"


@pytest.mark.asyncio
async def test_gtsp_transport_preserves_tls_gzip_and_no_redirect_policy():
    body = json.dumps(payload()).encode()
    session = _FakeSession(_FakeResponse(headers={"Content-Encoding": "gzip"}, chunks=[gzip.compress(body)]))
    transport = ChinaAiohttpTransport(session)
    result = await transport.execute(request(), deadline=_deadline(), connect_timeout=10, read_timeout=20)
    assert result.body == body
    args, kwargs = session.calls[0]
    assert args[0] == "GET" and str(args[1]).startswith(china_gtsp.STATUS_URL)
    assert kwargs["ssl"].check_hostname is True
    assert kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED
    assert kwargs["allow_redirects"] is False and kwargs["proxy"] is None
    assert kwargs["data"] is None
    session.response = _FakeResponse(status=302)
    with pytest.raises(GwmRedirectError):
        await transport.execute(request(), deadline=_deadline(), connect_timeout=10, read_timeout=20)
    session.error = ssl.SSLError(SECRET)
    with pytest.raises(GwmTlsError) as exc:
        await transport.execute(request(), deadline=_deadline(), connect_timeout=10, read_timeout=20)
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize("value,expected", [("12345.6,km", "12345.6"), (0, "0"), ("12345", "12345"),
    ("12,miles", None), (-1, None), (True, None), ("NaN", None), (10000001, None)])
def test_odometer_accepts_provisional_km_only(value, expected):
    result = mapped({"mileage": value})
    assert next((x.value for x in result.items if x.code == "2103010"), None) == expected


@pytest.mark.parametrize("coords,expected", [
    ({"latitude": 32.1, "longitude": 34.8}, (32.1, 34.8)),
    ({"latitude": 32.1, "longitude": 34.8, "gpsSwitchOn": True}, (32.1, 34.8)),
    ({"latitude": 32.1, "longitude": 34.8, "gpsSwitchOn": False}, (None, None)),
    ({"latitude": 32.1, "longitude": 34.8, "gpsSwitchOn": "true"}, (None, None)),
    ({"latitude": 0, "longitude": 0}, (None, None)),
    ({"latitude": 0, "longitude": 34.8}, (0, 34.8)),
    ({"latitude": True, "longitude": 34.8}, (None, None)),
    ({"latitude": "32.1", "longitude": 34.8}, (None, None)),
    ({"latitude": 91, "longitude": 34.8}, (None, None)),
    ({"latitude": 32.1, "longitude": 181}, (None, None)),
    ({"latitude": float("nan"), "longitude": 34.8}, (None, None)),
    ({"latitude": 10**400, "longitude": 34.8}, (None, None)),
    ({"latitude": 32.1}, (None, None)),
])
def test_coordinates_validate_pairs_without_guessing_fix_or_conversion(coords, expected):
    result = mapped({}, **coords)
    assert (result.latitude, result.longitude) == expected


def test_location_only_response_does_not_require_battery_fields():
    result = china_gtsp.map_gtsp_status(
        {"latitude": 32.1, "longitude": 34.8}, identifier=IDENTIFIER, vehicle_id=None,
    )
    assert result.latitude == 32.1 and result.items == ()


@pytest.mark.parametrize("code,group,field", [(code, *source) for code, source in china_gtsp.GTSP_DIAGNOSTIC_FIELDS.items()])
def test_each_raw_diagnostic_is_isolated_from_normalized_sensor_semantics(code, group, field):
    root = {"vehicleStatusInfo": {}}
    node = root if group == "root" else root["vehicleStatusInfo"]
    if group not in {"root", "status"}:
        node[group] = {}
        node = node[group]
    node[field] = 7
    result = china_gtsp.map_gtsp_status(root, identifier=IDENTIFIER, vehicle_id=None)
    assert [(x.code, x.value, x.unit) for x in result.items] == [(code, "7", None)]


@pytest.mark.parametrize("value,expected,unit", [
    ("180,km", "180", "km"), ("65535", "65535", None), (-1, "-1", None),
    ("12.5,min", "12.5", "min"), (True, None, None), ([], None, None),
    ("1" * 129, None, None), ("12," + SECRET, None, None),
    ("invalid", None, None), ("nan", None, None), (2**32, None, None),
])
def test_raw_diagnostics_keep_sentinels_but_never_arbitrary_text(value, expected, unit):
    result = mapped({"charge": {"chargingTime": value}})
    assert [(x.value, x.unit) for x in result.items] == ([] if expected is None else [(expected, unit)])


def test_nested_raw_range_has_no_electric_or_fuel_interpretation():
    assert [(x.code, x.value) for x in mapped({"charge": {"preMileage": "800"}}).items] == [
        ("gtsp_reported_range_raw", "800"),
    ]


def test_schema_logs_only_fixed_paths_types_and_recognized_units(caplog):
    status = {"mileage": "12345,km", "speed": "private-value", SECRET: SECRET,
        "charge": {"chargeStatus": "1", "chargingTime": "21,min", "connectSts": "1," + SECRET},
        "door": {"maindrvedoorsts": 1, VIN: SECRET}, "windows": [],
        "tirepress": {"lftirepressval": "260,kPa"},
    }
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        mapped(status, latitude=32.123456, longitude=34.654321, deviceId=SECRET)
    assert "data.vehiclestatusinfo.mileage:string:unit=km" in caplog.text
    assert "data.vehiclestatusinfo.speed:string" in caplog.text
    assert "data.vehiclestatusinfo.charge.chargingtime:string:unit=min" in caplog.text
    assert "unit=unrecognized" in caplog.text
    assert "data.vehiclestatusinfo.windows:array" in caplog.text
    assert "unlisted_fields=3" in caplog.text
    for secret in (SECRET, VIN, "12345", "260", "32.123456", "34.654321", "private-value"):
        assert secret not in caplog.text


def test_schema_diagnostics_disabled_or_malformed_are_nonfatal(monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        china_gtsp.log_status_shape({"vehiclestatusinfo": {"mileage": 1, "MILEAGE": 2}})
        china_gtsp.log_status_shape({"vehiclestatusinfo": None})
    monkeypatch.setattr(china_gtsp._LOGGER, "isEnabledFor", lambda _: False)
    china_gtsp.log_status_shape({"vehiclestatusinfo": {"mileage": 1}})
