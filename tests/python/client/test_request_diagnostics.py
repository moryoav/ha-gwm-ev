"""Offline coverage for diagnostic-only overseas request logging."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import aiohttp
import pytest
from support.overseas import _default_context, _QueueTransport

from custom_components.gwm_ora.gwm_client import (
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    GwmClient,
    GwmClientConfig,
    GwmSession,
    VehicleIdentifier,
)
from custom_components.gwm_ora.gwm_client import _diagnostics as diagnostics
from custom_components.gwm_ora.gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmHttpError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmSchemaError,
)
from custom_components.gwm_ora.gwm_client.tls import LEGACY_CIPHER_STRING
from custom_components.gwm_ora.gwm_client.transport import AiohttpTransport

LOGGER = "custom_components.gwm_ora.gwm_client._diagnostics"
SECRET = "SENSITIVE-never-log-this-value"
NEW_OPERATIONS = (
    "get_charging_plan", "get_remote_command_result", "update_climate_defaults",
    "send_climate_command", "send_close_windows_command", "send_lock_command",
)


def _request(operation="send_climate_command", path="vehicle/T5/sendCmd", method="POST"):
    return _TransportRequest(
        operation=operation,
        method=method,
        url=f"https://example.invalid/api/v1/{path}?vin={SECRET}&seqNo={SECRET}",
        headers={"accessToken": SECRET, **({"Content-Type": "application/json"} if method == "POST" else {})},
        body=json.dumps({"securityPassword": SECRET, "vin": SECRET}).encode() if method == "POST" else None,
        ssl_context=ssl.create_default_context(),
    )


@pytest.mark.parametrize("operation", NEW_OPERATIONS)
@pytest.mark.parametrize("error_type", [GwmSchemaError, GwmApiError, GwmNetworkError])
def test_operation_alias_is_preserved(operation, error_type):
    assert error_type(operation=operation).operation == operation
    assert error_type(operation=SECRET).operation == "unknown"


@pytest.mark.parametrize(("body", "reason"), [
    (b"", "empty_body"),
    (b"<html>upstream unavailable</html>", "invalid_json"),
    (b"\xff", "invalid_utf8"),
    (b"null", "unexpected_root_type"),
    (b"[]", "unexpected_root_type"),
    (b'"private response"', "unexpected_root_type"),
    (b'{}', "missing_code"),
    (b'{"code":null}', "unexpected_code_type"),
    (b'{"code":0}', "unexpected_code_type"),
    (b'{"code":false}', "unexpected_code_type"),
    (b'{"code":550002}', "unexpected_code_type"),
    (b'{"code":"550002"}', "api_code_not_success"),
    (b'{"code":"000000"}', "envelope_ok"),
    (b'{"code":"000000","data":null}', "envelope_ok"),
    (b'{"code":"000000","data":{}}', "envelope_ok"),
    (b'{"code":"000000","data":[]}', "envelope_ok"),
    (b'{"code":"000000","data":true}', "envelope_ok"),
    (b'{"code":"000000","code":"000000"}', "duplicate_json_key"),
    (b'{"code":"000000","data":{"x":1,"x":2}}', "duplicate_json_key"),
    (b'{"code":"000000","data":NaN}', "non_finite_number"),
    (b'{"code":"000000","data":1e999}', "non_finite_number"),
    (b"[" * 66 + b"0" + b"]" * 66, "json_too_deep"),
    (b"[" * 1200 + b"0" + b"]" * 1200, "json_too_deep"),
    pytest.param(b" " * (64 * 1024 + 1), "diagnostic_size_limit", id="diagnostic-size-limit"),
])
def test_response_logs_the_bounded_envelope_reason(caplog, body, reason):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    diagnostics.log_response(_request(), _TransportResponse(200, {}, body))
    assert f"envelope_reason={reason}" in caplog.text
    assert len(caplog.records) == 1
    assert SECRET not in caplog.text


@pytest.mark.parametrize(("code", "safe"), [
    ("000000", "000000"), (550002, "550002"), (-101, "-101"), (0, "0"),
    (True, None), (False, None), (550002.0, None), (None, None),
    ("5\n50002", None), ("１２３", None), (SECRET, None), ({"token": SECRET}, None),
    ([], None), (10**12, None), (-10**11, None), (10**100, None),
    (999_999_999_999, "999999999999"), (-99_999_999_999, "-99999999999"),
])
def test_response_logs_only_bounded_numeric_codes(caplog, code, safe):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    diagnostics.log_response(_request(), _TransportResponse(200, {}, json.dumps({"code": code}).encode()))
    assert f"api_code={safe} api_code_type=" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.parametrize(("operation", "path", "method", "stage"), [
    ("update_climate_defaults", "vehicle/modifyVehicleRemoteCtlInfo", "POST", "save_climate_defaults"),
    ("send_climate_command", "userAuth/checkSecurityPassword", "POST", "security_check"),
    ("send_climate_command", "vehicle/T5/sendCmd", "POST", "command_send"),
    ("send_lock_command", "userAuth/checkSecurityPassword", "POST", "security_check"),
    ("send_lock_command", "vehicle/T5/sendCmd", "POST", "command_send"),
    ("send_cabin_clean_command", "userAuth/checkSecurityPassword", "POST", "security_check"),
    ("send_cabin_clean_command", "vehicle/T5/sendCmd", "POST", "command_send"),
    ("get_remote_command_result", "vehicle/getRemoteCtrlResultT5", "GET", "command_result"),
    ("get_vehicle_basics", "vehicle/vehicleBasicsInfo", "GET", "vehicle_basics"),
    ("get_last_status", "vehicle/getLastStatus", "GET", "vehicle_status"),
    ("get_charging_plan", "vehicleCharge/getChargingInfos", "GET", "charging_plan_read"),
    ("set_charging_plan", "vehicleCharge/setChargingPlan", "POST", "charging_plan_write"),
])
def test_request_stage_and_response_shape_are_logged_without_secrets(caplog, operation, path, method, stage):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    request = _request(operation, path, method)
    response = _TransportResponse(200, {"content-type": SECRET}, b'{"code":"000000"}')
    diagnostics.log_request(request)
    diagnostics.log_response(request, response)
    assert f"operation={operation} stage={stage}" in caplog.text
    assert "http_status=200" in caplog.text
    assert "api_code=000000 api_code_type=string" in caplog.text
    assert "data_present=False data_type=missing envelope_reason=envelope_ok" in caplog.text
    assert SECRET not in caplog.text
    assert "example.invalid" not in caplog.text
    assert path not in caplog.text
    assert response.body == b'{"code":"000000"}'


@pytest.mark.parametrize("code", [SECRET, {SECRET: SECRET}, [SECRET], 550002])
def test_response_values_keys_and_descriptions_are_never_logged(caplog, code):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    body = json.dumps({"code": code, "description": SECRET, SECRET: SECRET, "data": {"token": SECRET}}).encode()
    diagnostics.log_response(_request(), _TransportResponse(200, {}, body))
    assert SECRET not in caplog.text
    assert "description" not in caplog.text
    assert "token" not in caplog.text
    if type(code) is int:
        assert "api_code=550002 api_code_type=integer" in caplog.text
        assert GwmApiError(api_code=code).api_code is None  # No retry/renewal behavior change.


@pytest.mark.parametrize("status", [200, 401, 403, 429, 500, 503])
def test_response_http_status_is_retained(caplog, status):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    diagnostics.log_response(_request(), _TransportResponse(status, {}, b"not json"))
    assert f"http_status={status}" in caplog.text
    assert "envelope_reason=invalid_json" in caplog.text


def test_disabled_debug_does_not_parse_or_log(caplog, monkeypatch):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    parser = Mock(side_effect=AssertionError("must not parse"))
    monkeypatch.setattr(diagnostics, "_envelope_shape", parser)
    request = _request()
    diagnostics.log_request(request)
    diagnostics.log_response(request, _TransportResponse(200, {}, b"{}"))
    diagnostics.log_failure(request, GwmNetworkError())
    parser.assert_not_called()
    assert not caplog.records


@pytest.mark.parametrize(("operation", "path"), [
    ("login", "userAuth/checkSecurityPassword"),
    ("refresh_token", "vehicle/T5/sendCmd"),
    ("send_climate_command", "private/unknown"),
    ("acquire_vehicles", "vehicle/getLastStatus"),
    ("get_last_status", "globalapp/vehicle/acquireVehicles"),
])
def test_authentication_and_unknown_routes_are_not_inspected(caplog, monkeypatch, operation, path):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    parser = Mock(side_effect=AssertionError("must not parse"))
    monkeypatch.setattr(diagnostics, "_envelope_shape", parser)
    request = _request(operation, path)
    diagnostics.log_request(request)
    diagnostics.log_response(request, _TransportResponse(200, {}, b"{}"))
    diagnostics.log_failure(request, GwmNetworkError())
    parser.assert_not_called()
    assert not caplog.records


def test_logging_failure_is_nonfatal(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    monkeypatch.setattr(diagnostics._LOGGER, "log", Mock(side_effect=RuntimeError(SECRET)))
    request = _request()
    diagnostics.log_request(request)
    diagnostics.log_response(request, _TransportResponse(200, {}, b"{}"))
    diagnostics.log_failure(request, GwmNetworkError())


def test_transport_failure_does_not_log_exception_text_or_mutated_category(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    error = GwmNetworkError()
    error.args = (SECRET,)
    error.category = SECRET
    diagnostics.log_failure(_request(), error)
    assert "stage=command_send category=unknown" in caplog.text
    assert SECRET not in caplog.text


class _ResponseContext:
    def __init__(self, body, error=None, *, status=200, headers=None):
        self.body = body
        self.error = error
        self.status = status
        self.headers = {} if headers is None else headers

    async def __aenter__(self):
        if self.error is not None:
            raise self.error
        return SimpleNamespace(status=self.status, headers=self.headers, content=self)

    async def __aexit__(self, *_args):
        return None

    async def iter_chunked(self, _size):
        yield self.body


def _transport(context):
    session = SimpleNamespace(
        trust_env=False, headers={}, cookie_jar=aiohttp.DummyCookieJar(),
        _raise_for_status=False, _retry_connection=False, _middlewares=(), _trace_configs=[],
        _request_class=aiohttp.ClientRequest, _response_class=aiohttp.ClientResponse,
        closed=False, request=Mock(return_value=context),
    )
    return AiohttpTransport(cast(aiohttp.ClientSession, session)), session


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_real_transport_preserves_bytes_request_count_and_failure(caplog, failure):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    body = b'{"code":"000000"}'
    context = _ResponseContext(body, OSError(SECRET) if failure else None)
    transport, session = _transport(context)
    request = _request()
    call = transport.execute(
        request, deadline=_Deadline(asyncio.get_running_loop().time() + 10),
        connect_timeout=3, read_timeout=3,
    )
    if failure:
        with pytest.raises(GwmNetworkError):
            await call
        assert "stage=command_send category=network_error" in caplog.text
    else:
        result = await call
        assert result.body == body
        assert "envelope_reason=envelope_ok" in caplog.text
    session.request.assert_called_once()
    assert session.request.call_args.kwargs["data"] == request.body
    assert SECRET not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mime", "body", "expected"),
    [
        (
            "application/json",
            json.dumps({"code": 550004, "description": SECRET, "data": {"vin": SECRET}}).encode(),
            ("content_type=json", "root_type=object", "api_code=550004 api_code_type=integer", "html_hint=False"),
        ),
        (
            "text/html",
            f"<!DOCTYPE html><html>{SECRET}</html>".encode(),
            ("content_type=html", "api_code=None", "envelope_reason=invalid_json", "html_hint=True"),
        ),
    ],
)
async def test_russia_discovery_400_logs_safe_metadata_and_preserves_http_error(caplog, mime, body, expected):
    """Report a discovery 400 at startup without exposing response or request values."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    headers = {
        "Content-Type": f"{mime}; private={SECRET}",
        "Server": f"nginx {SECRET}",
        "X-Request-ID": SECRET,
        "X-Aliyun-Waf": SECRET,
        "Set-Cookie": f"acw_tc={SECRET}",
    }
    transport, session = _transport(_ResponseContext(body, status=400, headers=headers))
    tls = _default_context()
    tls.set_ciphers(LEGACY_CIPHER_STRING)
    async with GwmClient(
        GwmClientConfig("rus"), GwmSession("RU", "0123456789abcdef", SECRET, tls), transport=transport,
    ) as client:
        with pytest.raises(GwmHttpError) as raised:
            await client.acquire_vehicles()
    assert raised.value.status == 400
    session.request.assert_called_once()
    (record,) = (record for record in caplog.records if record.name == LOGGER)
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert "operation=acquire_vehicles stage=vehicle_discovery http_status=400" in message
    assert f"body_bytes={len(body)}" in message
    assert "server_family=nginx" in message
    assert "waf_header_hint=True" in message
    assert "waf_cookie_hint=True" in message
    assert "request_id_present=True" in message
    assert "region=rus gateway=app_v1 method=GET tls_mode=russia_bootstrap_mtls" in message
    assert all(value in message for value in expected)
    assert SECRET not in repr(record.args)
    assert SECRET not in message
    assert "gwmcloud.com" not in message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "error_type", "expected"),
    [
        (302, {"Location": f"https://example.invalid/{SECRET}"}, GwmRedirectError, "location_present=True"),
        (400, {"Content-Encoding": "gzip"}, GwmProtocolError, "content_encoding=gzip"),
        (400, {"Content-Length": "999999999"}, GwmResponseTooLargeError, "declared_body_bytes=999999999"),
        (400, {"Content-Length": SECRET}, GwmProtocolError, "declared_body_bytes=None"),
    ],
)
async def test_rejected_discovery_logs_headers_without_reading_body(caplog, status, headers, error_type, expected):
    """Keep HTTP metadata when transport rejects a discovery response before reading."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    context = _ResponseContext(
        SECRET.encode(), status=status, headers={**headers, "Content-Type": "text/html", "X-Request-ID": SECRET},
    )
    context.iter_chunked = Mock(side_effect=AssertionError("rejected body must not be read"))
    transport, session = _transport(context)
    request = _request("acquire_vehicles", "globalapp/vehicle/acquireVehicles", "GET")
    with pytest.raises(error_type) as raised:
        await transport.execute(
            request, deadline=_Deadline(asyncio.get_running_loop().time() + 10),
            connect_timeout=3, read_timeout=3,
        )
    session.request.assert_called_once()
    context.iter_chunked.assert_not_called()
    (record,) = (record for record in caplog.records if record.name == LOGGER)
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert f"operation=acquire_vehicles stage=vehicle_discovery http_status={status}" in message
    assert f"response_rejected=True category={raised.value.category}" in message
    assert "content_type=html" in message
    assert "request_id_present=True" in message
    assert expected in message
    assert SECRET not in repr(record.args)


def test_successful_discovery_remains_opt_in(caplog, monkeypatch):
    """Avoid parsing routine successful discovery responses at the default level."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    parser = Mock(side_effect=AssertionError("must not parse"))
    monkeypatch.setattr(diagnostics, "_envelope_shape", parser)
    request = _request("acquire_vehicles", "globalapp/vehicle/acquireVehicles", "GET")
    diagnostics.log_response(request, _TransportResponse(200, {}, b"{}"))
    parser.assert_not_called()
    assert not caplog.records


@pytest.mark.parametrize(("body", "expected_error"), [
    (b"not json", GwmSchemaError),
    (b"null", GwmSchemaError),
    (b"[]", GwmSchemaError),
    (b'{"code":"000000"}', None),
    (b'{"code":0,"data":null}', GwmApiError),
    (b'{"code":"000000","data":null}', None),
])
@pytest.mark.asyncio
async def test_code_only_acknowledgements_reach_the_public_client(caplog, body, expected_error):
    """Accept code-only acknowledgements while rejecting invalid envelopes."""

    caplog.set_level(logging.DEBUG, logger=LOGGER)
    response = _TransportResponse(200, {}, body)
    diagnostics.log_response(_request(), response)
    client = GwmClient(
        GwmClientConfig("aus"), GwmSession("AU", "0123456789abcdef", "SYNTHETIC-ACCESS", _default_context()),
        transport=_QueueTransport([response]),
    )
    call = client.update_climate_defaults(VehicleIdentifier("LGWTEST0000000001"), temperature=21, operation_time_minutes=15)
    try:
        if expected_error is not None:
            with pytest.raises(expected_error):
                await call
        else:
            assert await call is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", NEW_OPERATIONS)
async def test_public_client_preserves_the_operation_on_sanitized_failures(operation):
    client = GwmClient(
        GwmClientConfig("aus"), GwmSession("AU", "0123456789abcdef", "SYNTHETIC-ACCESS", _default_context()),
        transport=_QueueTransport([GwmSchemaError(operation=operation)]),
    )
    identifier = VehicleIdentifier("LGWTEST0000000001")
    calls = {
        "get_charging_plan": lambda: client.get_charging_plan(identifier),
        "get_remote_command_result": lambda: client.get_remote_command_results(identifier, "SYNTHETIC-COMMAND"),
        "update_climate_defaults": lambda: client.update_climate_defaults(identifier, temperature=21, operation_time_minutes=15),
        "send_climate_command": lambda: client.send_climate_command(ClimateCommand(identifier, "auto", 21, 15), security_password_hash="0" * 32),
        "send_close_windows_command": lambda: client.send_close_windows_command(CloseWindowsCommand(identifier), security_password_hash="0" * 32),
        "send_lock_command": lambda: client.send_lock_command(DoorLockCommand(identifier, True), security_password_hash="0" * 32),
    }
    try:
        with pytest.raises(GwmSchemaError) as raised:
            await calls[operation]()
        assert raised.value.operation == operation
    finally:
        await client.aclose()
