"""Authentication visibility, hostile-response privacy, and IO equivalence."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from datetime import UTC, datetime
from email.utils import format_datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import aiohttp
import pytest

from gwm_client import _auth_diagnostics as diagnostics
from gwm_client._protocol import _Deadline, _TransportRequest
from gwm_client.errors import (
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmSchemaError,
    GwmTlsError,
)
from gwm_client.transport import AiohttpTransport

LOGGER = "gwm_client._auth_diagnostics"
SECRET = "PRIVATE-auth-user-token-pin-vin-email-location-946d88"


def _request(*, operation="login", path="userAuth/loginWithPassword", region="eu", version="v2.0", host=None):
    return _TransportRequest(
        operation=operation, method="GET" if operation == "get_user_info" else "POST",
        url=f"https://{host or f'{region}-h5-gateway.gwmcloud.com'}/app-api/api/{version}/{path}?private={SECRET}",
        headers={
            "accessToken": SECRET, "deviceId": SECRET, "gwm-auth-sign": SECRET,
            "gwm-auth-timestamp": SECRET, "gwm-auth-nonce": SECRET, "bt-auth-sign": SECRET,
            "bt-auth-timestamp": SECRET, "bt-auth-nonce": SECRET, "X-Private-Header": SECRET,
            **({"Content-Type": "application/json"} if operation != "get_user_info" else {}),
        },
        body=json.dumps({"account": SECRET, "password": SECRET, "refreshToken": SECRET}).encode() if operation != "get_user_info" else None,
        ssl_context=ssl.create_default_context(),
    )


def _exchange(request=None):
    result = diagnostics.begin_request(request or _request(), connect_timeout=3, read_timeout=4, remaining=10)
    assert result is not None
    return result


def _assert_private(caplog):
    # Check both rendered messages and the original LogRecord arguments. No
    # handler/formatter should be able to expose an unrendered private object.
    for record in caplog.records:
        if record.name == LOGGER:
            assert SECRET not in record.getMessage()
            assert SECRET not in repr(record.args)
            assert "gwmcloud.com" not in record.getMessage()
            assert "userAuth/" not in record.getMessage()
            assert record.exc_info is None


@pytest.mark.parametrize(("operation", "path", "version", "region", "stage"), [
    ("login", "userAuth/loginWithPassword", "v2.0", "eu", "password_login"),
    ("refresh_token", "userAuth/refreshToken", "v1.0", "eu", "token_refresh"),
    ("request_verification", "userAuth/getVerifyCode", "v2.0", "eu", "request_verification"),
    ("verify_code", "userAuth/checkVerifyCode", "v2.0", "eu", "verify_code"),
    ("get_user_info", "user/getUserBaseInfo", "v1.0", "eu", "user_profile"),
    ("login", "userAuth/loginAccount", "v1.0", "aus", "legacy_login"),
    ("login", "userAuth/loginWithPassword", "v2.0", "aus", "password_login"),
    ("refresh_token", "userAuth/refreshToken", "v1.0", "aus", "token_refresh"),
    ("request_verification", "userAuth/getSMSCode", "v1.0", "rus", "request_sms"),
    ("verify_code", "userAuth/loginWithSMS", "v1.0", "rus", "sms_login"),
])
def test_known_authentication_stages_have_safe_request_metadata(caplog, operation, path, version, region, stage):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    exchange = _exchange(_request(operation=operation, path=path, region=region, version=version))
    assert exchange.fields["stage"] == stage
    assert exchange.fields["region"] == region
    assert "signature_present=True timestamp_present=True nonce_present=True" in caplog.text
    assert "connect_timeout_ms=3000 read_timeout_ms=4000 deadline_remaining_ms=10000" in caplog.text
    _assert_private(caplog)


def test_certificate_enrollment_is_classified_without_identity_material(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    exchange = _exchange(_request(operation="enroll_certificate", path="appAuth/applyCertificate", version="v1.0", host="eu-app-gateway-common.gwmcloud.com"))
    assert exchange.fields["gateway"] == "certificate_v1"
    assert exchange.fields["tls"] == "bootstrap_mtls"
    _assert_private(caplog)


@pytest.mark.parametrize("prepared", [
    _request(host="example.invalid"),
    _request(path=f"private/{SECRET}"),
    _request(operation="refresh_token"),
    _request(operation="acquire_vehicles", path="globalapp/vehicle/acquireVehicles", version="v1.0"),
])
def test_unknown_routes_are_ignored_even_when_debug_is_enabled(caplog, prepared):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    assert diagnostics.begin_request(prepared, connect_timeout=3, read_timeout=4, remaining=10) is None
    assert not caplog.records


@pytest.mark.parametrize("status", [200, 401, 403, 405, 429, 500, 503])
def test_json_error_and_headers_are_available_at_warning_level(caplog, status):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    exchange = _exchange()
    headers = {
        "Content-Type": f"application/json; private={SECRET}", "Content-Length": "999",
        "Allow": f"GET, POST, {SECRET}", "Server": f"nginx/{SECRET}",
        "Location": f"https://private.invalid/{SECRET}", "Via": SECRET,
        "X-Request-ID": SECRET, "Set-Cookie": f"acw_sc__v2={SECRET}; HttpOnly",
        "Date": format_datetime(datetime.now(UTC), usegmt=True), "Retry-After": "30",
        SECRET: SECRET,
    }
    diagnostics.response_headers(exchange, status=status, headers=headers, version=SimpleNamespace(major=1, minor=1))
    body = json.dumps({"code": "550004", "description": f"Token expired {SECRET}", SECRET: SECRET,
                       "data": {"accessToken": SECRET, "refreshToken": SECRET, "privateKey": SECRET, SECRET: SECRET}}).encode()
    diagnostics.response_body(exchange, body)
    assert f"http_status={status}" in caplog.text
    assert "allow_methods=GET,POST allow_unknown_methods=True" in caplog.text
    assert "server_family=nginx" in caplog.text
    assert "content_type=json" in caplog.text
    assert "waf_cookie_hint=True" in caplog.text
    assert "api_code=550004" in caplog.text
    assert "expired_hint=True" in caplog.text
    assert "privateKey:string" in caplog.text
    assert "http_version=1.1" in caplog.text
    assert body == json.dumps({"code": "550004", "description": f"Token expired {SECRET}", SECRET: SECRET,
                               "data": {"accessToken": SECRET, "refreshToken": SECRET, "privateKey": SECRET, SECRET: SECRET}}).encode()
    _assert_private(caplog)


def test_successful_token_and_certificate_responses_require_debug_and_never_log_values(caplog):
    exchange = _exchange()
    body = json.dumps({"code": "000000", "data": {"accessToken": SECRET, "refreshToken": SECRET,
                                                  "privateKey": SECRET, "certificate": SECRET, "gwId": SECRET}}).encode()
    caplog.set_level(logging.WARNING, logger=LOGGER)
    diagnostics.response_headers(exchange, status=200, headers={"Content-Type": "application/json"})
    diagnostics.response_body(exchange, body)
    assert not caplog.records
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    diagnostics.response_body(exchange, body)
    assert "api_code=000000" in caplog.text
    assert "auth_fields=accessToken:string,refreshToken:string,gwId:string,certificate:string,privateKey:string" in caplog.text
    _assert_private(caplog)


@pytest.mark.parametrize(("body", "reason", "kind"), [
    (b"", "empty_body", "empty"),
    (b"\xff", "invalid_utf8", "binary"),
    (f"<html><script>captcha</script>Web Application Firewall request blocked {SECRET}</html>".encode(), "invalid_json", "html"),
    (b"null", "unexpected_root_type", "json"),
    (b"[]", "unexpected_root_type", "json"),
    (json.dumps(SECRET).encode(), "unexpected_root_type", "json"),
    (b"{}", "missing_code", "json"),
    (b'{"code":0}', "unexpected_code_type", "json"),
    (b'{"code":"000000","code":"550004"}', "duplicate_json_key", "json"),
    (b'{"code":"000000","data":NaN}', "non_finite_number", "json"),
    (b'{"code":"000000","data":1e999}', "non_finite_number", "json"),
    (b"[" * 66 + b"0" + b"]" * 66, "json_too_deep", "json"),
    (b"[" * 1500 + b"0" + b"]" * 1500, "json_too_deep", "json"),
    (b" " * (256 * 1024 + 1), "diagnostic_size_limit", "other"),
], ids=lambda value: f"bytes-{len(value)}" if isinstance(value, bytes) else None)
def test_hostile_and_unexpected_response_shapes_are_bounded(caplog, body, reason, kind):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    exchange = _exchange()
    diagnostics.response_headers(exchange, status=405, headers={"Content-Type": SECRET})
    diagnostics.response_body(exchange, body)
    assert f"body_kind={kind}" in caplog.text
    assert f"envelope_reason={reason}" in caplog.text
    if kind == "html":
        assert "waf_hint=True captcha_hint=True denied_hint=True" in caplog.text
        assert "javascript_hint=True" in caplog.text
    _assert_private(caplog)


@pytest.mark.parametrize("code", [SECRET, {SECRET: SECRET}, [SECRET], True, 123456789012, "123456789012", "５５０００４"])
def test_code_fields_cannot_echo_arbitrary_strings_objects_or_long_numeric_tokens(caplog, code):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    exchange = _exchange()
    diagnostics.response_headers(exchange, status=405, headers={})
    diagnostics.response_body(exchange, json.dumps({"code": code, "message": SECRET}).encode())
    assert "api_code=None" in caplog.text
    assert "123456789012" not in caplog.text
    _assert_private(caplog)


def test_header_values_are_classified_without_reflecting_unknown_data(caplog):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    exchange = _exchange()
    diagnostics.response_headers(exchange, status=405, headers={
        "Server": SECRET, "Content-Type": SECRET, "Content-Encoding": SECRET,
        "Content-Length": SECRET, "Retry-After": SECRET, "Date": SECRET,
        "Allow": SECRET, "Set-Cookie": f"{SECRET}={SECRET}", "X-Private": SECRET,
    })
    assert "server_family=other" in caplog.text
    assert "allow_methods=none allow_unknown_methods=True" in caplog.text
    assert "server_date=invalid" in caplog.text
    _assert_private(caplog)


class _Response:
    def __init__(self, *, status=200, headers=None, body=b'{"code":"000000","data":{}}', error=None):
        self.status, self.headers, self.body, self.error = status, headers or {}, body, error
        self.content = self
        self.reads = 0

    async def __aenter__(self):
        if self.error is not None:
            raise self.error
        return self

    async def __aexit__(self, *_args):
        return None

    async def iter_chunked(self, _size):
        self.reads += 1
        yield self.body


def _transport(response, *, limit=4 * 1024 * 1024):
    session = SimpleNamespace(
        trust_env=False, headers={}, cookie_jar=aiohttp.DummyCookieJar(),
        _raise_for_status=False, _retry_connection=False, _middlewares=(), _trace_configs=[],
        _request_class=aiohttp.ClientRequest, _response_class=aiohttp.ClientResponse,
        closed=False, request=Mock(return_value=response),
    )
    return AiohttpTransport(cast(aiohttp.ClientSession, session), max_response_bytes=limit), session


async def _execute(transport, request=None):
    return await transport.execute(request or _request(), deadline=_Deadline(asyncio.get_running_loop().time() + 10), connect_timeout=3, read_timeout=3)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "headers", "expected"), [
    (302, {"Location": SECRET}, GwmRedirectError),
    (405, {"Content-Encoding": "gzip", "Set-Cookie": f"acw_tc={SECRET}"}, GwmProtocolError),
    (405, {"Content-Length": "9999"}, GwmResponseTooLargeError),
    (405, {"Content-Length": SECRET}, GwmProtocolError),
])
async def test_header_diagnostics_survive_transport_policy_rejections(caplog, status, headers, expected):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    response = _Response(status=status, headers=headers, body=SECRET.encode())
    transport, session = _transport(response, limit=100)
    with pytest.raises(expected):
        await _execute(transport)
    assert f"http_status={status}" in caplog.text
    assert "event=transport_failure" in caplog.text
    assert response.reads == 0
    session.request.assert_called_once()
    _assert_private(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize(("cause", "expected"), [
    (OSError(SECRET), GwmNetworkError), (TimeoutError(SECRET), GwmDeadlineExceededError),
    (ssl.SSLError(SECRET), GwmTlsError),
    (RuntimeError(SECRET), RuntimeError), (asyncio.CancelledError(SECRET), asyncio.CancelledError),
])
async def test_transport_failures_keep_original_behavior_without_exception_messages(caplog, cause, expected):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    transport, session = _transport(_Response(error=cause))
    with pytest.raises(expected):
        await _execute(transport)
    session.request.assert_called_once()
    assert "event=transport_failure" in caplog.text
    _assert_private(caplog)


@pytest.mark.asyncio
async def test_success_envelope_shape_is_repeated_on_later_validation_failure_without_debug(caplog):
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with pytest.raises(GwmSchemaError), diagnostics.authentication_scope(
        flow="interactive", saved_state=False, access_present=False, refresh_present=False,
        identity_present=False, password_login_allowed=True, verification_supplied=False,
    ):
        transport, _ = _transport(_Response(body=json.dumps({
            "code": "000000", "data": {"accessToken": SECRET, "refreshToken": None, "encoded": SECRET},
        }).encode()))
        await _execute(transport)
        assert not caplog.records
        raise GwmSchemaError(operation="login")
    assert "event=attempt_last_response" in caplog.text
    assert "http_status=200" in caplog.text
    assert "auth_fields=accessToken:string,refreshToken:null,encoded:string" in caplog.text
    assert "category=schema_error" in caplog.text
    _assert_private(caplog)


def test_identity_validation_logs_only_fixed_reasons_and_stages(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    diagnostics.identity_check("issued_context", "renewal_needed", reason="identity_renewal_required")
    diagnostics.identity_check(SECRET, SECRET, reason=SECRET)
    diagnostics.identity_check("enrolled_identity", "rejected", reason={SECRET: SECRET})
    assert "stage=issued_context outcome=renewal_needed reason=identity_renewal_required" in caplog.text
    assert "stage=unknown outcome=unknown reason=unspecified" in caplog.text
    _assert_private(caplog)


@pytest.mark.asyncio
async def test_real_transport_keeps_request_bytes_response_bytes_and_header_contract(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    request = _request()
    response = _Response(status=405, headers={"Content-Type": "text/html", "Set-Cookie": SECRET}, body=f"<html>{SECRET}</html>".encode())
    transport, session = _transport(response)
    result = await _execute(transport, request)
    assert result.status == 405
    assert result.body is response.body or result.body == response.body
    assert result.headers == {"content-type": "text/html"}
    assert session.request.call_args.kwargs["data"] is request.body
    assert str(session.request.call_args.args[1]) == request.url
    assert session.request.call_args.kwargs["allow_redirects"] is False
    assert session.request.call_args.kwargs["auto_decompress"] is False
    session.request.assert_called_once()
    _assert_private(caplog)


@pytest.mark.asyncio
async def test_logging_handler_failure_cannot_change_authentication_io(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    monkeypatch.setattr(diagnostics._LOGGER, "log", Mock(side_effect=RuntimeError(SECRET)))
    transport, session = _transport(_Response())
    result = await _execute(transport)
    assert result.status == 200
    session.request.assert_called_once()


@pytest.mark.asyncio
async def test_scopes_correlate_concurrent_attempts_and_reset_after_failure(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    async def run(fail):
        with diagnostics.authentication_scope(flow="startup_resume", saved_state=True, access_present=True,
                                             refresh_present=True, identity_present=True,
                                             password_login_allowed=False, verification_supplied=False) as attempt:
            await asyncio.sleep(0)
            exchange = _exchange()
            assert exchange.fields["attempt"] == attempt.identifier
            if fail:
                error = GwmHttpError(operation="refresh_token", status=405)
                error.args = (SECRET,)
                raise error
            attempt.complete("authenticated")
            return attempt.identifier

    results = await asyncio.gather(run(False), run(True), return_exceptions=True)
    assert isinstance(results[0], int)
    assert isinstance(results[1], GwmHttpError)
    assert "event=attempt_failure" in caplog.text
    assert "http_status=405" in caplog.text
    assert "password_login_allowed=False" in caplog.text
    assert _exchange().fields["attempt"] == 0
    _assert_private(caplog)
