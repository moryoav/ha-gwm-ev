"""BR request construction, password digest and envelope decoding (offline)."""

from __future__ import annotations

import hashlib
import json
import ssl
from pathlib import Path

import pytest
from support.br import envelope, html, write_dummy_material

from custom_components.gwm_ora.gwm_client.br_endpoints import br_endpoint
from custom_components.gwm_ora.gwm_client.br_identity import (
    BrCredentials,
    br_password_md5,
    generate_br_device_id,
    load_or_create_br_device_id,
)
from custom_components.gwm_ora.gwm_client.br_material import create_br_ssl_context, load_br_material
from custom_components.gwm_ora.gwm_client.br_request import GwmBrCredentialError, decode_br_envelope, prepare_br_request
from custom_components.gwm_ora.gwm_client.errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmHttpError,
    GwmSchemaError,
    GwmTlsError,
)

DEVICE = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def context(tmp_path: Path):
    write_dummy_material(tmp_path)
    return create_br_ssl_context(load_br_material(tmp_path))


def test_password_md5_is_lowercase_hex_of_plain_text() -> None:
    assert br_password_md5("Synthetic1") == hashlib.md5(b"Synthetic1").hexdigest()
    assert br_password_md5("Synthetic1") == br_password_md5("Synthetic1").lower()


def test_device_id_is_md5_shaped_and_persisted(tmp_path: Path) -> None:
    assert len(generate_br_device_id()) == 32
    path = tmp_path / "deviceid"
    first = load_or_create_br_device_id(path)
    assert load_or_create_br_device_id(path) == first
    assert path.stat().st_mode & 0o077 == 0


def test_login_uses_a_clean_default_tls_context_not_the_vehicle_identity(context) -> None:
    credentials = BrCredentials.from_password("someone@example.invalid", "Synthetic1", DEVICE)
    # The vehicle mTLS context (SECLEVEL=0, client certificate) is refused for the login host.
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="login", ssl_context=context, credentials=credentials)
    clean = ssl.create_default_context()
    assert clean.security_level > 0 and clean.check_hostname
    request = prepare_br_request(operation="login", ssl_context=clean, credentials=credentials)
    assert request.ssl_context is clean
    # And the reverse: the vehicle gateway still demands the mTLS context.
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="acquire_vehicles", ssl_context=clean, access_token="tok-a")


def test_login_request_headers_and_body() -> None:
    credentials = BrCredentials.from_password("someone@example.invalid", "Synthetic1", DEVICE)
    request = prepare_br_request(operation="login", ssl_context=ssl.create_default_context(), credentials=credentials)
    assert request.method == "POST"
    assert request.url == (
        "https://br-front-service.gwmcloud.com/br-official-commerce/br-official-gateway/"
        "pc-api/api/v1.0/userAuth/loginAccount"
    )
    headers = dict(request.headers)
    for name, value in {
        "appid": "6", "brand": "6", "brandid": "CCZ001", "country": "BR", "devicetype": "0",
        "enterpriseid": "CC01", "gwid": "", "language": "pt_BR", "rs": "5", "terminal": "GW_PC_GWM",
        "content-type": "application/json",
    }.items():
        assert headers[name] == value
    assert not {"accessToken", "refreshToken"} & set(headers)
    assert json.loads(request.body) == {
        "deviceid": DEVICE,
        "password": hashlib.md5(b"Synthetic1").hexdigest(),
        "account": "someone@example.invalid",
    }
    assert "Synthetic1" not in request.body.decode()
    assert "someone" not in repr(credentials)


def test_app_requests_headers_and_urls(context) -> None:
    listing = prepare_br_request(operation="acquire_vehicles", ssl_context=context, access_token="tok-a", refresh_token="tok-r")
    assert listing.method == "GET" and listing.body is None
    assert listing.url == "https://br-app-gateway.gwmcloud.com/app-api/api/v1.0/globalapp/vehicle/acquireVehicles"
    headers = dict(listing.headers)
    for name, value in {
        "rs": "2", "terminal": "GW_APP_GWM", "brand": "6", "language": "pt_BR", "systemtype": "2",
        "regioncode": "BR", "country": "BR", "accessToken": "tok-a", "refreshToken": "tok-r",
    }.items():
        assert headers[name] == value
    status = prepare_br_request(
        operation="get_last_status", ssl_context=context, access_token="tok-a", refresh_token="tok-r", vehicle_id="SYNTHETICVIN000001"
    )
    assert status.url.endswith("/vehicle/getLastStatus?vin=SYNTHETICVIN000001&flag=true")


def test_refresh_endpoint_is_the_h5_host_contract() -> None:
    endpoint = br_endpoint("refresh_token")
    assert (endpoint.method, endpoint.authenticated) == ("POST", True)
    assert endpoint.base_url + endpoint.path == (
        "https://br-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/refreshToken"
    )


@pytest.mark.parametrize("operation", ["send_command", "sendCmd", "send_climate_command", "refreshToken", ""])
def test_only_allowlisted_operations_exist(operation: str) -> None:
    with pytest.raises(ValueError, match="^br_operation_not_supported$"):
        br_endpoint(operation)


def test_app_request_requires_token_and_secure_context(context) -> None:
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="acquire_vehicles", ssl_context=context)
    import ssl

    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="acquire_vehicles", ssl_context=ssl.create_default_context(), access_token="t")


def test_credential_rejection_308001_is_a_clear_credential_error() -> None:
    with pytest.raises(GwmBrCredentialError) as error:
        decode_br_envelope(envelope(None, code="308001", description="bad password"), operation="login")
    assert isinstance(error.value, GwmAuthenticationError)
    assert error.value.api_code == "308001"
    assert "bad password" not in str(error.value)


def test_html_400_without_certificate_is_tls_error() -> None:
    with pytest.raises(GwmTlsError):
        decode_br_envelope(html(400, "No required SSL certificate was sent"), operation="acquire_vehicles")
    with pytest.raises(GwmTlsError):
        decode_br_envelope(html(400, "The SSL certificate error"), operation="acquire_vehicles")


def test_other_http_and_schema_failures() -> None:
    with pytest.raises(GwmHttpError) as http_error:
        decode_br_envelope(html(400, "Bad Request"), operation="get_last_status")
    assert http_error.value.status == 400
    with pytest.raises(GwmAuthenticationError):
        decode_br_envelope(html(401, "x"), operation="acquire_vehicles")
    with pytest.raises(GwmSchemaError):
        decode_br_envelope(html(200, "<p>oops</p>"), operation="acquire_vehicles")
    with pytest.raises(GwmApiError) as api_error:
        decode_br_envelope(envelope(None, code="999999"), operation="acquire_vehicles")
    assert api_error.value.api_code == "999999"
    with pytest.raises(GwmAuthenticationError):
        decode_br_envelope(envelope(None, code="999999"), operation="login")
    assert decode_br_envelope(envelope({"k": 1}), operation="login") == {"k": 1}


def test_refresh_request_url_body_headers_and_mtls(context) -> None:
    request = prepare_br_request(
        operation="refresh_token", ssl_context=context, access_token="tok-a", refresh_token="tok-r", device_id=DEVICE
    )
    assert request.method == "POST"
    assert request.url == "https://br-h5-gateway.gwmcloud.com/app-api/api/v1.0/userAuth/refreshToken"
    assert request.ssl_context is context and context.security_level == 0
    assert json.loads(request.body) == {"accessToken": "tok-a", "refreshToken": "tok-r", "deviceId": DEVICE[:16]}
    assert len(json.loads(request.body)["deviceId"]) == 16
    assert b" " not in request.body
    headers = dict(request.headers)
    assert headers["accessToken"] == "tok-a" and headers["refreshToken"] == "tok-r"
    assert headers["terminal"] == "GW_APP_GWM" and headers["content-type"] == "application/json"
    # The refresh host also demands the mTLS context, never the clean login one.
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(
            operation="refresh_token", ssl_context=ssl.create_default_context(),
            access_token="tok-a", refresh_token="tok-r", device_id=DEVICE,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"refresh_token": ""},
        {"device_id": None},
        {"device_id": "short"},
        {"device_id": DEVICE.upper()},
        {"vehicle_id": "SYNTHETICVIN000001"},
        {"access_token": None},
    ],
)
def test_refresh_request_rejects_incomplete_input(context, kwargs) -> None:
    base = {"access_token": "tok-a", "refresh_token": "tok-r", "device_id": DEVICE}
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="refresh_token", ssl_context=context, **{**base, **kwargs})


def test_device_id_is_only_accepted_by_the_refresh_operation(context) -> None:
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(operation="acquire_vehicles", ssl_context=context, access_token="t", device_id=DEVICE)
    credentials = BrCredentials.from_password("someone@example.invalid", "Synthetic1", DEVICE)
    with pytest.raises(ValueError, match="^br_request_invalid$"):
        prepare_br_request(
            operation="login", ssl_context=ssl.create_default_context(), credentials=credentials, device_id=DEVICE
        )


def test_refresh_envelope_failure_is_an_authentication_error() -> None:
    with pytest.raises(GwmAuthenticationError):
        decode_br_envelope(envelope(None, code="999999"), operation="refresh_token")
    for status in (401, 403):
        with pytest.raises(GwmAuthenticationError):
            decode_br_envelope(html(status, "x"), operation="refresh_token")
    assert decode_br_envelope(envelope({"accessToken": "a"}), operation="refresh_token") == {"accessToken": "a"}
