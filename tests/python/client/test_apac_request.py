"""Synthetic-only tests for signed APAC request preparation."""

import ssl

import pytest

from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_request import prepare_apac_request
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


def _args() -> dict:
    return {
        "material": ApacMaterial(
            EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
            "synthetic-key", "synthetic-secret",
        ),
        "ssl_context": ssl.create_default_context(),
        "device_id": "a" * 32,
        "country": "PK",
    }


def test_signed_status_request_is_read_only_and_redacted() -> None:
    request = prepare_apac_request(
        **_args(), operation="get_last_status", access_token="synthetic-token", vehicle_id="synthetic/vehicle"
    )
    assert request.method == "GET"
    assert request.url.startswith("https://ap-app-gateway.gwmcloud.com/")
    assert "synthetic%2Fvehicle" in request.url
    assert request.headers["country"] == "PK"
    assert "synthetic" not in repr(request)
    assert request.body is None


def test_login_post_uses_exact_synthetic_payload() -> None:
    request = prepare_apac_request(**_args(), operation="login", body={"account": "synthetic"})
    assert request.method == "POST"
    assert request.body == b'{"account":"synthetic"}'
    assert request.headers["Content-Type"] == "application/json; charset=utf-8"


@pytest.mark.parametrize("operation", ["send_lock_command", "set_charging_plan", "charge_now"])
def test_vehicle_write_cannot_build_a_request(operation: str) -> None:
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**_args(), operation=operation, body={})


def test_bad_tls_and_missing_authentication_fail_closed() -> None:
    args = _args()
    args["ssl_context"] = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**args, operation="login", body={})
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**_args(), operation="acquire_vehicles")


@pytest.mark.parametrize("country", ["TH", "MY", "ID", "PK"])
def test_selected_country_reaches_request_headers(country: str) -> None:
    """Preserve the selected APAC country instead of defaulting to Pakistan."""
    args = {**_args(), "country": country}
    request = prepare_apac_request(**args, operation="acquire_vehicles", access_token="synthetic-token")
    assert request.headers["country"] == request.headers["regionCode"] == country
