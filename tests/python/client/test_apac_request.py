"""Synthetic-only tests for signed APAC request preparation."""

import ssl
from types import SimpleNamespace

import pytest

from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_request import prepare_apac_request
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.regions import TlsMode


def _args(*, mtls: bool = False) -> dict:
    """Provide synthetic signing material and the requested TLS role."""
    context = ssl.create_default_context()
    if mtls:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    return {
        "material": ApacMaterial(
            EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
            "synthetic-key",
            "synthetic-secret",
        ),
        "ssl_context": context,
        "device_id": "a" * 32,
        "country": "PK",
    }


def test_signed_status_request_is_read_only_and_redacted() -> None:
    """Encode the vehicle identifier and hide request secrets in repr."""
    request = prepare_apac_request(
        **_args(mtls=True), operation="get_last_status", access_token="synthetic-token", vehicle_id="synthetic/vehicle"
    )
    assert request.method == "GET"
    assert request.url.startswith("https://ap-app-gateway.gwmcloud.com/")
    assert "synthetic%2Fvehicle" in request.url
    assert request.headers["country"] == "PK"
    assert "synthetic" not in repr(request)
    assert request.body is None


def test_login_post_uses_exact_synthetic_payload() -> None:
    """Preserve the exact serialized login bytes that are signed."""
    request = prepare_apac_request(**_args(), operation="login", body={"account": "synthetic"})
    assert request.method == "POST"
    assert request.body == b'{"account":"synthetic"}'
    assert request.headers["Content-Type"] == "application/json; charset=utf-8"


@pytest.mark.parametrize("operation", ["send_lock_command", "set_charging_plan", "charge_now"])
def test_vehicle_write_cannot_build_a_request(operation: str) -> None:
    """Reject control requests before constructing a transport request."""
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**_args(), operation=operation, body={})


def test_bad_tls_and_missing_authentication_fail_closed() -> None:
    """Reject unverified TLS and missing tokens at request preparation."""
    args = _args()
    args["ssl_context"] = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**args, operation="login", body={})
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**_args(), operation="acquire_vehicles")


@pytest.mark.parametrize("country", ["TH", "MY", "ID", "PK"])
def test_selected_country_reaches_request_headers(country: str) -> None:
    """Preserve the selected APAC country instead of defaulting to Pakistan."""
    args = {**_args(mtls=True), "country": country}
    request = prepare_apac_request(**args, operation="acquire_vehicles", access_token="synthetic-token")
    assert request.headers["country"] == request.headers["regionCode"] == country


@pytest.mark.parametrize(
    "operation", ["login", "request_verification", "verify_code", "refresh_token", "get_user_info"]
)
def test_legacy_mtls_policy_cannot_reach_h5_gateways(operation: str) -> None:
    """Reject weakened identity contexts on standard TLS authentication hosts."""
    args = _args(mtls=True)
    if operation == "get_user_info":
        args["access_token"] = "synthetic-token"
    else:
        args["body"] = {}
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**args, operation=operation)


@pytest.mark.parametrize(
    "operation", ["enroll_certificate", "acquire_vehicles", "get_last_status", "get_vehicle_basics"]
)
def test_default_context_cannot_replace_an_mtls_identity(operation: str) -> None:
    """Require APAC identity policy for enrollment and vehicle gateway calls."""
    args = {**_args(), "access_token": "synthetic-token"}
    if operation == "enroll_certificate":
        args.update(body={}, enrollment_device_id="a" * 32 + "1234567890123")
    elif operation != "acquire_vehicles":
        args["vehicle_id"] = "SYNTHETIC-VEHICLE"
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**args, operation=operation)


@pytest.mark.parametrize("registered_mode", [None, TlsMode.APAC_BOOTSTRAP_MTLS])
def test_unvalidated_or_bootstrap_context_cannot_reach_the_vehicle_host(registered_mode: TlsMode | None) -> None:
    """An untagged legacy context or bootstrap identity cannot authorize reads."""
    args = _args()
    context = args["ssl_context"]
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    if registered_mode is not None:
        _register_validated_context(context, registered_mode)
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(**args, operation="acquire_vehicles", access_token="synthetic-token")


def test_issued_context_cannot_replace_the_bootstrap_identity() -> None:
    """Do not send the account-issued identity to the enrollment gateway."""
    with pytest.raises(ValueError, match="^apac_request_invalid$"):
        prepare_apac_request(
            **_args(mtls=True),
            operation="enroll_certificate",
            access_token="synthetic-token",
            enrollment_device_id="a" * 32 + "1234567890123",
            body={},
        )


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("get_last_status", "4bc0dad9591a5dda11b2d8c954ab21b378c240cc869c7c5adde77d450cc936ad"),
        ("login", "0be3b58369fc6836601927018a580000fe6abbc2116952af5a485189dfb2ae6c"),
    ],
)
def test_synthetic_signing_vectors_cover_body_encoding_and_empty_query_values(
    monkeypatch, operation: str, expected: str
) -> None:
    """Lock down independent synthetic vectors, not vendor-captured signatures."""
    from custom_components.gwm_ora.gwm_client import signing

    monkeypatch.setattr(signing.time, "time_ns", lambda: 1700000000123 * 1_000_000)
    monkeypatch.setattr(signing.uuid, "uuid4", lambda: SimpleNamespace(hex="0123456789abcdef" * 2))
    args = _args(mtls=operation == "get_last_status")
    if operation == "get_last_status":
        args.update(access_token="synthetic-token", vehicle_id="synthetic/vehicle")
    else:
        args["body"] = {"account": "person@example.invalid", "password": "synthetic password"}
    request = prepare_apac_request(**args, operation=operation)
    assert request.headers["bt-auth-appkey"] == "synthetic-key"
    assert request.headers["bt-auth-nonce"] == "0123456789ABCDEF"
    assert request.headers["bt-auth-timestamp"] == "1700000000123"
    assert request.headers["bt-auth-sign"] == expected
    if operation == "get_last_status":
        assert request.url.endswith("?vin=synthetic%2Fvehicle&seqNo=")
        assert request.body is None
    else:
        assert request.body == b'{"account":"person@example.invalid","password":"synthetic password"}'
