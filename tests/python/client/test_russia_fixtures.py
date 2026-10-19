"""Offline golden contracts for Russia authentication, identity, and reads."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from custom_components.gwm_ora.gwm_client.crypto import load_certificate, recover_transformed_private_key
from custom_components.gwm_ora.gwm_client.models import (
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)
from custom_components.gwm_ora.gwm_client.regions import Region, get_region_protocol
from custom_components.gwm_ora.gwm_client.signing import RUSSIA_GWM_AUTH, sign_request

FIXTURE_DIR = Path(__file__).with_name("fixtures")
AUTH_FIXTURE_PATH = FIXTURE_DIR / "russia_auth_contracts_v1.json"
READ_FIXTURE_PATH = FIXTURE_DIR / "russia_read_responses_v1.json"
RESOURCE_DIR = (
    Path(__file__).resolve().parents[3]
    / "custom_components"
    / "gwm_ora"
    / "resources"
)
_PEM_CERTIFICATE = re.compile(
    br"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)


def _fixture(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_russia_auth_fixture_closes_every_route_body_and_signature() -> None:
    fixture = _fixture(AUTH_FIXTURE_PATH)
    signing = fixture["signing"]
    operations = fixture["operations"]
    assert isinstance(signing, dict)
    assert isinstance(operations, dict)
    assert set(operations) == {
        "get_user_info",
        "login",
        "refresh",
        "request_verification",
        "verified_login",
    }
    assert signing == {
        "profile": "russia-gwm-auth",
        "prefix": "gwm-auth-",
        "app_key": "4694605273",
        "timestamp": "1721462400123",
        "nonce": "0123456789abcdef",
    }

    for name, value in operations.items():
        assert isinstance(value, dict)
        body = value["body"]
        assert body is None or isinstance(body, str)
        url = f"https://{value['host']}{value['path']}"
        signed = sign_request(
            RUSSIA_GWM_AUTH,
            str(value["method"]),
            url,
            body,
            timestamp=str(signing["timestamp"]),
            nonce=str(signing["nonce"]),
        )
        parsed = urlsplit(signed.url)
        assert parsed.scheme == "https"
        assert parsed.hostname == "rus-h5-gateway.gwmcloud.com"
        assert parsed.query == ""
        assert value["tls_mode"] == "default"
        assert signed.headers["gwm-auth-sign"] == value["signature"], name
        assert signed.headers["gwm-auth-appkey"] == signing["app_key"]
        assert not any(header.startswith("bt-auth-") for header in signed.headers)

    login = operations["login"]
    verified = operations["verified_login"]
    assert isinstance(login, dict) and isinstance(login["body"], str)
    assert isinstance(verified, dict) and isinstance(verified["body"], str)
    login_body = json.loads(login["body"])
    verified_body = json.loads(verified["body"])
    assert "countryCode" not in login_body
    assert login_body["agreement"] == [1, 2, 18, 19]
    assert login_body["isEncrypt"] is False
    assert login_body["deviceId"] == fixture["credentials"]["api_device_id"]  # type: ignore[index]
    assert verified_body["agreement"] == [1, 2, 18, 19]
    assert verified_body["smsCode"] == "SYNTHETIC-246810"
    assert operations["get_user_info"]["access_token_header"] is True  # type: ignore[index]
    assert all(
        value["access_token_header"] is False
        for name, value in operations.items()
        if name != "get_user_info" and isinstance(value, dict)
    )


def test_russia_auth_fixture_matches_regional_header_contract() -> None:
    fixture = _fixture(AUTH_FIXTURE_PATH)
    required_headers = fixture["required_headers"]
    credentials = fixture["credentials"]
    assert isinstance(required_headers, dict)
    assert isinstance(credentials, dict)
    protocol = get_region_protocol(Region.RUSSIA)
    expected = {
        **protocol.base_headers,
        "country": "RU",
        "regionCode": "RU",
        "deviceId": credentials["api_device_id"],
        "iccid": credentials["api_device_id"],
    }
    assert required_headers == expected
    assert required_headers["deviceId"] == credentials["device_id"]


def test_russia_bootstrap_fixture_contains_only_public_metadata_and_digests() -> None:
    fixture = _fixture(AUTH_FIXTURE_PATH)
    expected = fixture["bootstrap_identity"]
    assert isinstance(expected, dict)
    assert set(expected) == {
        "app_tls_mode",
        "ca_bundle_certificate_der_sha256",
        "certificate_der_sha256",
        "certificate_spki_sha256",
        "client_chain_certificate_der_sha256",
        "h5_tls_mode",
        "issuer_common_name",
        "not_valid_after",
        "not_valid_before",
        "rsa_bits",
        "rsa_public_exponent",
        "subject_common_name",
        "subject_country",
        "transformed_key_source_sha256",
    }

    certificate_data = (RESOURCE_DIR / "gwm_general_rus.cer").read_bytes()
    transformed_key_data = (RESOURCE_DIR / "gwm_general_rus.key").read_bytes()
    ca_bundle = (RESOURCE_DIR / "gwm_root_rus.pem").read_bytes()
    certificate = load_certificate(certificate_data)
    private_key = recover_transformed_private_key(certificate_data, transformed_key_data)
    public_key = certificate.public_key()

    assert certificate.fingerprint(hashes.SHA256()).hex() == expected["certificate_der_sha256"]
    assert hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest() == expected["certificate_spki_sha256"]
    assert hashlib.sha256(transformed_key_data).hexdigest() == expected["transformed_key_source_sha256"]
    assert private_key.public_key().public_numbers() == public_key.public_numbers()
    assert public_key.key_size == expected["rsa_bits"]
    assert public_key.public_numbers().e == expected["rsa_public_exponent"]
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == expected["subject_common_name"]
    assert certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == expected["subject_country"]
    assert certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == expected["issuer_common_name"]
    assert certificate.not_valid_before_utc.isoformat() == expected["not_valid_before"]
    assert certificate.not_valid_after_utc.isoformat() == expected["not_valid_after"]

    bundle_hashes = [
        hashlib.sha256(base64.b64decode(b"".join(payload.split()), validate=True)).hexdigest()
        for payload in _PEM_CERTIFICATE.findall(ca_bundle)
    ]
    assert bundle_hashes == expected["ca_bundle_certificate_der_sha256"]
    assert expected["client_chain_certificate_der_sha256"] == [
        expected["certificate_der_sha256"],
        bundle_hashes[1],
    ]
    assert expected["h5_tls_mode"] == "default"
    assert expected["app_tls_mode"] == "russia_bootstrap_mtls"


def test_russia_read_fixture_preserves_only_typed_synthetic_parity_fields() -> None:
    fixture = _fixture(READ_FIXTURE_PATH)
    responses = fixture["responses"]
    assert isinstance(responses, dict)

    vehicles = parse_cloud_vehicles(
        responses["acquire_vehicles"],
        allow_numbers_for_strings=True,
    )
    status = parse_cloud_vehicle_status(
        responses["get_last_status"],
        allow_stringified_numbers=True,
        allow_numbers_for_strings=True,
    )
    basics = parse_cloud_vehicle_basics(
        responses["get_vehicle_basics"],
        allow_numbers_for_strings=True,
    )

    assert len(vehicles) == 1
    assert vehicles[0].identifier.value == fixture["identifier"]
    assert vehicles[0].vehicle_id == "9007199254740993"
    assert status.device_id == "9007199254740995"
    assert status.acquisition_time_ms == 1_787_747_696_789
    assert status.update_time_ms == 1_787_747_697_890
    assert status.latitude == 1.25
    assert status.longitude == -2.5
    assert [(item.code, item.unit) for item in status.items] == [
        ("2013021", "1"),
        ("NESTED", None),
    ]
    assert basics.climate is not None
    assert basics.climate.temperature == "22"
    assert basics.climate.operation_time == "7"
    assert basics.climate.engine_operation_time == "9"
    rendered = repr((vehicles, status, basics))
    assert "SYNTHETIC-owner@example.invalid" not in rendered
    assert "SYNTHETIC-LICENSE-NOT-RETAINED" not in rendered
    assert str(fixture["identifier"]) not in rendered


def test_russia_string_or_number_fields_reject_json_booleans() -> None:
    with pytest.raises(ValueError):
        parse_cloud_vehicles(
            [{"vin": "SYNTHETIC+RUS/OPAQUE=", "vehicleId": True}],
            allow_numbers_for_strings=True,
        )
