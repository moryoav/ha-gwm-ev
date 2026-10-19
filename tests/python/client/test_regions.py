"""Contract tests for immutable regional GWM protocol policies."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from custom_components.gwm_ora.gwm_client.regions import (
    GatewayConfig,
    GatewayRole,
    Region,
    RegionProtocol,
    TlsMode,
    get_region_protocol,
)

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "region_contracts_v1.json"


def _contract_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_public_enum_wire_values_are_stable() -> None:
    assert [region.value for region in Region] == ["eu", "aus", "rus"]
    assert [role.value for role in GatewayRole] == [
        "h5_v1",
        "auth_v2",
        "app_v1",
        "certificate_v1",
    ]
    assert [mode.value for mode in TlsMode] == [
        "default",
        "eu_bootstrap_mtls",
        "eu_issued_mtls",
        "russia_bootstrap_mtls",
    ]


def test_versioned_synthetic_fixture_matches_every_regional_contract() -> None:
    fixture = _contract_fixture()
    assert fixture["schema_version"] == 1
    assert [case["region"] for case in fixture["regions"]] == ["eu", "aus", "rus"]

    for case in fixture["regions"]:
        gateway_roles = set(case["gateways"])
        unsupported_roles = set(case["unsupported_gateways"])
        assert gateway_roles.isdisjoint(unsupported_roles)
        assert gateway_roles | unsupported_roles == {role.value for role in GatewayRole}

        protocol = get_region_protocol(case["region"])
        assert protocol.region.value == case["region"]
        assert protocol.device_id_length == case["device_id_length"]
        expected_countries = case["allowed_countries"]
        assert protocol.allowed_countries == (
            None if expected_countries is None else frozenset(expected_countries)
        )
        assert dict(protocol.base_headers) == case["base_headers"]
        assert {role.value for role in protocol.gateways} == gateway_roles

        for role_value, expected in case["gateways"].items():
            gateway = protocol.gateway(role_value)
            assert gateway.role.value == role_value
            assert gateway.base_url == expected["base_url"]
            assert gateway.signing_profile.name == expected["signing_profile"]
            assert gateway.tls_mode.value == expected["tls_mode"]

        for role_value in case["unsupported_gateways"]:
            with pytest.raises(
                ValueError,
                match="^gateway role is not supported by the region$",
            ):
                protocol.gateway(role_value)

        request = case["synthetic_request"]
        assert protocol.validate_country(request["country"]) == request["country"]
        assert protocol.normalize_device_id(request["device_id"]) == request["normalized_device_id"]
        headers = protocol.authenticated_headers(
            country=request["country"],
            device_id=request["device_id"],
            access_token=request["access_token"],
        )
        assert dict(headers) == request["headers"]
        with pytest.raises(TypeError):
            headers["accessToken"] = "replacement"  # type: ignore[index]


def test_get_region_protocol_accepts_enums_and_normalized_strings() -> None:
    assert get_region_protocol(Region.EU) is get_region_protocol("eu")
    assert get_region_protocol(" AUS ") is get_region_protocol(Region.ANZ)
    assert get_region_protocol("RUS") is get_region_protocol(Region.RUSSIA)


@pytest.mark.parametrize("region", ["unknown", 7, None])
def test_get_region_protocol_rejects_unknown_values_without_echoing_them(
    region: object,
) -> None:
    with pytest.raises(ValueError, match="^unsupported region$") as raised:
        get_region_protocol(region)  # type: ignore[arg-type]
    assert str(region) not in str(raised.value)


def test_get_region_protocol_rejects_empty_region() -> None:
    with pytest.raises(ValueError, match="^unsupported region$"):
        get_region_protocol("")


@pytest.mark.parametrize("country", ["il", "I", "ISR", "I1", " I"])
def test_country_must_already_be_uppercase_iso2(country: str) -> None:
    with pytest.raises(
        ValueError,
        match="^country must be an uppercase ISO-2 code$",
    ):
        get_region_protocol(Region.EU).validate_country(country)


@pytest.mark.parametrize(
    ("region", "country"),
    [(Region.ANZ, "IL"), (Region.RUSSIA, "AU")],
)
def test_country_must_match_restricted_regions(region: Region, country: str) -> None:
    with pytest.raises(
        ValueError,
        match="^country is not supported by the region$",
    ):
        get_region_protocol(region).validate_country(country)


def test_device_id_normalization_preserves_regional_difference() -> None:
    device_id = "feedface-dead-beef-cafe-0123456789ab"
    assert get_region_protocol(Region.EU).normalize_device_id(device_id) == "feedfacedeadbeef"
    assert get_region_protocol(Region.ANZ).normalize_device_id("abc-def") == "abcdef0000000000"
    assert get_region_protocol(Region.RUSSIA).normalize_device_id(device_id) == device_id


@pytest.mark.parametrize(
    "device_id",
    ["", "----", "not-hex", "with space", "abc\r\ndef", "a" * 65],
)
def test_unsafe_device_ids_are_rejected_with_a_fixed_message(device_id: str) -> None:
    with pytest.raises(
        ValueError,
        match="^device ID must contain only hexadecimal characters and hyphens$",
    ):
        get_region_protocol(Region.EU).normalize_device_id(device_id)


@pytest.mark.parametrize(
    "token",
    ["", "token with spaces", "token\r\nInjected:value", "café", "x" * (16 * 1024 + 1)],
)
def test_unsafe_access_tokens_are_rejected_with_a_fixed_message(token: str) -> None:
    with pytest.raises(
        ValueError,
        match="^access token must be visible ASCII and within the size limit$",
    ):
        get_region_protocol(Region.ANZ).authenticated_headers(
            country="AU",
            device_id="feedface",
            access_token=token,
        )


def test_access_tokens_are_request_local_and_protocol_policies_are_immutable() -> None:
    protocol = get_region_protocol(Region.ANZ)
    first = protocol.authenticated_headers(
        country="NZ",
        device_id="feedface",
        access_token="SYNTHETIC-FIRST-TOKEN",
    )
    second = protocol.authenticated_headers(
        country="NZ",
        device_id="feedface",
        access_token="SYNTHETIC-SECOND-TOKEN",
    )

    assert first["accessToken"] == "SYNTHETIC-FIRST-TOKEN"
    assert second["accessToken"] == "SYNTHETIC-SECOND-TOKEN"
    assert "SYNTHETIC" not in repr(protocol)
    assert "accessToken" not in protocol.base_headers

    with pytest.raises(TypeError):
        protocol.base_headers["brand"] = "replacement"  # type: ignore[index]
    with pytest.raises(TypeError):
        protocol.gateways[GatewayRole.APP_V1] = protocol.gateway(GatewayRole.APP_V1)  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        protocol.region = Region.EU  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        protocol.gateway(GatewayRole.APP_V1).base_url = "https://example.invalid/"  # type: ignore[misc]


def test_region_protocol_rejects_mismatched_gateway_keys() -> None:
    gateway = GatewayConfig(
        role=GatewayRole.APP_V1,
        base_url="https://example.invalid/",
        signing_profile=get_region_protocol(Region.ANZ).gateway(GatewayRole.APP_V1).signing_profile,
        tls_mode=TlsMode.DEFAULT,
    )

    with pytest.raises(
        ValueError,
        match="^gateway role does not match its configuration$",
    ):
        RegionProtocol(
            region=Region.ANZ,
            gateways={GatewayRole.H5_V1: gateway},
            base_headers={},
            device_id_length=16,
            allowed_countries=frozenset({"AU", "NZ"}),
        )
