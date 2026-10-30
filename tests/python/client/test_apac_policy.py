"""APAC policy tests with synthetic-only signing material."""

from __future__ import annotations

import pytest

from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_policy import apac_calling_code, apac_gateways, validate_apac_country
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.regions import GatewayRole, TlsMode, get_region_protocol


def _material() -> ApacMaterial:
    return ApacMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key",
        "synthetic-secret",
    )


def test_gateway_policy_is_immutable_and_uses_injected_profile() -> None:
    routes = apac_gateways(_material())
    assert routes[GatewayRole.AUTH_V2].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v2.0/"
    assert routes[GatewayRole.H5_V1].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v1.0/"
    assert routes[GatewayRole.APP_V1].tls_mode is TlsMode.EU_ISSUED_MTLS
    assert routes[GatewayRole.CERTIFICATE_V1].tls_mode is TlsMode.EU_BOOTSTRAP_MTLS
    assert routes[GatewayRole.APP_V1].signing_profile.app_secret == "synthetic-secret"
    with pytest.raises(TypeError):
        routes[GatewayRole.APP_V1] = routes[GatewayRole.H5_V1]  # type: ignore[index]


@pytest.mark.parametrize("country", ["pk", "", "US", "AU", "NZ", "RU", None, []])
def test_countries_outside_apac_are_rejected(country: str) -> None:
    with pytest.raises(ValueError, match="^apac_country_invalid$"):
        validate_apac_country(country)


@pytest.mark.parametrize("country,calling_code", [("TH", "+66"), ("MY", "+60"), ("ID", "+62"), ("PK", "+92")])
def test_app_listed_countries_have_explicit_calling_codes(country: str, calling_code: str) -> None:
    """Generalize protocol configuration without asserting live country support."""
    assert validate_apac_country(country) == country
    assert apac_calling_code(country) == calling_code


def test_existing_regional_policy_does_not_change() -> None:
    before = get_region_protocol("eu")
    apac_gateways(_material())
    assert get_region_protocol("eu") is before
    assert validate_apac_country("PK") == "PK"
