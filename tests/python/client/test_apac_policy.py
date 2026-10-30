"""APAC policy tests with synthetic-only signing material."""

from __future__ import annotations

import pytest

from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_policy import apac_calling_code, apac_gateways, validate_apac_country
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.regions import GatewayRole, TlsMode, get_region_protocol


def _material() -> ApacMaterial:
    """Create a synthetic externally supplied APAC signing profile."""
    return ApacMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key",
        "synthetic-secret",
    )


def test_gateway_policy_is_immutable_and_uses_injected_profile() -> None:
    """Keep routing immutable and each gateway on its own TLS policy."""
    routes = apac_gateways(_material())
    assert routes[GatewayRole.AUTH_V2].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v2.0/"
    assert routes[GatewayRole.H5_V1].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v1.0/"
    assert routes[GatewayRole.APP_V1].tls_mode is TlsMode.APAC_ISSUED_MTLS
    assert routes[GatewayRole.CERTIFICATE_V1].tls_mode is TlsMode.APAC_BOOTSTRAP_MTLS
    assert routes[GatewayRole.APP_V1].signing_profile.app_secret == "synthetic-secret"
    with pytest.raises(TypeError):
        routes[GatewayRole.APP_V1] = routes[GatewayRole.H5_V1]  # type: ignore[index]


@pytest.mark.parametrize("country", ["pk", "", "US", "AU", "NZ", "RU", None, []])
def test_countries_outside_apac_are_rejected(country: str) -> None:
    """Reject countries outside the app-listed APAC family."""
    with pytest.raises(ValueError, match="^apac_country_invalid$"):
        validate_apac_country(country)


@pytest.mark.parametrize("country,calling_code", [("TH", "+66"), ("MY", "+60"), ("ID", "+62"), ("PK", "+92")])
def test_app_listed_countries_have_explicit_calling_codes(country: str, calling_code: str) -> None:
    """Generalize protocol configuration without asserting live country support."""
    assert validate_apac_country(country) == country
    assert apac_calling_code(country) == calling_code


@pytest.mark.parametrize("region", ["eu", "aus", "rus"])
def test_existing_regional_policy_does_not_change(region: str) -> None:
    """Keep existing gateway and header policies unchanged after APAC use."""
    before = get_region_protocol(region)
    before_gateways = dict(before.gateways)
    before_headers = dict(before.base_headers)
    apac_gateways(_material())
    assert get_region_protocol(region) is before
    assert dict(before.gateways) == before_gateways
    assert dict(before.base_headers) == before_headers
    assert validate_apac_country("PK") == "PK"


def test_apac_is_not_registered_as_an_existing_region() -> None:
    """Keep the experimental APAC client outside production region routing."""
    with pytest.raises(ValueError, match="^unsupported region$"):
        get_region_protocol("apac")
