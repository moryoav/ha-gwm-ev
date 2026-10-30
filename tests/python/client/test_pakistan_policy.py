"""Pakistan policy tests with synthetic-only signing material."""

from __future__ import annotations

import pytest

from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.pakistan_material import PakistanMaterial
from custom_components.gwm_ora.gwm_client.pakistan_policy import pakistan_gateways, validate_pakistan_country
from custom_components.gwm_ora.gwm_client.regions import GatewayRole, TlsMode, get_region_protocol


def _material() -> PakistanMaterial:
    return PakistanMaterial(
        EuBootstrapMaterial(b"synthetic-certificate", b"c3ludGhldGljLWtleQ==", b"synthetic-ca"),
        "synthetic-key",
        "synthetic-secret",
    )


def test_gateway_policy_is_immutable_and_uses_injected_profile() -> None:
    routes = pakistan_gateways(_material())
    assert routes[GatewayRole.AUTH_V2].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v2.0/"
    assert routes[GatewayRole.H5_V1].base_url == "https://ap-h5-gateway.gwmcloud.com/app-api/api/v1.0/"
    assert routes[GatewayRole.APP_V1].tls_mode is TlsMode.EU_ISSUED_MTLS
    assert routes[GatewayRole.CERTIFICATE_V1].tls_mode is TlsMode.EU_BOOTSTRAP_MTLS
    assert routes[GatewayRole.APP_V1].signing_profile.app_secret == "synthetic-secret"
    with pytest.raises(TypeError):
        routes[GatewayRole.APP_V1] = routes[GatewayRole.H5_V1]  # type: ignore[index]


@pytest.mark.parametrize("country", ["TH", "MY", "ID", "pk", "", "US"])
def test_only_confirmed_country_is_accepted(country: str) -> None:
    with pytest.raises(ValueError, match="^pakistan_country_invalid$"):
        validate_pakistan_country(country)


def test_existing_regional_policy_does_not_change() -> None:
    before = get_region_protocol("eu")
    pakistan_gateways(_material())
    assert get_region_protocol("eu") is before
    assert validate_pakistan_country("PK") == "PK"
