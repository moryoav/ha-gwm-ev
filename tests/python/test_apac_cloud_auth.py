"""Home Assistant authentication boundary for the isolated APAC flow."""

import pytest

import custom_components.gwm_ora.cloud_auth as cloud_auth
from custom_components.gwm_ora.cloud_auth import GwmCloudAuthenticator, GwmCloudCredentials
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.gwm_client.apac_flow import ApacVerificationRequired
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.errors import GwmConfigurationError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


def _credentials():
    return GwmCloudCredentials(REGION_APAC, "PK", "person@example.invalid", "synthetic-password", "a" * 32)


def _material():
    return ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")


@pytest.mark.asyncio
async def test_apac_authentication_requires_private_material():
    with pytest.raises(GwmConfigurationError):
        await GwmCloudAuthenticator().async_authenticate(_credentials())


@pytest.mark.asyncio
async def test_apac_authentication_closes_owned_transport_and_preserves_opt_in(monkeypatch):
    calls = []
    class FakeTransport:
        async def aclose(self): calls.append("closed")
    monkeypatch.setattr(cloud_auth.AiohttpTransport, "create_owned", lambda **kwargs: FakeTransport())
    async def fake_authenticate(**kwargs):
        calls.append(kwargs["allow_password_login"])
        state = ApacAuthState.for_credentials(kwargs["credentials"])
        return ApacVerificationRequired(state, code_requested=False)
    monkeypatch.setattr(cloud_auth, "authenticate_apac", fake_authenticate)
    auth = GwmCloudAuthenticator(apac_material_loader=_material)
    result = await auth.async_authenticate(_credentials(), allow_password_login=False)
    assert isinstance(result, ApacVerificationRequired)
    assert calls == [False, "closed"]
