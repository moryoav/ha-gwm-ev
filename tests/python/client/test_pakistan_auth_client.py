"""Synthetic transport tests for Pakistan auth, without network requests."""

import json
import ssl

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.crypto import GeneratedClientCertificateRequest
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.pakistan_auth import PakistanCredentials
from custom_components.gwm_ora.gwm_client.pakistan_auth_client import PakistanAuthClient, PakistanTokens
from custom_components.gwm_ora.gwm_client.pakistan_material import PakistanMaterial


class FakeTransport:
    def __init__(self):
        self.requests = []

    async def execute(self, request, **kwargs):
        self.requests.append(request)
        data = {"accessToken": "synthetic-access", "refreshToken": "synthetic-refresh", "gwId": "synthetic-gw", "beanId": "synthetic-bean"}
        if request.operation == "enroll_certificate":
            data = {"encoded": "c3ludGhldGljLWNlcnQ="}
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_explicit_login_and_refresh_without_secret_repr() -> None:
    transport = FakeTransport()
    material = PakistanMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    client = PakistanAuthClient(material=material, credentials=PakistanCredentials("fake@example.invalid", "fake-password", "a" * 32), h5_context=ssl.create_default_context(), transport=transport)
    tokens = await client.login()
    assert tokens.access_token == "synthetic-access"
    assert "synthetic" not in repr(tokens)
    await client.refresh(tokens)
    assert [r.operation for r in transport.requests] == ["login", "refresh_token"]
    assert "fake-password" not in repr(transport.requests[0])


@pytest.mark.asyncio
async def test_verification_is_only_requested_explicitly() -> None:
    transport = FakeTransport()
    material = PakistanMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    client = PakistanAuthClient(material=material, credentials=PakistanCredentials("fake@example.invalid", "fake-password", "a" * 32), h5_context=ssl.create_default_context(), transport=transport)
    assert transport.requests == []
    await client.request_verification()
    await client.verify_code("123456")
    assert [r.operation for r in transport.requests] == ["request_verification", "verify_code"]


@pytest.mark.asyncio
async def test_enrollment_checks_issued_identity_before_return(monkeypatch) -> None:
    import custom_components.gwm_ora.gwm_client.pakistan_auth_client as auth

    transport = FakeTransport()
    material = PakistanMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    context = ssl.create_default_context()
    client = PakistanAuthClient(material=material, credentials=PakistanCredentials("fake@example.invalid", "fake-password", "a" * 32), h5_context=context, transport=transport)
    monkeypatch.setattr(auth, "generate_client_certificate_request", lambda *args, **kwargs: GeneratedClientCertificateRequest("fake-csr", "c3ludGhldGljLWtleQ=="))
    monkeypatch.setattr(auth, "create_pakistan_bootstrap_context", lambda material: context)
    checks = []
    def validate(identity, **kwargs):
        checks.append((identity, kwargs["ca_bundle"]))
        return context
    monkeypatch.setattr(auth, "create_pakistan_issued_context", validate)
    issued = await client.enroll_identity(PakistanTokens("fake-access", "fake-refresh", "fake-gw", "fake-bean"))
    assert issued.app_ssl_context is context
    assert len(checks) == 1
    assert [r.operation for r in transport.requests] == ["enroll_certificate"]
    assert "fake" not in repr(issued)
