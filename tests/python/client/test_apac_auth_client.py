"""Synthetic transport tests for APAC auth, without network requests."""

import asyncio
import json
import ssl

import pytest

from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacAuthClient, ApacTokens
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.crypto import GeneratedClientCertificateRequest
from custom_components.gwm_ora.gwm_client.errors import GwmDeadlineExceededError, GwmSchemaError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial


class FakeTransport:
    def __init__(self, *, response=None, error=None):
        self.requests = []
        self.response = response
        self.error = error

    async def execute(self, request, **kwargs):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        if self.response is not None:
            return self.response
        data = {"accessToken": "synthetic-access", "refreshToken": "synthetic-refresh", "gwId": "synthetic-gw", "beanId": "synthetic-bean"}
        if request.operation == "enroll_certificate":
            data = {"encoded": "c3ludGhldGljLWNlcnQ="}
        return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_explicit_login_and_refresh_without_secret_repr() -> None:
    transport = FakeTransport()
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    client = ApacAuthClient(material=material, credentials=ApacCredentials("fake@example.invalid", "fake-password", "a" * 32, country="PK"), h5_context=ssl.create_default_context(), transport=transport)
    tokens = await client.login()
    assert tokens.access_token == "synthetic-access"
    assert "synthetic" not in repr(tokens)
    await client.refresh(tokens)
    assert [r.operation for r in transport.requests] == ["login", "refresh_token"]
    assert "fake-password" not in repr(transport.requests[0])


@pytest.mark.asyncio
async def test_verification_is_only_requested_explicitly() -> None:
    transport = FakeTransport()
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    client = ApacAuthClient(material=material, credentials=ApacCredentials("fake@example.invalid", "fake-password", "a" * 32, country="PK"), h5_context=ssl.create_default_context(), transport=transport)
    assert transport.requests == []
    await client.request_verification()
    await client.verify_code("123456")
    assert [r.operation for r in transport.requests] == ["request_verification", "verify_code"]


def _auth_client(transport: FakeTransport) -> ApacAuthClient:
    """Build an authentication client using only synthetic private inputs."""
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    return ApacAuthClient(material=material, credentials=ApacCredentials("fake@example.invalid", "fake-password", "a" * 32, country="PK"), h5_context=ssl.create_default_context(), transport=transport)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["login", "refresh"])
async def test_auth_timeouts_use_the_client_error_without_fallback(operation: str) -> None:
    """A timed-out refresh must not start a password login or retry."""
    transport = FakeTransport(error=TimeoutError("private-value"))
    client = _auth_client(transport)
    with pytest.raises(GwmDeadlineExceededError) as error:
        if operation == "login":
            await client.login()
        else:
            await client.refresh(ApacTokens("fake-access", "fake-refresh", "fake-gw", "fake-bean"))
    assert error.value.operation == ("login" if operation == "login" else "refresh_token")
    assert "private" not in str(error.value)
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_auth_cancellation_propagates_without_retry() -> None:
    """Preserve cancellation when authentication is interrupted."""
    transport = FakeTransport(error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await _auth_client(transport).login()
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_enrollment_payload_uses_the_client_schema_error(monkeypatch) -> None:
    """Reject malformed enrollment responses before issuing a read session."""
    import custom_components.gwm_ora.gwm_client.apac_auth_client as auth

    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    monkeypatch.setattr(auth, "generate_client_certificate_request", lambda *args, **kwargs: GeneratedClientCertificateRequest("fake-csr", "c3ludGhldGljLWtleQ=="))
    monkeypatch.setattr(auth, "create_apac_bootstrap_context", lambda *args, **kwargs: context)
    response = _TransportResponse(200, {}, b'{"code":"000000","data":{"encoded":123}}')
    transport = FakeTransport(response=response)
    with pytest.raises(GwmSchemaError) as error:
        await _auth_client(transport).enroll_identity(ApacTokens("fake-access", "fake-refresh", "fake-gw", "fake-bean"))
    assert error.value.operation == "enroll_certificate"
    assert len(transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("country", ["TH", "MY", "ID", "PK"])
async def test_enrollment_checks_issued_identity_before_return(monkeypatch, country: str) -> None:
    import custom_components.gwm_ora.gwm_client.apac_auth_client as auth

    transport = FakeTransport()
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    context = ssl.create_default_context()
    client = ApacAuthClient(material=material, credentials=ApacCredentials("fake@example.invalid", "fake-password", "a" * 32, country=country), h5_context=context, transport=transport)
    identity_context = ssl.create_default_context()
    identity_context.set_ciphers("DEFAULT:@SECLEVEL=0")
    csr_countries = []
    def generate(country_code, *args, **kwargs):
        """Record the country passed into synthetic CSR generation."""
        csr_countries.append(country_code)
        return GeneratedClientCertificateRequest("fake-csr", "c3ludGhldGljLWtleQ==")
    monkeypatch.setattr(auth, "generate_client_certificate_request", generate)
    monkeypatch.setattr(auth, "create_apac_bootstrap_context", lambda material: identity_context)
    checks = []
    def validate(identity, **kwargs):
        checks.append((identity, kwargs["ca_bundle"]))
        return identity_context
    monkeypatch.setattr(auth, "create_apac_issued_context", validate)
    issued = await client.enroll_identity(ApacTokens("fake-access", "fake-refresh", "fake-gw", "fake-bean"))
    assert issued.app_ssl_context is identity_context
    assert len(checks) == 1
    assert [r.operation for r in transport.requests] == ["enroll_certificate"]
    assert "fake" not in repr(issued)
    assert csr_countries == [country]
    assert transport.requests[0].headers["country"] == country


@pytest.mark.parametrize("field", ["access_token", "refresh_token", "gw_id", "bean_id"])
@pytest.mark.parametrize("invalid", ["", "private\nvalue", "é", "x" * (16 * 1024 + 1), None])
def test_invalid_token_state_is_rejected_without_disclosing_values(field: str, invalid: object) -> None:
    """Reject incomplete or unsafe state before it can reach authentication."""
    values = dict(access_token="synthetic-access", refresh_token="synthetic-refresh", gw_id="synthetic-gw", bean_id="synthetic-bean")
    values[field] = invalid
    with pytest.raises(ValueError, match="^apac_session_invalid$"):
        ApacTokens(**values)


@pytest.mark.asyncio
async def test_invalid_verification_never_reaches_transport() -> None:
    """Reject user input before a code check or password login is transmitted."""
    transport = FakeTransport()
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    client = ApacAuthClient(material=material, credentials=ApacCredentials("fake@example.invalid", "fake-password", "a" * 32, country="PK"), h5_context=ssl.create_default_context(), transport=transport)
    for action in (client.login, client.verify_code):
        with pytest.raises(ValueError, match="^apac_verification_invalid$"):
            await action("private\ncode")
    with pytest.raises(ValueError, match="^apac_verification_invalid$"):
        await client.verify_code(None)  # type: ignore[arg-type]
    assert transport.requests == []
