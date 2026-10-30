"""Explicit APAC sign-in tests without real network or vehicle requests."""

import ssl
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import custom_components.gwm_ora.gwm_client.apac_flow as flow
from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.errors import GwmApiError, GwmAuthenticationError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity


def _arguments():
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, "PK")
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    return {"credentials": credentials, "material": material, "state": None, "h5_context": ssl.create_default_context(), "transport": None}


@pytest.mark.asyncio
async def test_startup_without_state_never_logs_in_or_requests_code(monkeypatch):
    class ForbiddenAuth:
        def __init__(self, **kwargs): raise AssertionError("unexpected login")
    monkeypatch.setattr(flow, "ApacAuthClient", ForbiddenAuth)
    with pytest.raises(GwmAuthenticationError):
        await flow.authenticate_apac(**_arguments())


@pytest.mark.asyncio
async def test_challenge_requests_one_code_and_respects_cooldown(monkeypatch):
    calls = []
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def login(self, code):
            calls.append("login")
            raise GwmApiError(operation="login", api_code="308103")
        async def request_verification(self): calls.append("request_verification")
    monkeypatch.setattr(flow, "ApacAuthClient", FakeAuth)
    args = _arguments()
    result = await flow.authenticate_apac(**args, allow_password_login=True)
    assert result.code_requested is True
    args["state"] = result.state
    again = await flow.authenticate_apac(**args, allow_password_login=True)
    assert again.code_requested is False
    assert calls == ["login", "request_verification", "login"]


@pytest.mark.asyncio
async def test_explicit_login_binds_state_and_performs_read_only_discovery(monkeypatch):
    calls = []
    context = ssl.create_default_context()
    identity = EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj")
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def verify_code(self, code): calls.append("verify_code")
        async def login(self, code):
            calls.append("login")
            return ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
        async def get_user_info(self, token):
            calls.append("profile")
            return "synthetic-gw", "synthetic-bean"
        async def enroll_identity(self, tokens):
            calls.append("enroll")
            return SimpleNamespace(identity=identity, app_ssl_context=context)
    class FakeRead:
        def __init__(self, **kwargs): pass
        async def acquire_vehicles(self): calls.append("discovery")
    monkeypatch.setattr(flow, "ApacAuthClient", FakeAuth)
    monkeypatch.setattr(flow, "ApacReadClient", FakeRead)
    args = _arguments()
    result = await flow.authenticate_apac(**args, verification_code="123456", allow_password_login=True)
    assert result.state.matches(args["credentials"])
    assert result.state.verification_requested_at is None
    assert calls == ["verify_code", "login", "profile", "enroll", "discovery"]
    assert "synthetic" not in repr(result)


@pytest.mark.asyncio
async def test_wrong_account_state_is_rejected_before_network():
    args = _arguments()
    other = ApacCredentials("other@example.invalid", "synthetic-password", "a" * 32, "PK")
    args["state"] = replace(ApacAuthState.for_credentials(other), verification_requested_at=datetime.now(UTC))
    with pytest.raises(GwmAuthenticationError):
        await flow.authenticate_apac(**args, allow_password_login=True)
