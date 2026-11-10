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
from custom_components.gwm_ora.gwm_client.errors import GwmApiError, GwmAuthenticationError, GwmNetworkError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity


def _arguments():
    """Build synthetic APAC sign-in inputs without opening a network connection."""
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, "PK")
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    return {
        "credentials": credentials,
        "material": material,
        "state": None,
        "h5_context": ssl.create_default_context(),
        "transport": None,
    }


@pytest.mark.asyncio
async def test_startup_without_state_never_logs_in_or_requests_code(monkeypatch):
    """Require explicit sign-in when startup has no saved session."""
    class ForbiddenAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            raise AssertionError("unexpected login")

    monkeypatch.setattr(flow, "ApacAuthClient", ForbiddenAuth)
    with pytest.raises(GwmAuthenticationError):
        await flow.authenticate_apac(**_arguments())


@pytest.mark.asyncio
async def test_challenge_requests_one_code_and_respects_cooldown(monkeypatch):
    """Keep repeated verification challenges within the persisted request cooldown."""
    calls = []

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def login(self, code):
            """Model an explicit password login with a synthetic token or challenge."""
            calls.append("login")
            raise GwmApiError(operation="login", api_code="308103")

        async def request_verification(self):
            """Record an explicitly requested verification-code operation."""
            calls.append("request_verification")

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
    """Bind explicit sign-in and identity enrollment to the resulting read session."""
    calls = []
    context = ssl.create_default_context()
    identity = EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj")

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def verify_code(self, code):
            """Record an explicitly supplied synthetic verification code."""
            calls.append("verify_code")

        async def login(self, code):
            """Model an explicit password login with a synthetic token or challenge."""
            calls.append("login")
            return ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append("profile")
            return "synthetic-gw", "synthetic-bean"

        async def enroll_identity(self, tokens):
            """Return a synthetic issued identity and its TLS context."""
            calls.append("enroll")
            return SimpleNamespace(identity=identity, app_ssl_context=context)

    class FakeRead:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append("discovery")

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
    """Reject another account's saved state before dispatching any request."""
    args = _arguments()
    other = ApacCredentials("other@example.invalid", "synthetic-password", "a" * 32, "PK")
    args["state"] = replace(ApacAuthState.for_credentials(other), verification_requested_at=datetime.now(UTC))
    with pytest.raises(GwmAuthenticationError):
        await flow.authenticate_apac(**args, allow_password_login=True)


@pytest.mark.asyncio
async def test_discovery_failure_preserves_sign_in_for_a_login_free_retry(monkeypatch):
    """Persist verified tokens and identity before discovery, then resume them."""
    import custom_components.gwm_ora.gwm_client.apac_restore as restore

    args = _arguments()
    context = args["h5_context"]
    identity = EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj")
    calls = []
    saved = []

    class Auth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def login(self, code):
            """Model an explicit password login with a synthetic token or challenge."""
            calls.append("login")
            return ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append("profile")
            return "synthetic-gw", "synthetic-bean"

        async def enroll_identity(self, tokens):
            """Return a synthetic issued identity and its TLS context."""
            calls.append("enroll")
            return SimpleNamespace(identity=identity, app_ssl_context=context)

    class Reader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append("discovery")
            if calls.count("discovery") == 1:
                raise GwmNetworkError(operation="acquire_vehicles")
            return ()

    async def persist(result):
        """Publish a restorable session independently of discovery success."""
        saved.append(result.state)

    for module in (flow, restore):
        monkeypatch.setattr(module, "ApacAuthClient", Auth)
        monkeypatch.setattr(module, "ApacReadClient", Reader)
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *a, **k: context)
    with pytest.raises(GwmNetworkError):
        await flow.authenticate_apac(**args, allow_password_login=True, on_session_updated=persist)
    assert len(saved) == 1
    assert saved[0].tokens is not None and saved[0].issued_identity == identity
    args["state"] = saved[0]
    result = await flow.authenticate_apac(**args, allow_password_login=False)
    assert isinstance(result, flow.ApacAuthenticated)
    assert result.state == saved[0]
    assert calls == ["login", "profile", "enroll", "discovery", "discovery", "profile"]
