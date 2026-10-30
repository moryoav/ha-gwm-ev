"""Session restart tests using synthetic state and injected fakes only."""

import ssl
from dataclasses import replace

import pytest

import custom_components.gwm_ora.gwm_client.apac_restore as restore
from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.errors import GwmApiError, GwmAuthenticationError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity


def _inputs():
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, "PK")
    material = ApacMaterial(EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret")
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(ApacAuthState.for_credentials(credentials), tokens=tokens, issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"))
    return credentials, material, state


@pytest.mark.asyncio
async def test_reuses_session_without_password_login_or_refresh(monkeypatch):
    credentials, material, state = _inputs()
    calls = []
    context = ssl.create_default_context()
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    class FakeReader:
        def __init__(self, **kwargs): calls.append(("read", kwargs["session"].access_token))
        async def acquire_vehicles(self): return ()
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def get_user_info(self, token):
            calls.append(("profile", token))
            return "synthetic-gw", "synthetic-bean"
    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    result = await restore.restore_apac_session(credentials=credentials, material=material, state=state, h5_context=context, transport=None)
    assert result.state is state
    assert calls == [("read", "synthetic-access"), ("profile", "synthetic-access")]
    assert "synthetic" not in repr(result)


@pytest.mark.asyncio
async def test_expired_access_refreshes_once_without_password_login(monkeypatch):
    credentials, material, state = _inputs()
    calls = []
    context = ssl.create_default_context()
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    class FakeReader:
        def __init__(self, **kwargs): self.token = kwargs["session"].access_token
        async def acquire_vehicles(self):
            calls.append(("read", self.token))
            if self.token == "synthetic-access":
                raise GwmAuthenticationError(operation="acquire_vehicles")
            return ()
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def refresh(self, tokens):
            calls.append(("refresh", tokens.refresh_token))
            return ApacTokens("renewed-access", "renewed-refresh", tokens.gw_id, tokens.bean_id)
        async def get_user_info(self, token):
            calls.append(("profile", token))
            return "synthetic-gw", "synthetic-bean"
    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    result = await restore.restore_apac_session(credentials=credentials, material=material, state=state, h5_context=context, transport=None)
    assert result.state.tokens.access_token == "renewed-access"
    assert calls == [("read", "synthetic-access"), ("refresh", "synthetic-refresh"), ("profile", "renewed-access"), ("read", "renewed-access")]


@pytest.mark.asyncio
async def test_other_account_and_non_auth_errors_do_not_trigger_refresh(monkeypatch):
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    other = ApacCredentials("other@example.invalid", "synthetic-password", "a" * 32, "PK")
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(credentials=other, material=material, state=state, h5_context=context, transport=None)
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    class FakeReader:
        def __init__(self, **kwargs): pass
        async def acquire_vehicles(self): raise GwmApiError(operation="acquire_vehicles", api_code="123456")
    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    with pytest.raises(GwmApiError):
        await restore.restore_apac_session(credentials=credentials, material=material, state=state, h5_context=context, transport=None)


@pytest.mark.asyncio
async def test_rejected_refresh_requests_reauth_without_password_fallback(monkeypatch):
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    calls = []
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    class FakeReader:
        def __init__(self, **kwargs): pass
        async def acquire_vehicles(self):
            calls.append("read")
            raise GwmAuthenticationError(operation="acquire_vehicles")
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def refresh(self, tokens):
            calls.append("refresh")
            raise GwmApiError(operation="refresh_token", api_code="551011")
    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(credentials=credentials, material=material, state=state, h5_context=context, transport=None)
    assert calls == ["read", "refresh"]


@pytest.mark.asyncio
async def test_restored_server_profile_must_match_private_account_state(monkeypatch):
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    calls = []
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    class FakeReader:
        def __init__(self, **kwargs): pass
        async def acquire_vehicles(self): calls.append("read")
    class FakeAuth:
        def __init__(self, **kwargs): pass
        async def get_user_info(self, token):
            calls.append("profile")
            return "different-gw", "synthetic-bean"
    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(credentials=credentials, material=material, state=state, h5_context=context, transport=None)
    assert calls == ["read", "profile"]
