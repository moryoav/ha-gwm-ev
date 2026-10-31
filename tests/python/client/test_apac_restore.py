"""Session restart tests using synthetic state and injected fakes only."""

import ssl
from dataclasses import replace

import pytest

import custom_components.gwm_ora.gwm_client.apac_restore as restore
from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState
from custom_components.gwm_ora.gwm_client.errors import GwmApiError, GwmAuthenticationError, GwmNetworkError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial, EuIssuedIdentity


def _inputs():
    """Build synthetic account-bound state for APAC session recovery."""
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, "PK")
    material = ApacMaterial(
        EuBootstrapMaterial(b"fake-cert", b"c3ludGhldGljLWtleQ==", b"fake-ca"), "fake-key", "fake-secret"
    )
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    state = replace(
        ApacAuthState.for_credentials(credentials),
        tokens=tokens,
        issued_identity=EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj"),
    )
    return credentials, material, state


@pytest.mark.asyncio
async def test_reuses_session_without_password_login_or_refresh(monkeypatch):
    """Reuse a valid saved session without password login or token rotation."""
    credentials, material, state = _inputs()
    calls = []
    context = ssl.create_default_context()
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)

    class FakeReader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            calls.append(("read", kwargs["session"].access_token))

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            return ()

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append(("profile", token))
            return "synthetic-gw", "synthetic-bean"

    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    result = await restore.restore_apac_session(
        credentials=credentials, material=material, state=state, h5_context=context, transport=None
    )
    assert result.state is state
    assert calls == [("read", "synthetic-access"), ("profile", "synthetic-access")]
    assert "synthetic" not in repr(result)


@pytest.mark.asyncio
async def test_expired_access_refreshes_once_without_password_login(monkeypatch):
    """Rotate rejected access tokens once without falling back to password login."""
    credentials, material, state = _inputs()
    calls = []
    context = ssl.create_default_context()
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)

    class FakeReader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            self.token = kwargs["session"].access_token

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append(("read", self.token))
            if self.token == "synthetic-access":
                raise GwmAuthenticationError(operation="acquire_vehicles")
            return ()

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def refresh(self, tokens):
            """Return a rotated synthetic token pair or the configured rejection."""
            calls.append(("refresh", tokens.refresh_token))
            return ApacTokens("renewed-access", "renewed-refresh", tokens.gw_id, tokens.bean_id)

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append(("profile", token))
            return "synthetic-gw", "synthetic-bean"

    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    result = await restore.restore_apac_session(
        credentials=credentials, material=material, state=state, h5_context=context, transport=None
    )
    assert result.state.tokens.access_token == "renewed-access"
    assert calls == [
        ("read", "synthetic-access"),
        ("refresh", "synthetic-refresh"),
        ("profile", "renewed-access"),
        ("read", "renewed-access"),
    ]


@pytest.mark.asyncio
async def test_other_account_and_non_auth_errors_do_not_trigger_refresh(monkeypatch):
    """Keep account mismatches and ordinary service failures out of token recovery."""
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    other = ApacCredentials("other@example.invalid", "synthetic-password", "a" * 32, "PK")
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(
            credentials=other, material=material, state=state, h5_context=context, transport=None
        )
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)

    class FakeReader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            raise GwmApiError(operation="acquire_vehicles", api_code="123456")

    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    with pytest.raises(GwmApiError):
        await restore.restore_apac_session(
            credentials=credentials, material=material, state=state, h5_context=context, transport=None
        )


@pytest.mark.asyncio
async def test_rejected_refresh_requests_reauth_without_password_fallback(monkeypatch):
    """Surface rejected refresh tokens as a request for explicit reauthentication."""
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    calls = []
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)

    class FakeReader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append("read")
            raise GwmAuthenticationError(operation="acquire_vehicles")

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def refresh(self, tokens):
            """Return a rotated synthetic token pair or the configured rejection."""
            calls.append("refresh")
            raise GwmApiError(operation="refresh_token", api_code="551011")

    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(
            credentials=credentials, material=material, state=state, h5_context=context, transport=None
        )
    assert calls == ["read", "refresh"]


@pytest.mark.asyncio
async def test_restored_server_profile_must_match_private_account_state(monkeypatch):
    """Reject a restored session when the server reports another account's identifiers."""
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    calls = []
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)

    class FakeReader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append("read")

    class FakeAuth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append("profile")
            return "different-gw", "synthetic-bean"

    monkeypatch.setattr(restore, "ApacReadClient", FakeReader)
    monkeypatch.setattr(restore, "ApacAuthClient", FakeAuth)
    with pytest.raises(GwmAuthenticationError):
        await restore.restore_apac_session(
            credentials=credentials, material=material, state=state, h5_context=context, transport=None
        )
    assert calls == ["read", "profile"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_operation", ["get_user_info", "acquire_vehicles"])
async def test_rotated_tokens_are_published_before_follow_up_reads_fail(monkeypatch, failure_operation):
    """Preserve a successful refresh even when profile or discovery is unavailable."""
    credentials, material, state = _inputs()
    context = ssl.create_default_context()
    monkeypatch.setattr(restore, "create_apac_issued_context", lambda *args, **kwargs: context)
    calls = []
    published = []

    class Reader:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            self.token = kwargs["session"].access_token

        async def acquire_vehicles(self):
            """Return synthetic discovery data or the configured authentication failure."""
            calls.append(("read", self.token))
            if self.token == "synthetic-access":
                raise GwmAuthenticationError(operation="acquire_vehicles")
            if failure_operation == "acquire_vehicles":
                raise GwmNetworkError(operation=failure_operation)
            return ()

    class Auth:
        def __init__(self, **kwargs):
            """Retain synthetic dependencies without making network requests."""
            pass

        async def refresh(self, tokens):
            """Return a rotated synthetic token pair or the configured rejection."""
            calls.append(("refresh", tokens.refresh_token))
            return ApacTokens("renewed-access", "renewed-refresh", tokens.gw_id, tokens.bean_id)

        async def get_user_info(self, token):
            """Return synthetic account identifiers or the configured profile failure."""
            calls.append(("profile", token))
            if failure_operation == "get_user_info":
                raise GwmNetworkError(operation=failure_operation)
            return "synthetic-gw", "synthetic-bean"

    async def publish(result):
        """Model the caller's private persistence boundary."""
        calls.append(("persist", result.state.tokens.refresh_token))
        published.append(result)

    monkeypatch.setattr(restore, "ApacReadClient", Reader)
    monkeypatch.setattr(restore, "ApacAuthClient", Auth)
    with pytest.raises(GwmNetworkError):
        await restore.restore_apac_session(
            credentials=credentials,
            material=material,
            state=state,
            h5_context=context,
            transport=None,
            on_session_updated=publish,
        )
    assert len(published) == 1
    assert published[0].state.tokens.refresh_token == "renewed-refresh"
    assert published[0].session.access_token == "renewed-access"
    assert calls.index(("persist", "renewed-refresh")) < calls.index(("profile", "renewed-access"))
    assert [call for call in calls if call[0] == "refresh"] == [("refresh", "synthetic-refresh")]
