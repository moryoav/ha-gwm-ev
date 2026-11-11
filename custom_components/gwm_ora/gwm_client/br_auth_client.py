"""BR login and the session that owns re-login.

The login host (a public web portal) is reached with a CLEAN default TLS context:
no client certificate and no lowered security level. The vehicle client identity
(mTLS, SECLEVEL=0) is used only for the vehicle gateway reads.

Access tokens last about 24 h; the refresh token lives about 60 days and rotates.
Renewal is a ``refreshToken`` call on the h5 gateway (same mTLS context as the
vehicle reads), which needs no password. A password login happens only when
explicitly allowed (standalone tool); the Home Assistant runtime never does it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ._protocol import _AsyncTransport, _Deadline
from .br_identity import BrCredentials
from .br_request import decode_br_envelope, prepare_br_request
from .errors import GwmAuthenticationError, GwmDeadlineExceededError, GwmSchemaError

_EXPIRY_MARGIN_SECONDS = 300
_MAX_TOKEN = 16 * 1024


@dataclass(frozen=True, slots=True)
class BrTokens:
    """Private token snapshot; never log or repr."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: float | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject malformed tokens."""
        for value in (self.access_token, self.refresh_token):
            if (
                not isinstance(value, str)
                or not 0 < len(value) <= _MAX_TOKEN
                or any(not 0x21 <= ord(c) <= 0x7E for c in value)
            ):
                raise ValueError("br_session_invalid")

    def expired(self, now: float, margin: float = _EXPIRY_MARGIN_SECONDS) -> bool:
        """True when the JWT ``exp`` claim is (nearly) reached; unknown expiry counts as valid."""
        return self.expires_at is not None and now >= self.expires_at - margin


def jwt_expiry(token: str) -> float | None:
    """Read the ``exp`` claim without verifying the signature; None when absent."""
    try:
        payload = token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        exp = data.get("exp") if isinstance(data, dict) else None
        return float(exp) if isinstance(exp, int | float) and not isinstance(exp, bool) else None
    except (IndexError, ValueError, TypeError, UnicodeError):
        return None


class BrAuthClient:
    """Explicit password login over an injected transport and a clean TLS context."""

    def __init__(
        self,
        *,
        credentials: BrCredentials,
        transport: _AsyncTransport,
        login_context: ssl.SSLContext | None = None,
        refresh_context: ssl.SSLContext | None = None,
    ) -> None:
        """Retain caller-owned dependencies without authenticating.

        ``login_context`` defaults to ``ssl.create_default_context()`` (system CA, no
        client certificate), created lazily in a worker thread on the first login.
        ``refresh_context`` is the vehicle-gateway mTLS context used by the h5 refresh;
        without it ``refresh`` is unavailable.
        """
        if type(credentials) is not BrCredentials:
            raise ValueError("br_credentials_invalid")
        self._credentials = credentials
        self._login_context = login_context
        self._refresh_context = refresh_context
        self._transport = transport
        self._lock = asyncio.Lock()

    @property
    def can_refresh(self) -> bool:
        """True when a refresh TLS context was supplied."""
        return self._refresh_context is not None

    async def refresh(self, tokens: BrTokens) -> BrTokens:
        """Renew the session with the refresh token (no password). Never retried."""
        if self._refresh_context is None or type(tokens) is not BrTokens or not tokens.refresh_token:
            raise GwmAuthenticationError(operation="refresh_token")
        deadline = _Deadline(asyncio.get_running_loop().time() + 30.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at):
                request = prepare_br_request(
                    operation="refresh_token",
                    ssl_context=self._refresh_context,
                    access_token=tokens.access_token,
                    refresh_token=tokens.refresh_token,
                    device_id=self._credentials.device_id,
                )
                response = await self._transport.execute(
                    request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0
                )
                data = decode_br_envelope(response, operation="refresh_token")
        except TimeoutError:
            raise GwmDeadlineExceededError(operation="refresh_token") from None
        if not isinstance(data, dict):
            raise GwmSchemaError(operation="refresh_token")
        access, refresh = data.get("accessToken"), data.get("refreshToken")
        if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
            raise GwmSchemaError(operation="refresh_token")
        try:
            return BrTokens(access, refresh, jwt_expiry(access))
        except ValueError:
            raise GwmSchemaError(operation="refresh_token") from None

    async def login(self) -> BrTokens:
        """One password login. A rejected credential is never retried."""
        deadline = _Deadline(asyncio.get_running_loop().time() + 30.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                if self._login_context is None:
                    self._login_context = await asyncio.to_thread(ssl.create_default_context)
                request = prepare_br_request(
                    operation="login", ssl_context=self._login_context, credentials=self._credentials
                )
                response = await self._transport.execute(
                    request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0
                )
                data = decode_br_envelope(response, operation="login")
        except TimeoutError:
            raise GwmDeadlineExceededError(operation="login") from None
        if not isinstance(data, dict):
            raise GwmSchemaError(operation="login")
        access, refresh = data.get("accessToken"), data.get("refreshToken")
        if not isinstance(access, str) or not isinstance(refresh, str):
            raise GwmSchemaError(operation="login")
        try:
            return BrTokens(access, refresh, jwt_expiry(access))
        except ValueError:
            raise GwmSchemaError(operation="login") from None


class BrSession:
    """Current tokens plus their silent renewal.

    An absent, expired or rejected access token is renewed with the refresh token on
    the h5 gateway (no password). If the auth client cannot refresh, there is no
    refresh token, or the refresh is refused, the session falls back to a password
    login when ``allow_login=True`` (standalone tool) and otherwise raises
    ``GwmAuthenticationError`` so the user is asked to reauthenticate (Home
    Assistant runtime, ``allow_login=False``).
    """

    def __init__(
        self, auth: BrAuthClient, *, clock: Callable[[], float] = time.time, allow_login: bool = True
    ) -> None:
        """Start without tokens; with ``allow_login`` the first use logs in."""
        self._auth = auth
        self._clock = clock
        self._allow_login = allow_login
        self._tokens: BrTokens | None = None
        self._lock = asyncio.Lock()

    def restore(self, tokens: BrTokens) -> None:
        """Adopt persisted tokens (still validated by expiry on use)."""
        if type(tokens) is not BrTokens:
            raise ValueError("br_session_invalid")
        self._tokens = tokens

    @property
    def tokens(self) -> BrTokens | None:
        """Current tokens, for the caller's private storage."""
        return self._tokens

    async def ensure(self, *, rejected: BrTokens | None = None) -> BrTokens:
        """Return valid tokens, refreshing (or logging in) when absent, expired or rejected.

        ``rejected`` is the snapshot a request just used and the server refused;
        concurrent callers holding the same snapshot trigger a single renewal.
        """
        async with self._lock:
            tokens = self._tokens
            if tokens is None or tokens is rejected or tokens.expired(self._clock()):
                if tokens is not None and tokens.refresh_token and self._auth.can_refresh:
                    try:
                        refreshed = await self._auth.refresh(tokens)
                    except GwmAuthenticationError:
                        refreshed = None
                    if refreshed is not None:
                        self._tokens = refreshed
                        return refreshed
                if not self._allow_login:
                    raise GwmAuthenticationError(operation="login")
                tokens = await self._auth.login()
                self._tokens = tokens
            return tokens
