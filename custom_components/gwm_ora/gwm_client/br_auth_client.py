"""BR login and the session that owns re-login.

The login host (a public web portal) is reached with a CLEAN default TLS context:
no client certificate and no lowered security level. The vehicle client identity
(mTLS, SECLEVEL=0) is used only for the vehicle gateway reads.

NOTE: this backend has no refresh endpoint (the ``refreshToken`` is only carried
as a header) and tokens last about 24 h, so renewal means a new password login.
Upstream policy forbids silent password re-login; the BR region keeps it inside
``BrSession`` so the PR can align the exact behaviour in one place.
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
    ) -> None:
        """Retain caller-owned dependencies without authenticating.

        ``login_context`` defaults to ``ssl.create_default_context()`` (system CA, no
        client certificate), created lazily in a worker thread on the first login.
        """
        if type(credentials) is not BrCredentials:
            raise ValueError("br_credentials_invalid")
        self._credentials = credentials
        self._login_context = login_context
        self._transport = transport
        self._lock = asyncio.Lock()

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
    """Current tokens plus, when allowed, the encapsulated re-login on expiry.

    Limitation: the BR backend has no refresh endpoint and tokens last about 24 h.
    With ``allow_login=False`` (the Home Assistant runtime) an expired or rejected
    session raises ``GwmAuthenticationError`` so the user is asked to reauthenticate,
    matching the repository's "no silent password login" policy. The maintainer may
    instead opt for a bounded automatic re-login by passing ``allow_login=True``.
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
        """Return valid tokens, logging in again when absent, expired or rejected.

        ``rejected`` is the snapshot a request just used and the server refused;
        concurrent callers holding the same snapshot trigger a single login.
        """
        async with self._lock:
            tokens = self._tokens
            if tokens is None or tokens is rejected or tokens.expired(self._clock()):
                if not self._allow_login:
                    raise GwmAuthenticationError(operation="login")
                tokens = await self._auth.login()
                self._tokens = tokens
            return tokens
