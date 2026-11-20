"""BR sign-in orchestration and the read-only adapter used by the cloud runtime.

Password login with device-verification continuation. Reads are ``acquireVehicles`` and ``getLastStatus``;
there is no command path in this region.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field, replace

from ._protocol import _AsyncTransport
from .br_auth_client import BrAuthClient, BrSession, BrTokens
from .br_identity import validate_br_verification_code
from .br_read import BrReadClient
from .br_state import BrAccountCredentials, BrAuthState
from .charging import ChargingPlanCommand
from .errors import GwmApiError, GwmAuthenticationError
from .models import (
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    VehicleIdentifier,
)


@dataclass(frozen=True, slots=True)
class BrAuthenticated:
    """Private account-bound state and the validated mTLS context."""

    state: BrAuthState = field(repr=False)
    ssl_context: ssl.SSLContext = field(repr=False)


@dataclass(frozen=True, slots=True)
class BrVerificationRequired:
    """An account-bound continuation containing no submitted code."""

    state: BrAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False


class BrCloudReader:
    """Read-only facade over ``BrReadClient`` shaped like the other regional readers."""

    def __init__(self, client: BrReadClient) -> None:
        """Wrap a client; nothing is sent until a read."""
        if type(client) is not BrReadClient:
            raise ValueError("br_session_invalid")
        self._client = client

    @property
    def authenticated(self) -> bool:
        """True while the session holds tokens (an expired access token is refreshed silently)."""
        return self._client.session.tokens is not None

    @property
    def tokens(self) -> BrTokens | None:
        """Current tokens, for the caller's private storage."""
        return self._client.session.tokens

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
        """Discover account vehicles."""
        return await self._client.acquire_vehicles()

    async def get_last_status(self, identifier: VehicleIdentifier) -> CloudVehicleStatus:
        """Read the last reported status."""
        return await self._client.get_last_status(identifier)

    async def get_vehicle_basics(self, identifier: VehicleIdentifier) -> CloudVehicleBasics:
        """This region has no basics endpoint; return the empty default without I/O."""
        if type(identifier) is not VehicleIdentifier:
            raise ValueError("br_vehicle_invalid")
        return CloudVehicleBasics()

    async def set_charging_plan(self, command: ChargingPlanCommand) -> None:
        """The only write; the cloud client allows it only with the charging opt-in."""
        await self._client.set_charging_plan(command)

    async def aclose(self) -> None:
        """Close the owned transport."""
        await self._client.aclose()


def create_br_reader(
    *,
    credentials: BrAccountCredentials,
    state: BrAuthState,
    ssl_context: ssl.SSLContext,
    transport: _AsyncTransport,
) -> BrCloudReader:
    """Build the runtime reader; it owns ``transport`` and restores persisted tokens."""
    if type(credentials) is not BrAccountCredentials or type(state) is not BrAuthState or not state.matches(credentials):
        raise ValueError("br_credentials_invalid")
    # Runtime sessions never log in by password: they renew silently with the refresh token
    # and ask for reauthentication only when that refresh is refused too.
    session = BrSession(
        BrAuthClient(
            credentials=credentials.to_br_credentials(), transport=transport, refresh_context=ssl_context
        ),
        allow_login=False,
    )
    if state.tokens is not None:
        session.restore(state.tokens)
    return BrCloudReader(BrReadClient(session=session, ssl_context=ssl_context, transport=transport, owns_transport=True))


async def authenticate_br(
    *,
    credentials: BrAccountCredentials,
    state: BrAuthState | None,
    ssl_context: ssl.SSLContext,
    transport: _AsyncTransport,
    allow_password_login: bool,
    verification_code: str | None = None,
) -> BrAuthenticated | BrVerificationRequired:
    """Restore persisted tokens lazily, or sign in once and validate with a read.

    Restoring performs no network call and no password login: a missing session raises
    ``GwmAuthenticationError`` (reauthentication); an expired access token is renewed
    by the first read through the refresh token. An explicit login (config or reauth flow) signs in
    and reads the vehicle list so certificate and credential problems surface here.
    """
    if (
        type(credentials) is not BrAccountCredentials
        or type(allow_password_login) is not bool
        or (state is not None and (type(state) is not BrAuthState or not state.matches(credentials)))
        or (verification_code is not None and (
            not allow_password_login or state is None or state.verification_requested_at is None
        ))
    ):
        raise GwmAuthenticationError(operation="login")
    candidate = state or BrAuthState.for_credentials(credentials)
    try:
        validate_br_verification_code(verification_code)
    except ValueError:
        raise GwmAuthenticationError(operation="verify_code") from None
    if not allow_password_login:
        # Older builds discarded gwId. Ask for one explicit login to recover it.
        if candidate.tokens is None or candidate.tokens.gw_id is None:
            raise GwmAuthenticationError(operation="login")
        # Resume only: an expired access token is recoverable (the first read refreshes it with
        # the refresh token); a dead refresh token surfaces there as reauthentication.
        return BrAuthenticated(candidate, ssl_context)

    auth = BrAuthClient(
        credentials=credentials.to_br_credentials(), transport=transport, refresh_context=ssl_context
    )
    try:
        if verification_code is not None:
            await auth.verify_code(verification_code)
        tokens = await auth.login(verification_code)
    except GwmApiError as error:
        if error.api_code not in {"308103", "308011", "308012", "550002"}:
            raise
        if verification_code is not None:
            return BrVerificationRequired(candidate, False, True)
        if error.api_code != "308103":
            raise
        now = time.time()
        if candidate.verification_requested_at is not None and 0 <= now - candidate.verification_requested_at < 600:
            return BrVerificationRequired(candidate, False)
        await auth.request_verification()
        return BrVerificationRequired(replace(candidate, tokens=None, verification_requested_at=now), True)
    session = BrSession(auth, allow_login=False)
    session.restore(tokens)
    await BrReadClient(session=session, ssl_context=ssl_context, transport=transport).acquire_vehicles()
    return BrAuthenticated(replace(candidate, tokens=session.tokens or tokens, verification_requested_at=None), ssl_context)
