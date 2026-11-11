"""BR sign-in orchestration and the read-only adapter used by the cloud runtime.

Password login only (no OTP). Reads are ``acquireVehicles`` and ``getLastStatus``;
there is no command path in this region.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field, replace

from ._protocol import _AsyncTransport
from .br_auth_client import BrAuthClient, BrSession, BrTokens
from .br_read import BrReadClient
from .br_state import BrAccountCredentials, BrAuthState
from .charging import ChargingPlanCommand
from .errors import GwmAuthenticationError
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


class BrCloudReader:
    """Read-only facade over ``BrReadClient`` shaped like the other regional readers."""

    def __init__(self, client: BrReadClient) -> None:
        """Wrap a client; nothing is sent until a read."""
        if type(client) is not BrReadClient:
            raise ValueError("br_session_invalid")
        self._client = client

    @property
    def authenticated(self) -> bool:
        """True while the session holds tokens (re-login on expiry is automatic)."""
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
    # Runtime sessions never log in by password: expiry or rejection means reauthentication.
    session = BrSession(
        BrAuthClient(credentials=credentials.to_br_credentials(), transport=transport), allow_login=False
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
) -> BrAuthenticated:
    """Restore persisted tokens lazily, or sign in once and validate with a read.

    Restoring performs no network call and no password login: an expired or missing
    session raises ``GwmAuthenticationError`` (reauthentication). An explicit login (config or reauth flow) signs in
    and reads the vehicle list so certificate and credential problems surface here.
    """
    if (
        type(credentials) is not BrAccountCredentials
        or type(allow_password_login) is not bool
        or (state is not None and (type(state) is not BrAuthState or not state.matches(credentials)))
    ):
        raise GwmAuthenticationError(operation="login")
    candidate = state or BrAuthState.for_credentials(credentials)
    if not allow_password_login:
        if candidate.tokens is None:
            raise GwmAuthenticationError(operation="login")
        # Honour "resume only": an expired saved session needs reauthentication, not a silent
        # password login (the backend has no refresh endpoint, so this recurs about daily).
        if candidate.tokens.expired(time.time()):
            raise GwmAuthenticationError(operation="login")
        return BrAuthenticated(candidate, ssl_context)

    auth = BrAuthClient(credentials=credentials.to_br_credentials(), transport=transport)
    tokens = await auth.login()
    session = BrSession(auth, allow_login=False)
    session.restore(tokens)
    await BrReadClient(session=session, ssl_context=ssl_context, transport=transport).acquire_vehicles()
    return BrAuthenticated(replace(candidate, tokens=session.tokens or tokens), ssl_context)
