"""Restore APAC read sessions without automatic password login or enrollment."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace

from ._protocol import _AsyncTransport
from .apac_auth import ApacCredentials
from .apac_auth_client import ApacAuthClient
from .apac_identity import create_apac_issued_context
from .apac_material import ApacMaterial
from .apac_read import ApacReadClient, ApacReadSession
from .apac_state import ApacAuthState
from .errors import GwmApiError, GwmAuthenticationError, is_overseas_refresh_rejected, is_overseas_session_expired


@dataclass(frozen=True, slots=True)
class ApacRestored:
    """A verified read session and its updated account-bound private state."""

    state: ApacAuthState = field(repr=False)
    session: ApacReadSession = field(repr=False)


type ApacSessionUpdated = Callable[[ApacRestored], Awaitable[None]]


async def restore_apac_session(
    *,
    credentials: ApacCredentials,
    material: ApacMaterial,
    state: ApacAuthState,
    h5_context: ssl.SSLContext,
    transport: _AsyncTransport,
    on_session_updated: ApacSessionUpdated | None = None,
    force_refresh: bool = False,
) -> ApacRestored:
    """Validate stored identity and test access, refreshing once if rejected.

    Force one refresh after a runtime authentication failure even if discovery
    would still accept the old token. Publish rotated tokens to the caller
    before subsequent network reads.
    Persistence remains caller-owned. This function never performs password
    login, requests verification codes, enrolls an identity or writes a vehicle.
    """
    if (
        type(credentials) is not ApacCredentials
        or type(material) is not ApacMaterial
        or type(state) is not ApacAuthState
        or not state.matches(credentials)
        or state.tokens is None
        or state.issued_identity is None
        or type(force_refresh) is not bool
    ):
        raise GwmAuthenticationError(operation="login")
    try:
        context = await asyncio.to_thread(
            create_apac_issued_context, state.issued_identity, ca_bundle=material.bootstrap.ca_bundle
        )
    except (TypeError, ValueError):
        raise GwmAuthenticationError(operation="login") from None

    def read_session(access_token: str) -> ApacReadSession:
        """Construct a read session from the already bound account state."""
        return ApacReadSession(
            device_id=credentials.device_id,
            access_token=access_token,
            app_ssl_context=context,
            country=credentials.country,
        )

    session = read_session(state.tokens.access_token)
    reader = ApacReadClient(material=material, session=session, transport=transport)
    auth = ApacAuthClient(material=material, credentials=credentials, h5_context=h5_context, transport=transport)
    if not force_refresh:
        try:
            await reader.acquire_vehicles()
            profile = await auth.get_user_info(state.tokens.access_token)
        except (GwmAuthenticationError, GwmApiError) as error:
            if not is_overseas_session_expired(error):
                raise
        else:
            if profile != (state.tokens.gw_id, state.tokens.bean_id):
                raise GwmAuthenticationError(operation="get_user_info")
            return ApacRestored(state, session)
    try:
        tokens = await auth.refresh(state.tokens)
    except GwmApiError as error:
        if is_overseas_refresh_rejected(error):
            raise GwmAuthenticationError(operation="refresh_token", api_code=error.api_code) from None
        raise
    session = read_session(tokens.access_token)
    restored = ApacRestored(replace(state, tokens=tokens), session)
    if on_session_updated is not None:
        await on_session_updated(restored)
    profile = await auth.get_user_info(tokens.access_token)
    if profile != (state.tokens.gw_id, state.tokens.bean_id):
        raise GwmAuthenticationError(operation="get_user_info")
    await ApacReadClient(material=material, session=session, transport=transport).acquire_vehicles()
    return restored
