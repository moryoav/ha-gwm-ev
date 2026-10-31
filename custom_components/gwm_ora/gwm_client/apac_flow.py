"""Explicit APAC sign-in orchestration for future Home Assistant setup."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

from ._protocol import _AsyncTransport
from .apac_auth import ApacCredentials
from .apac_auth_client import ApacAuthClient
from .apac_material import ApacMaterial
from .apac_read import ApacReadClient, ApacReadSession
from .apac_restore import ApacRestored, ApacSessionUpdated, restore_apac_session
from .apac_state import ApacAuthState
from .errors import GwmApiError, GwmAuthenticationError

_CHALLENGE_CODES = frozenset({"308103", "110641"})
_VERIFICATION_INTERVAL = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class ApacAuthenticated:
    """Private account-bound state and a validated read-only session."""

    state: ApacAuthState = field(repr=False)
    session: ApacReadSession = field(repr=False)
    material: ApacMaterial = field(repr=False)


@dataclass(frozen=True, slots=True)
class ApacVerificationRequired:
    """A user-facing continuation without retaining the submitted code."""

    state: ApacAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False


async def authenticate_apac(
    *,
    credentials: ApacCredentials,
    material: ApacMaterial,
    state: ApacAuthState | None,
    h5_context: ssl.SSLContext,
    transport: _AsyncTransport,
    verification_code: str | None = None,
    allow_password_login: bool = False,
    on_session_updated: ApacSessionUpdated | None = None,
) -> ApacAuthenticated | ApacVerificationRequired:
    """Restore or explicitly sign in without hidden OTP requests or writes."""
    if (
        type(credentials) is not ApacCredentials or type(material) is not ApacMaterial
        or type(allow_password_login) is not bool
        or (state is not None and (type(state) is not ApacAuthState or not state.matches(credentials)))
        or (verification_code is not None and not allow_password_login)
    ):
        raise GwmAuthenticationError(operation="login")
    candidate = state or ApacAuthState.for_credentials(credentials)
    if candidate.tokens is not None and candidate.issued_identity is not None and verification_code is None:
        try:
            result = await restore_apac_session(
                credentials=credentials, material=material, state=candidate, h5_context=h5_context, transport=transport,
                on_session_updated=on_session_updated,
            )
            return ApacAuthenticated(result.state, result.session, material)
        except GwmAuthenticationError:
            if not allow_password_login:
                raise
    if not allow_password_login:
        raise GwmAuthenticationError(operation="login")

    auth = ApacAuthClient(material=material, credentials=credentials, h5_context=h5_context, transport=transport)
    if verification_code is not None:
        try:
            await auth.verify_code(verification_code)
        except GwmApiError as error:
            if error.api_code not in _CHALLENGE_CODES:
                raise
            return ApacVerificationRequired(replace(candidate, verification_requested_at=None), False, True)
    try:
        tokens = await auth.login(verification_code)
    except GwmApiError as error:
        if error.api_code not in _CHALLENGE_CODES:
            raise
        if verification_code is not None:
            return ApacVerificationRequired(replace(candidate, verification_requested_at=None), False, True)
        now = datetime.now(UTC)
        last = candidate.verification_requested_at
        if last is not None and timedelta(0) <= now - last < _VERIFICATION_INTERVAL:
            return ApacVerificationRequired(candidate, False)
        await auth.request_verification()
        return ApacVerificationRequired(replace(candidate, verification_requested_at=now), True)

    if await auth.get_user_info(tokens.access_token) != (tokens.gw_id, tokens.bean_id):
        raise GwmAuthenticationError(operation="get_user_info")
    issued = await auth.enroll_identity(tokens)
    session = ApacReadSession(
        device_id=credentials.device_id, access_token=tokens.access_token,
        app_ssl_context=issued.app_ssl_context, country=credentials.country,
    )
    authenticated = ApacAuthenticated(
        replace(candidate, tokens=tokens, issued_identity=issued.identity, verification_requested_at=None), session, material
    )
    if on_session_updated is not None:
        await on_session_updated(ApacRestored(authenticated.state, session))
    await ApacReadClient(material=material, session=session, transport=transport).acquire_vehicles()
    return authenticated
