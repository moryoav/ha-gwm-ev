"""ANZ authentication, verification, refresh, and explicit session recovery."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import urlsplit

from ._dotnet_json import encode_dotnet_json
from ._protocol import _AsyncTransport, _Deadline, _TransportRequest, _TransportResponse
from .config import GwmClientConfig
from .errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRateLimitError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from .models import GwmSession
from .regions import GatewayRole, Region, RegionProtocol, TlsMode, get_region_protocol
from .signing import SignedRequest, SigningProfile, sign_request

_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")
_DEVICE_ID = re.compile(r"[0-9a-f]{32}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_MAX_ACCOUNT_BYTES = 4 * 1024
_MAX_PASSWORD_BYTES = 64 * 1024
_MAX_TOKEN_LENGTH = 16 * 1024
_MAX_VERIFICATION_CODE_LENGTH = 64
_MAX_JSON_DEPTH = 64
_VERIFICATION_INTERVAL = timedelta(minutes=10)
_LEGACY_VERIFICATION_REQUIRED_CODES = frozenset({"309702", "110641"})
_CURRENT_VERIFICATION_REQUIRED_CODES = frozenset({"309702", "308103", "110641"})
_CURRENT_CREDENTIAL_REJECTED_CODES = frozenset({"308001"})
_CURRENT_VERIFICATION_REJECTED_CODES = frozenset({"308011", "308012"})
# Historical, contributor-authored ANZ R&D evidence records 308011 as a wrong or
# expired verification code. No other application code is inferred as rejection.
_LEGACY_VERIFICATION_REJECTED_CODES = frozenset({"308011"})
_SESSION_CONFLICT_CODE = "607501"
_ANZ_COUNTRIES = frozenset({"AU", "NZ"})
_CALLING_CODES = MappingProxyType({"AU": "+61", "NZ": "+64"})
_CURRENT_APP_HEADERS = MappingProxyType(
    {
        "language": "en",
        "cVer": "1.0.6",
        "ip": "0.0.0.0",
        "secVersion": "2.0",
    }
)
# This persisted hash-domain value is a compatibility contract, not a vehicle-scope name.
_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-anz-account-v1\0"


class AnzAuthenticationMethod(StrEnum):
    """Supported official-app authentication protocol generations for ANZ."""

    LEGACY = "legacy_v1"
    CURRENT = "current_v2"


@dataclass(frozen=True, slots=True)
class AnzCredentials:
    """Normalized ANZ credentials and stable per-installation device identity."""

    account: str = field(repr=False)
    password: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)
    authentication_method: AnzAuthenticationMethod | str = AnzAuthenticationMethod.LEGACY

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str)
            for value in (
                self.account,
                self.password,
                self.country,
                self.device_id,
                self.authentication_method,
            )
        ):
            raise ValueError("credentials_invalid")
        account = self.account.strip()
        country = self.country.strip().upper()
        try:
            authentication_method = AnzAuthenticationMethod(self.authentication_method)
        except (TypeError, ValueError):
            raise ValueError("credentials_invalid") from None
        if authentication_method is AnzAuthenticationMethod.CURRENT:
            account = account.replace(" ", "")
        try:
            account_bytes = account.encode("utf-8", errors="strict")
            password_bytes = self.password.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ValueError("credentials_invalid") from None
        if (
            not account
            or len(account_bytes) > _MAX_ACCOUNT_BYTES
            or not self.password
            or len(password_bytes) > _MAX_PASSWORD_BYTES
            or country not in _ANZ_COUNTRIES
        ):
            raise ValueError("credentials_invalid")
        object.__setattr__(self, "account", account)
        object.__setattr__(self, "country", country)
        object.__setattr__(self, "device_id", _normalize_stable_device_id(self.device_id))
        object.__setattr__(self, "authentication_method", authentication_method)

    @property
    def account_binding(self) -> str:
        """Return a domain-separated pseudonymous binding for persisted state."""

        digest = hashlib.sha256()
        digest.update(_LEGACY_ACCOUNT_BINDING_DOMAIN)
        digest.update(self.account.encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class AnzAuthState:
    """Immutable ANZ state candidate for caller-owned persistence."""

    account_binding: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)
    authentication_method: AnzAuthenticationMethod | str = AnzAuthenticationMethod.LEGACY
    access_token: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)
    gw_id: str | None = field(default=None, repr=False)
    verification_requested_at: datetime | None = field(default=None, repr=False)
    session_reclaim_required: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        try:
            authentication_method = AnzAuthenticationMethod(self.authentication_method)
        except (TypeError, ValueError):
            raise ValueError("auth_state_invalid") from None
        if (
            not isinstance(self.account_binding, str)
            or _ACCOUNT_BINDING.fullmatch(self.account_binding) is None
            or not isinstance(self.country, str)
            or self.country not in _ANZ_COUNTRIES
            or not isinstance(self.device_id, str)
            or _DEVICE_ID.fullmatch(self.device_id) is None
            or type(self.session_reclaim_required) is not bool
        ):
            raise ValueError("auth_state_invalid")
        object.__setattr__(self, "authentication_method", authentication_method)
        _validate_optional_token(self.access_token)
        _validate_optional_token(self.refresh_token)
        _validate_optional_token(self.gw_id)
        if self.access_token is None and self.gw_id is not None:
            raise ValueError("auth_state_invalid")
        requested_at = self.verification_requested_at
        if requested_at is not None and (
            not isinstance(requested_at, datetime) or requested_at.tzinfo is None or requested_at.utcoffset() is None
        ):
            raise ValueError("auth_state_invalid")
        if self.session_reclaim_required and (self.access_token is not None or self.refresh_token is not None):
            raise ValueError("auth_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: AnzCredentials) -> AnzAuthState:
        """Create empty state bound to exactly one ANZ account and installation."""

        if type(credentials) is not AnzCredentials:
            raise ValueError("credentials_invalid")
        return cls(
            account_binding=credentials.account_binding,
            country=credentials.country,
            device_id=credentials.device_id,
            authentication_method=credentials.authentication_method,
        )

    def matches(self, credentials: AnzCredentials) -> bool:
        """Return whether this state can safely be reused for the credentials."""

        return type(credentials) is AnzCredentials and (
            self.account_binding == credentials.account_binding
            and self.country == credentials.country
            and self.device_id == credentials.device_id
            and self.authentication_method is credentials.authentication_method
        )


@dataclass(frozen=True, slots=True)
class AnzAuthenticated:
    """A validated ANZ state and ordinary-TLS read session."""

    state: AnzAuthState = field(repr=False)
    session: GwmSession = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.state) is not AnzAuthState or type(self.session) is not GwmSession:
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class AnzVerificationRequired:
    """A continuation outcome that never retains the submitted code or password."""

    state: AnzAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.state) is not AnzAuthState
            or type(self.code_requested) is not bool
            or type(self.code_rejected) is not bool
            or (self.code_requested and self.code_rejected)
        ):
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class AnzSessionReclaimRequired:
    """Explicit permission is required before a login may claim the single session."""

    state: AnzAuthState = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.state) is not AnzAuthState or not self.state.session_reclaim_required:
            raise ValueError("authentication_result_invalid")


type AnzAuthenticationResult = AnzAuthenticated | AnzVerificationRequired | AnzSessionReclaimRequired


@dataclass(slots=True)
class _AnzAuthProgress:
    """Internal attempt state used to retire only a definitively rejected session."""

    existing_session_rejected: bool = False


@dataclass(frozen=True, slots=True)
class _AuthEndpoint:
    operation: str
    role: GatewayRole
    path: str
    method: str
    access_token: bool
    require_data: bool


_LEGACY_LOGIN = _AuthEndpoint("login", GatewayRole.H5_V1, "userAuth/loginAccount", "POST", False, True)
_LEGACY_REQUEST_VERIFICATION = _AuthEndpoint(
    "request_verification",
    GatewayRole.H5_V1,
    "userAuth/getSMSCode",
    "POST",
    False,
    False,
)
_LEGACY_VERIFY_CODE = _AuthEndpoint(
    "verify_code",
    GatewayRole.H5_V1,
    "userAuth/checkSMSCode",
    "POST",
    False,
    False,
)
_CURRENT_LOGIN = _AuthEndpoint(
    "login",
    GatewayRole.AUTH_V2,
    "userAuth/loginWithPassword",
    "POST",
    False,
    True,
)
_CURRENT_REQUEST_VERIFICATION = _AuthEndpoint(
    "request_verification",
    GatewayRole.AUTH_V2,
    "userAuth/getVerifyCode",
    "POST",
    False,
    False,
)
_CURRENT_VERIFY_CODE = _AuthEndpoint(
    "verify_code",
    GatewayRole.AUTH_V2,
    "userAuth/checkVerifyCode",
    "POST",
    False,
    False,
)
_REFRESH = _AuthEndpoint(
    "refresh_token",
    GatewayRole.H5_V1,
    "userAuth/refreshToken",
    "POST",
    True,
    True,
)
_USER_INFO = _AuthEndpoint(
    "get_user_info",
    GatewayRole.H5_V1,
    "user/getUserBaseInfo",
    "GET",
    True,
    False,
)

# Retain the historical private aliases used by the v1 contract tests.
_LOGIN = _LEGACY_LOGIN
_REQUEST_VERIFICATION = _LEGACY_REQUEST_VERIFICATION
_VERIFY_CODE = _LEGACY_VERIFY_CODE

_AUTH_ENDPOINTS = MappingProxyType(
    {
        AnzAuthenticationMethod.LEGACY: MappingProxyType(
            {
                endpoint.operation: endpoint
                for endpoint in (
                    _LEGACY_LOGIN,
                    _LEGACY_REQUEST_VERIFICATION,
                    _LEGACY_VERIFY_CODE,
                    _REFRESH,
                    _USER_INFO,
                )
            }
        ),
        AnzAuthenticationMethod.CURRENT: MappingProxyType(
            {
                endpoint.operation: endpoint
                for endpoint in (
                    _CURRENT_LOGIN,
                    _CURRENT_REQUEST_VERIFICATION,
                    _CURRENT_VERIFY_CODE,
                )
            }
        ),
    }
)


async def authenticate_anz(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: AnzCredentials,
    state: AnzAuthState | None,
    verification_code: str | None,
    allow_session_reclaim: bool,
    deadline: _Deadline,
    progress: _AnzAuthProgress,
) -> AnzAuthenticationResult:
    """Run one serialized finite ANZ authentication continuation."""

    if (
        type(config) is not GwmClientConfig
        or config.region is not Region.ANZ
        or type(credentials) is not AnzCredentials
        or (state is not None and type(state) is not AnzAuthState)
        or type(allow_session_reclaim) is not bool
        or type(deadline) is not _Deadline
        or type(progress) is not _AnzAuthProgress
    ):
        raise GwmConfigurationError(operation="login")
    authentication_method = credentials.authentication_method
    if (
        not isinstance(authentication_method, AnzAuthenticationMethod)
        or config.anz_authentication_method != authentication_method.value
    ):
        raise GwmConfigurationError(operation="login")
    candidate = state if state is not None and state.matches(credentials) else AnzAuthState.for_credentials(credentials)
    endpoints = _auth_endpoints(credentials)
    login_endpoint = endpoints["login"]
    request_verification_endpoint = endpoints["request_verification"]
    verify_code_endpoint = endpoints["verify_code"]
    code = _normalize_verification_code(verification_code)
    _ensure_deadline(deadline, operation="login")
    reclaim_attempt = candidate.session_reclaim_required
    if not reclaim_attempt and candidate.access_token is None:
        candidate = _session_reclaim_state(candidate)
        reclaim_attempt = True
    if reclaim_attempt and not allow_session_reclaim:
        return AnzSessionReclaimRequired(state=candidate)
    try:
        default_context = await _blocking_call(_create_default_ssl_context)
    except (OSError, ssl.SSLError, ValueError):
        raise GwmConfigurationError(operation="login") from None
    _ensure_deadline(deadline, operation="login")

    # The current ANZ app installs the access token and gwId from the successful
    # login response directly. It does not validate a fresh or restored session
    # through the legacy v1 profile route.
    if authentication_method is AnzAuthenticationMethod.CURRENT and not reclaim_attempt:
        if candidate.access_token is not None and candidate.gw_id is not None:
            return _authenticated_result(candidate, default_context)
        candidate = _session_reclaim_state(candidate)
        if not allow_session_reclaim:
            return AnzSessionReclaimRequired(state=candidate)
        reclaim_attempt = True

    access_rejected = False
    if not reclaim_attempt and candidate.access_token is not None:
        try:
            profile = await _request_data(
                config=config,
                transport=transport,
                endpoint=_USER_INFO,
                credentials=credentials,
                body=None,
                access_token=candidate.access_token,
                ssl_context=default_context,
                deadline=deadline,
                gw_id=candidate.gw_id,
            )
        except GwmAuthenticationError:
            access_rejected = True
            progress.existing_session_rejected = True
        except GwmApiError as error:
            if not _is_session_conflict(error):
                raise
            progress.existing_session_rejected = True
            candidate = _session_reclaim_state(candidate)
            if not allow_session_reclaim:
                return AnzSessionReclaimRequired(state=candidate)
            reclaim_attempt = True
        else:
            candidate = replace(
                candidate,
                gw_id=_updated_gw_id(
                    profile,
                    current=candidate.gw_id,
                    operation="get_user_info",
                    authentication_method=authentication_method,
                ),
            )
            return _authenticated_result(candidate, default_context)

    if not reclaim_attempt and candidate.access_token is not None and candidate.refresh_token is not None:
        try:
            refreshed = await _request_data(
                config=config,
                transport=transport,
                endpoint=_REFRESH,
                credentials=credentials,
                body=_refresh_body(credentials, candidate),
                access_token=candidate.access_token,
                ssl_context=default_context,
                deadline=deadline,
                gw_id=candidate.gw_id,
            )
        except GwmAuthenticationError:
            candidate = replace(
                candidate,
                access_token=None,
                refresh_token=None,
                gw_id=None,
            )
        except GwmApiError as error:
            if not _is_session_conflict(error):
                raise
            progress.existing_session_rejected = True
            candidate = _session_reclaim_state(candidate)
            if not allow_session_reclaim:
                return AnzSessionReclaimRequired(state=candidate)
            reclaim_attempt = True
        else:
            access_token, refresh_token = _parse_token_pair(refreshed, operation="refresh_token")
            gw_id = _updated_gw_id(
                refreshed,
                current=candidate.gw_id,
                operation="refresh_token",
                authentication_method=authentication_method,
            )
            try:
                profile = await _request_data(
                    config=config,
                    transport=transport,
                    endpoint=_USER_INFO,
                    credentials=credentials,
                    body=None,
                    access_token=access_token,
                    ssl_context=default_context,
                    deadline=deadline,
                    gw_id=gw_id,
                )
            except GwmAuthenticationError:
                progress.existing_session_rejected = True
                candidate = replace(
                    candidate,
                    access_token=None,
                    refresh_token=None,
                    gw_id=None,
                )
            except GwmApiError as error:
                if not _is_session_conflict(error):
                    raise
                progress.existing_session_rejected = True
                candidate = _session_reclaim_state(candidate)
                if not allow_session_reclaim:
                    return AnzSessionReclaimRequired(state=candidate)
                reclaim_attempt = True
            else:
                candidate = replace(
                    candidate,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    gw_id=_updated_gw_id(
                        profile,
                        current=gw_id,
                        operation="get_user_info",
                        authentication_method=authentication_method,
                    ),
                    verification_requested_at=None,
                )
                return _authenticated_result(candidate, default_context)
    elif not reclaim_attempt and (access_rejected or candidate.access_token is None):
        candidate = replace(
            candidate,
            access_token=None,
            refresh_token=None,
            gw_id=None,
        )

    if not candidate.session_reclaim_required:
        candidate = _session_reclaim_state(candidate)
    if not allow_session_reclaim:
        return AnzSessionReclaimRequired(state=candidate)

    if code is not None:
        try:
            await _request_data(
                config=config,
                transport=transport,
                endpoint=verify_code_endpoint,
                credentials=credentials,
                body=_verification_check_body(credentials, code),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmRateLimitError:
            raise
        except GwmApiError as error:
            if not _is_verification_rejection(error, credentials):
                raise
            return AnzVerificationRequired(
                state=replace(candidate, verification_requested_at=None),
                code_requested=False,
                code_rejected=True,
            )
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=login_endpoint,
                credentials=credentials,
                body=_login_body(credentials, verification_code=code),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmApiError as error:
            if _is_verification_rejection(error, credentials):
                return AnzVerificationRequired(
                    state=replace(candidate, verification_requested_at=None),
                    code_requested=False,
                    code_rejected=True,
                )
            if _is_credential_rejection(error, credentials):
                raise GwmAuthenticationError(
                    operation=login_endpoint.operation,
                    api_code=error.api_code,
                ) from None
            raise
    else:
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=login_endpoint,
                credentials=credentials,
                body=_login_body(credentials, verification_code=None),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmApiError as error:
            if _is_credential_rejection(error, credentials):
                raise GwmAuthenticationError(
                    operation=login_endpoint.operation,
                    api_code=error.api_code,
                ) from None
            if not _is_verification_challenge(error, credentials):
                raise
            now = _utc_now()
            requested_at = candidate.verification_requested_at
            throttled = requested_at is not None and timedelta(0) <= now - requested_at < _VERIFICATION_INTERVAL
            if throttled:
                return AnzVerificationRequired(state=candidate, code_requested=False)
            await _request_data(
                config=config,
                transport=transport,
                endpoint=request_verification_endpoint,
                credentials=credentials,
                body=_verification_request_body(credentials),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
            return AnzVerificationRequired(
                state=replace(candidate, verification_requested_at=now),
                code_requested=True,
            )

    login_access_token, login_refresh_token = _parse_login_tokens(
        login,
        operation="login",
        authentication_method=authentication_method,
    )
    gw_id = _updated_gw_id(
        login,
        current=None,
        operation="login",
        authentication_method=authentication_method,
    )
    if authentication_method is AnzAuthenticationMethod.CURRENT:
        candidate = replace(
            candidate,
            access_token=login_access_token,
            refresh_token=login_refresh_token,
            gw_id=gw_id,
            verification_requested_at=None,
            session_reclaim_required=False,
        )
        return _authenticated_result(candidate, default_context)
    try:
        profile = await _request_data(
            config=config,
            transport=transport,
            endpoint=_USER_INFO,
            credentials=credentials,
            body=None,
            access_token=login_access_token,
            ssl_context=default_context,
            deadline=deadline,
            gw_id=gw_id,
        )
    except GwmAuthenticationError:
        progress.existing_session_rejected = True
        raise
    except GwmApiError as error:
        if not _is_session_conflict(error):
            raise
        progress.existing_session_rejected = True
        return AnzSessionReclaimRequired(state=_session_reclaim_state(candidate))
    candidate = replace(
        candidate,
        access_token=login_access_token,
        refresh_token=login_refresh_token,
        gw_id=_updated_gw_id(
            profile,
            current=gw_id,
            operation="get_user_info",
            authentication_method=authentication_method,
        ),
        verification_requested_at=None,
        session_reclaim_required=False,
    )
    return _authenticated_result(candidate, default_context)


def _authenticated_result(state: AnzAuthState, context: ssl.SSLContext) -> AnzAuthenticated:
    if (
        state.access_token is None
        or state.session_reclaim_required
        or (state.authentication_method is AnzAuthenticationMethod.CURRENT and state.gw_id is None)
    ):
        raise GwmSchemaError(operation="login")
    return AnzAuthenticated(
        state=state,
        session=GwmSession(
            country=state.country,
            device_id=state.device_id,
            access_token=state.access_token,
            app_ssl_context=context,
            gw_id=state.gw_id,
        ),
    )


async def _request_data(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    endpoint: _AuthEndpoint,
    credentials: AnzCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
    deadline: _Deadline,
    gw_id: str | None = None,
) -> object:
    request = _prepare_request(
        endpoint=endpoint,
        credentials=credentials,
        body=body,
        access_token=access_token,
        ssl_context=ssl_context,
        gw_id=gw_id,
    )
    failure: GwmClientError | None = None
    try:
        response = await transport.execute(
            request,
            deadline=deadline,
            connect_timeout=config.timeouts.connect,
            read_timeout=config.timeouts.read,
        )
        if type(response) is not _TransportResponse:
            raise GwmProtocolError(operation=endpoint.operation)
        _ensure_deadline(deadline, operation=endpoint.operation)
        try:
            result = _decode_auth_envelope(
                response,
                operation=endpoint.operation,
                require_data=endpoint.require_data,
            )
        except Exception:
            _ensure_deadline(deadline, operation=endpoint.operation)
            raise
        _ensure_deadline(deadline, operation=endpoint.operation)
        return result
    except asyncio.CancelledError:
        raise
    except GwmClientError as error:
        failure = _sanitized_error(error, operation=endpoint.operation)
    except Exception:
        failure = GwmNetworkError(operation=endpoint.operation)
    if failure is not None:
        raise failure
    raise GwmNetworkError(operation=endpoint.operation)


def _prepare_request(
    *,
    endpoint: _AuthEndpoint,
    credentials: AnzCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
    gw_id: str | None = None,
) -> _TransportRequest:
    if _auth_endpoints(credentials).get(endpoint.operation) is not endpoint:
        raise GwmRoutePolicyError(operation=endpoint.operation)
    protocol = get_region_protocol(Region.ANZ)
    gateway = protocol.gateway(endpoint.role)
    body_text: str | None
    if endpoint.method == "GET":
        if body is not None:
            raise GwmRoutePolicyError(operation=endpoint.operation)
        body_text = None
    elif endpoint.method == "POST" and type(body) is dict:
        try:
            body_text = (
                _encode_current_app_json(body)
                if credentials.authentication_method is AnzAuthenticationMethod.CURRENT
                else encode_dotnet_json(body)
            )
        except (TypeError, ValueError):
            raise GwmRoutePolicyError(operation=endpoint.operation) from None
    else:
        raise GwmRoutePolicyError(operation=endpoint.operation)
    if endpoint.access_token != (access_token is not None):
        raise GwmRoutePolicyError(operation=endpoint.operation)

    unsigned_url = gateway.base_url + endpoint.path
    try:
        if credentials.authentication_method is AnzAuthenticationMethod.CURRENT:
            signed = _sign_current_app_request(
                gateway.signing_profile,
                endpoint.method,
                unsigned_url,
                body_text,
            )
        else:
            signed = sign_request(gateway.signing_profile, endpoint.method, unsigned_url, body_text)
        _validate_signed_auth_request(
            signed,
            endpoint=endpoint,
            expected_body=body_text,
            credentials=credentials,
        )
        if credentials.authentication_method is AnzAuthenticationMethod.CURRENT:
            headers = _current_app_headers(
                protocol,
                country=credentials.country,
                device_id=credentials.device_id,
                access_token=access_token,
                gw_id=gw_id,
            )
        else:
            device_id = protocol.normalize_device_id(credentials.device_id)
            headers = {
                **protocol.base_headers,
                "country": credentials.country,
                "regionCode": credentials.country,
                "deviceId": device_id,
                "iccid": device_id,
            }
            if access_token is not None:
                _validate_token(access_token)
                headers["accessToken"] = access_token
        if endpoint.method == "POST":
            headers["Content-Type"] = (
                "application/json"
                if credentials.authentication_method is AnzAuthenticationMethod.CURRENT
                else "application/json; charset=utf-8"
            )
        headers.update(signed.headers)
        _validate_gateway_tls(endpoint, credentials, ssl_context)
        return _TransportRequest(
            operation=endpoint.operation,
            method=endpoint.method,
            url=signed.url,
            headers=headers,
            ssl_context=ssl_context,
            body=None if body_text is None else body_text.encode("utf-8"),
        )
    except GwmClientError:
        raise
    except (TypeError, ValueError):
        raise GwmRoutePolicyError(operation=endpoint.operation) from None


def _encode_current_app_json(value: object) -> str:
    """Match the compact Dart JSON used by the current GWM ANZ app."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _new_current_app_nonce() -> str:
    """Return the current app's lowercase 32-character nonce shape."""

    nonce_input = str(time.time_ns() // 1_000_000)
    return hashlib.sha256(nonce_input.encode()).hexdigest()[:32]


def _sign_current_app_request(
    profile: SigningProfile,
    method: str,
    url: str,
    body: str | None,
) -> SignedRequest:
    """Sign one request with the current GWM ANZ app's wire policy."""

    timestamp = str(time.time_ns() // 1_000_000)
    return sign_request(
        profile,
        method,
        url,
        body,
        timestamp=timestamp,
        nonce=_new_current_app_nonce(),
        uri_component_safe="-._~!*'()",
        whitespace_policy="preserve",
        request_target_policy="absolute-url",
        query_policy="dart-current",
    )


def _current_app_headers(
    protocol: RegionProtocol,
    *,
    country: str,
    device_id: str,
    access_token: str | None,
    gw_id: str | None = None,
) -> dict[str, str]:
    """Build the current app's full-device-ID ANZ headers."""

    if type(protocol) is not RegionProtocol or protocol.region is not Region.ANZ:
        raise ValueError("route_invalid")
    protocol.validate_country(country)
    protocol.normalize_device_id(device_id)
    if access_token is not None:
        _validate_token(access_token)
    if gw_id is not None:
        _validate_token(gw_id)
    if (access_token is None) != (gw_id is None):
        raise ValueError("route_invalid")
    return {
        **protocol.base_headers,
        **_CURRENT_APP_HEADERS,
        "country": country,
        "regionCode": country,
        "deviceId": device_id,
        "iccid": device_id,
        **({"accessToken": access_token, "gwId": gw_id} if access_token is not None and gw_id is not None else {}),
    }


def _validate_signed_auth_request(
    signed: SignedRequest,
    *,
    endpoint: _AuthEndpoint,
    expected_body: str | None,
    credentials: AnzCredentials,
) -> None:
    if type(signed) is not SignedRequest:
        raise ValueError("route_invalid")
    protocol = get_region_protocol(Region.ANZ)
    gateway = protocol.gateway(endpoint.role)
    parsed = urlsplit(signed.url)
    expected = urlsplit(gateway.base_url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("route_invalid") from None
    if (
        signed.body != expected_body
        or signed.method != endpoint.method
        or parsed.scheme != "https"
        or parsed.hostname != expected.hostname
        or parsed.path != expected.path + endpoint.path
        or parsed.query
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("route_invalid")
    _validate_signing_headers(
        signed,
        gateway.signing_profile,
        nonce_length=(32 if credentials.authentication_method is AnzAuthenticationMethod.CURRENT else 16),
    )


def _validate_signing_headers(
    signed: SignedRequest,
    profile: SigningProfile,
    *,
    nonce_length: int,
) -> None:
    prefix = profile.prefix
    expected = {
        f"{prefix}-auth-appkey",
        f"{prefix}-auth-nonce",
        f"{prefix}-auth-timestamp",
        f"{prefix}-auth-sign",
    }
    if set(signed.headers) != expected:
        raise ValueError("route_invalid")
    nonce = signed.headers[f"{prefix}-auth-nonce"]
    timestamp = signed.headers[f"{prefix}-auth-timestamp"]
    signature = signed.headers[f"{prefix}-auth-sign"]
    if (
        signed.headers[f"{prefix}-auth-appkey"] != profile.app_key
        or re.fullmatch(rf"[0-9A-Fa-f]{{{nonce_length}}}", nonce) is None
        or (profile.uppercase_nonce and nonce != nonce.upper())
        or (not profile.uppercase_nonce and nonce != nonce.lower())
        or not 10 <= len(timestamp) <= 17
        or not timestamp.isdecimal()
        or _SIGNATURE.fullmatch(signature) is None
    ):
        raise ValueError("route_invalid")


def _validate_gateway_tls(
    endpoint: _AuthEndpoint,
    credentials: AnzCredentials,
    context: object,
) -> None:
    if (
        not isinstance(context, ssl.SSLContext)
        or not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.minimum_version < ssl.TLSVersion.TLSv1_2
        or (
            context.maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
            and (context.maximum_version < ssl.TLSVersion.TLSv1_2 or context.maximum_version < context.minimum_version)
        )
        or context.security_level <= 0
        or get_region_protocol(Region.ANZ).gateway(endpoint.role).tls_mode is not TlsMode.DEFAULT
    ):
        raise ValueError("tls_context_invalid")
    if _auth_endpoints(credentials).get(endpoint.operation) is not endpoint:
        raise ValueError("route_invalid")


def _decode_auth_envelope(
    response: _TransportResponse,
    *,
    operation: str,
    require_data: bool,
) -> object:
    envelope: object = None
    valid_json = False
    try:
        text = response.body.decode("utf-8", errors="strict")
        envelope = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        _validate_json_depth(envelope)
        valid_json = isinstance(envelope, Mapping)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        pass

    code = envelope.get("code") if isinstance(envelope, Mapping) else None
    safe_code = _exact_api_code(code)
    if response.status in {401, 403}:
        if code == _SESSION_CONFLICT_CODE:
            raise GwmApiError(operation=operation, api_code=code)
        raise GwmAuthenticationError(operation=operation, api_code=safe_code)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry_seconds = int(retry_after) if retry_after and len(retry_after) <= 10 and retry_after.isdecimal() else None
        raise GwmRateLimitError(
            operation=operation,
            api_code=safe_code,
            retry_after_seconds=retry_seconds,
        )
    if not 200 <= response.status <= 299:
        raise GwmHttpError(operation=operation, status=response.status)
    if valid_json:
        assert isinstance(envelope, Mapping)
        if code != "000000":
            raise GwmApiError(operation=operation, api_code=safe_code)
    if not valid_json:
        raise GwmSchemaError(operation=operation)
    assert isinstance(envelope, Mapping)
    if require_data:
        if "data" not in envelope:
            raise GwmSchemaError(operation=operation)
        return envelope["data"]
    return envelope.get("data")


def _login_body(
    credentials: AnzCredentials,
    *,
    verification_code: str | None,
) -> dict[str, object]:
    if credentials.authentication_method is AnzAuthenticationMethod.CURRENT:
        current_body: dict[str, object] = {
            "account": credentials.account,
            "accountType": _current_account_type(credentials.account),
            "countryCode": _CALLING_CODES[credentials.country],
            "agreement": [1, 2],
            "password": credentials.password,
            "deviceId": credentials.device_id,
            "appType": "0",
            "pushToken": None,
            "country": credentials.country,
        }
        if verification_code is not None:
            current_body["verifyCode"] = verification_code
            current_body["validCodeMode"] = "1"
        return current_body

    body: dict[str, object] = {
        "account": credentials.account,
        "password": credentials.password,
        "agreement": [1, 2],
        "deviceId": credentials.device_id[:16],
        "appType": "0",
        "country": credentials.country,
        "accountId": None,
        "uid": None,
        "smsCode": None,
        "pushToken": "",
        "loginEmail": None,
    }
    if verification_code is not None:
        body["verifyCode"] = verification_code
    return body


def _verification_request_body(credentials: AnzCredentials) -> dict[str, object]:
    if credentials.authentication_method is AnzAuthenticationMethod.CURRENT:
        return {
            "type": "17",
            "account": credentials.account,
            "accountType": _current_account_type(credentials.account),
            "countryCode": _CALLING_CODES[credentials.country],
            "validCodeMode": 1,
            "operateCode": "",
            "captchaType": "",
            "captchaId": "",
            "token": "",
        }
    return {
        "type": "17",
        "email": credentials.account,
        "accountId": None,
        "uid": None,
    }


def _verification_check_body(credentials: AnzCredentials, code: str) -> dict[str, object]:
    if credentials.authentication_method is AnzAuthenticationMethod.CURRENT:
        return {
            "account": credentials.account,
            "verifyCode": code,
            "type": "17",
            "accountType": _current_account_type(credentials.account),
            "countryCode": _CALLING_CODES[credentials.country],
            "validCodeMode": 1,
        }
    return {
        "email": credentials.account,
        "smsCode": code,
        "type": "17",
    }


def _refresh_body(credentials: AnzCredentials, state: AnzAuthState) -> dict[str, object]:
    if state.access_token is None or state.refresh_token is None:
        raise GwmConfigurationError(operation="refresh_token")
    return {
        "accessToken": state.access_token,
        "refreshToken": state.refresh_token,
        "deviceId": (
            credentials.device_id
            if credentials.authentication_method is AnzAuthenticationMethod.CURRENT
            else credentials.device_id[:16]
        ),
    }


def _current_account_type(account: str) -> str:
    """Select the current app's email or phone account type from the identifier."""

    return "2" if "@" in account else "1"


def _parse_token_pair(data: object, *, operation: str) -> tuple[str, str]:
    access = _required_text(data, "accessToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    refresh = _required_text(data, "refreshToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    _validate_token(access)
    _validate_token(refresh)
    return access, refresh


def _parse_login_tokens(
    data: object,
    *,
    operation: str,
    authentication_method: AnzAuthenticationMethod,
) -> tuple[str, str | None]:
    """Parse login tokens without inventing a current-app refresh requirement."""

    if authentication_method is AnzAuthenticationMethod.LEGACY:
        return _parse_token_pair(data, operation=operation)
    access = _required_text(data, "accessToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    assert isinstance(data, Mapping)
    refresh = (
        None
        if data.get("refreshToken") is None
        else _required_text(data, "refreshToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    )
    return access, refresh


def _updated_gw_id(
    data: object,
    *,
    current: str | None,
    operation: str,
    authentication_method: AnzAuthenticationMethod,
) -> str | None:
    if authentication_method is AnzAuthenticationMethod.LEGACY:
        return current
    if not isinstance(data, Mapping):
        return current
    value = data.get("gwId")
    if value is None:
        return current
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TOKEN_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise GwmSchemaError(operation=operation)
    return value


def _required_text(data: object, key: str, *, operation: str, maximum: int) -> str:
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation=operation)
    value = data.get(key)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise GwmSchemaError(operation=operation)
    return value


def _exact_api_code(value: object) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    return value


def _normalize_verification_code(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise GwmConfigurationError(operation="verify_code")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > _MAX_VERIFICATION_CODE_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in normalized)
    ):
        raise GwmConfigurationError(operation="verify_code")
    return normalized


def _auth_endpoints(credentials: AnzCredentials) -> Mapping[str, _AuthEndpoint]:
    if type(credentials) is not AnzCredentials:
        raise GwmRoutePolicyError(operation="login")
    method = credentials.authentication_method
    if not isinstance(method, AnzAuthenticationMethod):
        raise GwmRoutePolicyError(operation="login")
    return _AUTH_ENDPOINTS[method]


def _verification_required_codes(credentials: AnzCredentials) -> frozenset[str]:
    return (
        _CURRENT_VERIFICATION_REQUIRED_CODES
        if credentials.authentication_method is AnzAuthenticationMethod.CURRENT
        else _LEGACY_VERIFICATION_REQUIRED_CODES
    )


def _is_verification_challenge(
    error: GwmApiError,
    credentials: AnzCredentials,
) -> bool:
    return type(error) is GwmApiError and error.api_code in _verification_required_codes(credentials)


def _is_credential_rejection(
    error: GwmApiError,
    credentials: AnzCredentials,
) -> bool:
    return (
        credentials.authentication_method is AnzAuthenticationMethod.CURRENT
        and type(error) is GwmApiError
        and error.api_code in _CURRENT_CREDENTIAL_REJECTED_CODES
    )


def _is_verification_rejection(
    error: GwmApiError,
    credentials: AnzCredentials,
) -> bool:
    rejected_codes = (
        _CURRENT_VERIFICATION_REJECTED_CODES
        if credentials.authentication_method is AnzAuthenticationMethod.CURRENT
        else _LEGACY_VERIFICATION_REJECTED_CODES
    )
    return type(error) is GwmApiError and (
        error.api_code in rejected_codes or error.api_code in _verification_required_codes(credentials)
    )


def _is_session_conflict(error: GwmApiError) -> bool:
    return type(error) is GwmApiError and error.api_code == _SESSION_CONFLICT_CODE


def _session_reclaim_state(state: AnzAuthState) -> AnzAuthState:
    return replace(
        state,
        access_token=None,
        refresh_token=None,
        gw_id=None,
        session_reclaim_required=True,
    )


def _normalize_stable_device_id(value: str) -> str:
    normalized = value.replace("-", "")
    if not normalized or len(value) > 64 or re.fullmatch(r"[0-9A-Fa-f]+", normalized) is None:
        raise ValueError("credentials_invalid")
    return normalized[:32].ljust(32, "0").lower()


def _validate_optional_token(value: str | None) -> None:
    if value is not None:
        _validate_token(value)


def _validate_token(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TOKEN_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError("token_invalid")


def _create_default_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED or context.security_level <= 0:
        raise ValueError("tls_context_invalid")
    return context


async def _blocking_call[T](function: Callable[[], T]) -> T:
    task = asyncio.create_task(asyncio.to_thread(function))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as cancelled:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if task.done() and not task.cancelled():
            with contextlib.suppress(BaseException):
                task.result()
        raise cancelled


def _ensure_deadline(deadline: _Deadline, *, operation: str) -> None:
    loop = asyncio.get_running_loop()
    if deadline.remaining(loop.time()) <= 0:
        raise GwmDeadlineExceededError(operation=operation)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("invalid_json_number")


def _validate_json_depth(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("json_too_deep")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("invalid_json_number")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth=depth + 1)


def _sanitized_error(error: GwmClientError, *, operation: str) -> GwmClientError:
    if type(error) is GwmHttpError:
        assert isinstance(error, GwmHttpError)
        return GwmHttpError(operation=operation, status=error.status)
    if type(error) is GwmRateLimitError:
        assert isinstance(error, GwmRateLimitError)
        return GwmRateLimitError(
            operation=operation,
            api_code=error.api_code,
            retry_after_seconds=error.retry_after_seconds,
        )
    if type(error) is GwmAuthenticationError:
        assert isinstance(error, GwmAuthenticationError)
        return GwmAuthenticationError(operation=operation, api_code=error.api_code)
    if type(error) is GwmApiError:
        assert isinstance(error, GwmApiError)
        return GwmApiError(operation=operation, api_code=error.api_code)
    if type(error) is GwmClosedError:
        return GwmClosedError(operation=operation)
    if type(error) is GwmConfigurationError:
        return GwmConfigurationError(operation=operation)
    if type(error) is GwmDeadlineExceededError:
        return GwmDeadlineExceededError(operation=operation)
    if type(error) is GwmNetworkError:
        return GwmNetworkError(operation=operation)
    if type(error) is GwmRedirectError:
        return GwmRedirectError(operation=operation)
    if type(error) is GwmResponseTooLargeError:
        return GwmResponseTooLargeError(operation=operation)
    if type(error) is GwmRoutePolicyError:
        return GwmRoutePolicyError(operation=operation)
    if type(error) is GwmSchemaError:
        return GwmSchemaError(operation=operation)
    if type(error) is GwmTlsError:
        return GwmTlsError(operation=operation)
    if type(error) is GwmProtocolError:
        return GwmProtocolError(operation=operation)
    return GwmNetworkError(operation=operation)


__all__ = [
    "AnzAuthenticated",
    "AnzAuthenticationMethod",
    "AnzAuthenticationResult",
    "AnzAuthState",
    "AnzCredentials",
    "AnzSessionReclaimRequired",
    "AnzVerificationRequired",
]
