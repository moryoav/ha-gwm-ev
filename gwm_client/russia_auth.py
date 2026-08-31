"""Russia authentication and immutable continuation state.

Russia uses the overseas H5/app gateway family, but its authentication wire
shape and static mutual-TLS identity are distinct from both EU and ANZ.  This
module keeps the finite authentication continuation independent of Home
Assistant and persistence while publishing only a validated read session.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
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
    is_overseas_refresh_rejected,
    is_overseas_session_expired,
)
from .models import GwmSession
from .regions import GatewayRole, Region, TlsMode, get_region_protocol
from .russia_identity import (
    RussiaBootstrapMaterial,
    create_russia_bootstrap_ssl_context,
)
from .signing import SignedRequest, SigningProfile, sign_request

_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_MAX_ACCOUNT_BYTES = 4 * 1024
_MAX_PASSWORD_BYTES = 64 * 1024
_MAX_TOKEN_LENGTH = 16 * 1024
_MAX_ID_LENGTH = 4 * 1024
_MAX_VERIFICATION_CODE_LENGTH = 64
_MAX_JSON_DEPTH = 64
_VERIFICATION_INTERVAL = timedelta(minutes=10)
_VERIFICATION_REQUIRED_CODE = "110641"
_RUSSIA_COUNTRY = "RU"
_RUSSIA_AGREEMENTS = (1, 2, 18, 19)
# These values are persisted or proven wire contracts, not vehicle-scope names.
_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-russia-account-v1\0"
_LEGACY_APP_MODEL = "ha-gwm-ora"


@dataclass(frozen=True, slots=True)
class RussiaCredentials:
    """A Russia account and stable per-installation device identity."""

    account: str = field(repr=False)
    password: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str)
            for value in (self.account, self.password, self.country, self.device_id)
        ):
            raise ValueError("credentials_invalid")
        account = self.account.strip()
        country = self.country.strip().upper()
        try:
            account_bytes = account.encode("utf-8", errors="strict")
            password_bytes = self.password.encode("utf-8", errors="strict")
            device_id = get_region_protocol(Region.RUSSIA).normalize_device_id(
                self.device_id
            )
        except (TypeError, UnicodeEncodeError, ValueError):
            raise ValueError("credentials_invalid") from None
        if (
            not account
            or len(account_bytes) > _MAX_ACCOUNT_BYTES
            or not self.password
            or len(password_bytes) > _MAX_PASSWORD_BYTES
            or country != _RUSSIA_COUNTRY
        ):
            raise ValueError("credentials_invalid")
        object.__setattr__(self, "account", account)
        object.__setattr__(self, "country", country)
        object.__setattr__(self, "device_id", device_id)

    @property
    def account_binding(self) -> str:
        """Return a domain-separated pseudonymous account binding."""

        digest = hashlib.sha256()
        digest.update(_LEGACY_ACCOUNT_BINDING_DOMAIN)
        digest.update(self.account.encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class RussiaAuthState:
    """Immutable Russia state candidate for caller-owned persistence."""

    account_binding: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)
    access_token: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)
    gw_id: str | None = field(default=None, repr=False)
    bean_id: str | None = field(default=None, repr=False)
    verification_requested_at: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        valid_device = False
        if isinstance(self.device_id, str):
            with contextlib.suppress(TypeError, ValueError):
                valid_device = (
                    get_region_protocol(Region.RUSSIA).normalize_device_id(
                        self.device_id
                    )
                    == self.device_id
                )
        if (
            not isinstance(self.account_binding, str)
            or _ACCOUNT_BINDING.fullmatch(self.account_binding) is None
            or self.country != _RUSSIA_COUNTRY
            or not valid_device
        ):
            raise ValueError("auth_state_invalid")
        _validate_optional_token(self.access_token)
        _validate_optional_token(self.refresh_token)
        _validate_optional_identifier(self.gw_id)
        _validate_optional_identifier(self.bean_id)
        requested_at = self.verification_requested_at
        if requested_at is not None and (
            not isinstance(requested_at, datetime)
            or requested_at.tzinfo is None
            or requested_at.utcoffset() is None
        ):
            raise ValueError("auth_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: RussiaCredentials) -> RussiaAuthState:
        """Create an empty state bound to exactly one account and installation."""

        if type(credentials) is not RussiaCredentials:
            raise ValueError("credentials_invalid")
        return cls(
            account_binding=credentials.account_binding,
            country=credentials.country,
            device_id=credentials.device_id,
        )

    def matches(self, credentials: RussiaCredentials) -> bool:
        """Return whether this state may be reused for the supplied credentials."""

        return type(credentials) is RussiaCredentials and (
            self.account_binding == credentials.account_binding
            and self.country == credentials.country
            and self.device_id == credentials.device_id
        )


@dataclass(frozen=True, slots=True)
class RussiaAuthenticated:
    """A validated Russia state and bootstrap-mTLS read session."""

    state: RussiaAuthState = field(repr=False)
    session: GwmSession = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not RussiaAuthState
            or type(self.session) is not GwmSession
            or self.state.access_token is None
            or self.session.country != self.state.country
            or self.session.device_id != self.state.device_id
            or self.session.access_token != self.state.access_token
        ):
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class RussiaVerificationRequired:
    """A finite verification continuation that never retains a submitted code."""

    state: RussiaAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.state) is not RussiaAuthState
            or type(self.code_requested) is not bool
            or type(self.code_rejected) is not bool
            or (self.code_requested and self.code_rejected)
        ):
            raise ValueError("authentication_result_invalid")


type RussiaAuthenticationResult = RussiaAuthenticated | RussiaVerificationRequired


@dataclass(slots=True)
class _RussiaAuthProgress:
    """Internal attempt state used to retire only definite auth rejection."""

    existing_session_rejected: bool = False


@dataclass(frozen=True, slots=True)
class _AuthEndpoint:
    operation: str
    path: str
    method: str
    access_token: bool
    require_data: bool


_LOGIN = _AuthEndpoint(
    "login",
    "userAuth/loginAccount",
    "POST",
    False,
    True,
)
_VERIFY_CODE = _AuthEndpoint(
    "verify_code",
    "userAuth/loginWithSMS",
    "POST",
    False,
    True,
)
_REQUEST_VERIFICATION = _AuthEndpoint(
    "request_verification",
    "userAuth/getSMSCode",
    "POST",
    False,
    False,
)
_REFRESH = _AuthEndpoint(
    "refresh_token",
    "userAuth/refreshToken",
    "POST",
    False,
    True,
)
_USER_INFO = _AuthEndpoint(
    "get_user_info",
    "user/getUserBaseInfo",
    "GET",
    True,
    True,
)
_AUTH_ENDPOINTS = MappingProxyType(
    {
        endpoint.operation: endpoint
        for endpoint in (
            _LOGIN,
            _VERIFY_CODE,
            _REQUEST_VERIFICATION,
            _REFRESH,
            _USER_INFO,
        )
    }
)


async def authenticate_russia(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: RussiaCredentials,
    state: RussiaAuthState | None,
    verification_code: str | None,
    bootstrap_material: RussiaBootstrapMaterial,
    deadline: _Deadline,
    progress: _RussiaAuthProgress,
    allow_password_login: bool = True,
) -> RussiaAuthenticationResult:
    """Run one serialized, finite Russia authentication continuation."""

    if (
        type(config) is not GwmClientConfig
        or config.region is not Region.RUSSIA
        or type(credentials) is not RussiaCredentials
        or (state is not None and type(state) is not RussiaAuthState)
        or type(allow_password_login) is not bool
        or type(bootstrap_material) is not RussiaBootstrapMaterial
        or type(deadline) is not _Deadline
        or type(progress) is not _RussiaAuthProgress
    ):
        raise GwmConfigurationError(operation="login")
    candidate = (
        state
        if state is not None and state.matches(credentials)
        else RussiaAuthState.for_credentials(credentials)
    )
    code = _normalize_verification_code(verification_code)

    # Russia always needs the static regional identity for the read session.
    # Preflight it before login, refresh, or verification delivery can occur.
    app_context: ssl.SSLContext | None = None
    default_context: ssl.SSLContext | None = None
    context_failure = False
    try:
        app_context = await _blocking_call(
            lambda: create_russia_bootstrap_ssl_context(
                bootstrap_material,
                now=_utc_now(),
            )
        )
        _ensure_deadline(deadline, operation="login")
        default_context = await _blocking_call(_create_default_ssl_context)
    except (OSError, ssl.SSLError, TypeError, ValueError):
        context_failure = True
    if context_failure or app_context is None or default_context is None:
        raise GwmConfigurationError(operation="login")
    _ensure_deadline(deadline, operation="login")

    access_rejected = False
    if candidate.access_token is not None:
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
            )
        except (GwmAuthenticationError, GwmApiError) as error:
            if not is_overseas_session_expired(error):
                raise
            access_rejected = True
            progress.existing_session_rejected = True
        else:
            candidate = _apply_user_info(candidate, profile)
            return _authenticated_result(candidate, app_context)

    if candidate.access_token is not None and candidate.refresh_token is not None:
        try:
            refreshed = await _request_data(
                config=config,
                transport=transport,
                endpoint=_REFRESH,
                credentials=credentials,
                body=_refresh_body(credentials, candidate),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except (GwmAuthenticationError, GwmApiError) as error:
            if not is_overseas_refresh_rejected(error):
                raise
            candidate = replace(
                candidate,
                access_token=None,
                refresh_token=None,
            )
        else:
            access_token, refresh_token = _parse_token_pair(
                refreshed,
                operation="refresh_token",
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
                )
            except (GwmAuthenticationError, GwmApiError) as error:
                if not is_overseas_session_expired(error):
                    raise
                progress.existing_session_rejected = True
                candidate = replace(
                    candidate,
                    access_token=None,
                    refresh_token=None,
                )
            else:
                candidate = _apply_user_info(
                    replace(
                        candidate,
                        access_token=access_token,
                        refresh_token=refresh_token,
                        verification_requested_at=None,
                    ),
                    profile,
                )
                return _authenticated_result(candidate, app_context)
    elif access_rejected or candidate.access_token is None:
        candidate = replace(
            candidate,
            access_token=None,
            refresh_token=None,
        )

    if not allow_password_login:
        raise GwmAuthenticationError(operation="login")

    if code is not None:
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=_VERIFY_CODE,
                credentials=credentials,
                body=_verification_login_body(credentials, code),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmRateLimitError:
            raise
        except GwmApiError as error:
            if not _is_verification_rejection(error):
                raise
            return RussiaVerificationRequired(
                state=replace(candidate, verification_requested_at=None),
                code_requested=False,
                code_rejected=True,
            )
    else:
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=_LOGIN,
                credentials=credentials,
                body=_password_login_body(credentials),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmApiError as error:
            if not _is_verification_challenge(error):
                raise
            now = _utc_now()
            requested_at = candidate.verification_requested_at
            throttled = (
                requested_at is not None
                and timedelta(0) <= now - requested_at < _VERIFICATION_INTERVAL
            )
            if throttled:
                return RussiaVerificationRequired(
                    state=candidate,
                    code_requested=False,
                )
            await _request_data(
                config=config,
                transport=transport,
                endpoint=_REQUEST_VERIFICATION,
                credentials=credentials,
                body=_verification_request_body(credentials),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
            return RussiaVerificationRequired(
                state=replace(candidate, verification_requested_at=now),
                code_requested=True,
            )

    access_token, refresh_token, gw_id, bean_id = _parse_login(login)
    candidate = replace(
        candidate,
        access_token=access_token,
        refresh_token=refresh_token,
        gw_id=gw_id,
        bean_id=bean_id,
        verification_requested_at=None,
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
        )
    except GwmAuthenticationError:
        progress.existing_session_rejected = True
        raise
    candidate = _apply_user_info(candidate, profile)
    return _authenticated_result(candidate, app_context)


async def refresh_russia_session(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: RussiaCredentials,
    state: RussiaAuthState,
    ssl_context: ssl.SSLContext,
    deadline: _Deadline,
) -> RussiaAuthenticated:
    """Rotate one Russia session while retaining its static app identity."""

    if (
        type(config) is not GwmClientConfig
        or config.region is not Region.RUSSIA
        or type(credentials) is not RussiaCredentials
        or type(state) is not RussiaAuthState
        or not state.matches(credentials)
        or state.access_token is None
        or state.refresh_token is None
        or not isinstance(ssl_context, ssl.SSLContext)
        or type(deadline) is not _Deadline
    ):
        raise GwmAuthenticationError(operation="refresh_token")
    _ensure_deadline(deadline, operation="refresh_token")
    try:
        default_context = await _blocking_call(_create_default_ssl_context)
    except (OSError, ssl.SSLError, ValueError):
        raise GwmConfigurationError(operation="refresh_token") from None
    try:
        refreshed = await _request_data(
            config=config,
            transport=transport,
            endpoint=_REFRESH,
            credentials=credentials,
            body=_refresh_body(credentials, state),
            access_token=None,
            ssl_context=default_context,
            deadline=deadline,
        )
    except (GwmAuthenticationError, GwmApiError) as error:
        if is_overseas_refresh_rejected(error):
            raise GwmAuthenticationError(
                operation="refresh_token",
                api_code=error.api_code,
            ) from None
        raise
    access_token, refresh_token = _parse_token_pair(
        refreshed,
        operation="refresh_token",
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
        )
    except (GwmAuthenticationError, GwmApiError) as error:
        if is_overseas_session_expired(error):
            raise GwmAuthenticationError(
                operation="get_user_info",
                api_code=error.api_code,
            ) from None
        raise
    updated = _apply_user_info(
        replace(
            state,
            access_token=access_token,
            refresh_token=refresh_token,
            verification_requested_at=None,
        ),
        profile,
    )
    return _authenticated_result(updated, ssl_context)


def _authenticated_result(
    state: RussiaAuthState,
    context: ssl.SSLContext,
) -> RussiaAuthenticated:
    access_token = state.access_token
    if access_token is None:
        raise GwmSchemaError(operation="login")
    return RussiaAuthenticated(
        state=state,
        session=GwmSession(
            country=state.country,
            device_id=state.device_id,
            access_token=access_token,
            app_ssl_context=context,
        ),
    )


async def _request_data(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    endpoint: _AuthEndpoint,
    credentials: RussiaCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
    deadline: _Deadline,
) -> object:
    request = _prepare_request(
        endpoint=endpoint,
        credentials=credentials,
        body=body,
        access_token=access_token,
        ssl_context=ssl_context,
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
    credentials: RussiaCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
) -> _TransportRequest:
    if _AUTH_ENDPOINTS.get(endpoint.operation) is not endpoint:
        raise GwmRoutePolicyError(operation=endpoint.operation)
    protocol = get_region_protocol(Region.RUSSIA)
    gateway = protocol.gateway(GatewayRole.H5_V1)
    body_text: str | None
    if endpoint.method == "GET":
        if body is not None:
            raise GwmRoutePolicyError(operation=endpoint.operation)
        body_text = None
    elif endpoint.method == "POST" and type(body) is dict:
        try:
            body_text = encode_dotnet_json(body)
        except ValueError:
            raise GwmRoutePolicyError(operation=endpoint.operation) from None
    else:
        raise GwmRoutePolicyError(operation=endpoint.operation)
    if endpoint.access_token != (access_token is not None):
        raise GwmRoutePolicyError(operation=endpoint.operation)

    unsigned_url = gateway.base_url + endpoint.path
    try:
        signed = sign_request(
            gateway.signing_profile,
            endpoint.method,
            unsigned_url,
            body_text,
        )
        _validate_signed_auth_request(
            signed,
            endpoint=endpoint,
            expected_body=body_text,
        )
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
            headers["Content-Type"] = "application/json; charset=utf-8"
        headers.update(signed.headers)
        _validate_gateway_tls(endpoint, ssl_context)
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


def _validate_signed_auth_request(
    signed: SignedRequest,
    *,
    endpoint: _AuthEndpoint,
    expected_body: str | None,
) -> None:
    if type(signed) is not SignedRequest:
        raise ValueError("route_invalid")
    protocol = get_region_protocol(Region.RUSSIA)
    gateway = protocol.gateway(GatewayRole.H5_V1)
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
    _validate_signing_headers(signed, gateway.signing_profile)


def _validate_signing_headers(
    signed: SignedRequest,
    profile: SigningProfile,
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
        or re.fullmatch(r"[0-9A-Fa-f]{16}", nonce) is None
        or (profile.uppercase_nonce and nonce != nonce.upper())
        or (not profile.uppercase_nonce and nonce != nonce.lower())
        or not 10 <= len(timestamp) <= 17
        or not timestamp.isdecimal()
        or _SIGNATURE.fullmatch(signature) is None
    ):
        raise ValueError("route_invalid")


def _validate_gateway_tls(endpoint: _AuthEndpoint, context: object) -> None:
    if (
        not isinstance(context, ssl.SSLContext)
        or not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.minimum_version < ssl.TLSVersion.TLSv1_2
        or (
            context.maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
            and (
                context.maximum_version < ssl.TLSVersion.TLSv1_2
                or context.maximum_version < context.minimum_version
            )
        )
        or context.security_level <= 0
        or get_region_protocol(Region.RUSSIA).gateway(GatewayRole.H5_V1).tls_mode
        is not TlsMode.DEFAULT
    ):
        raise ValueError("tls_context_invalid")
    if _AUTH_ENDPOINTS.get(endpoint.operation) is not endpoint:
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
        raise GwmAuthenticationError(operation=operation, api_code=safe_code)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry_seconds = (
            int(retry_after)
            if retry_after and len(retry_after) <= 10 and retry_after.isdecimal()
            else None
        )
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


def _password_login_body(credentials: RussiaCredentials) -> dict[str, object]:
    return {
        "account": credentials.account,
        "agreement": list(_RUSSIA_AGREEMENTS),
        "appType": 0,
        "country": credentials.country,
        "deviceId": credentials.device_id,
        "isEncrypt": False,
        "model": _LEGACY_APP_MODEL,
        "password": credentials.password,
        "pushToken": "",
        "type": 1,
    }


def _verification_login_body(
    credentials: RussiaCredentials,
    code: str,
) -> dict[str, object]:
    return {
        "agreement": list(_RUSSIA_AGREEMENTS),
        "appType": 0,
        "country": credentials.country,
        "deviceId": credentials.device_id,
        "email": credentials.account,
        "model": _LEGACY_APP_MODEL,
        "pushToken": "",
        "smsCode": code,
    }


def _verification_request_body(
    credentials: RussiaCredentials,
) -> dict[str, object]:
    return {
        "email": credentials.account,
        "scenario": 0,
        "type": 3,
    }


def _refresh_body(
    credentials: RussiaCredentials,
    state: RussiaAuthState,
) -> dict[str, object]:
    if state.access_token is None or state.refresh_token is None:
        raise GwmConfigurationError(operation="refresh_token")
    return {
        "accessToken": state.access_token,
        "refreshToken": state.refresh_token,
        "deviceId": credentials.device_id,
    }


def _parse_token_pair(data: object, *, operation: str) -> tuple[str, str]:
    access = _required_text(
        data,
        "accessToken",
        operation=operation,
        maximum=_MAX_TOKEN_LENGTH,
        allow_integer=False,
    )
    refresh = _required_text(
        data,
        "refreshToken",
        operation=operation,
        maximum=_MAX_TOKEN_LENGTH,
        allow_integer=False,
    )
    _validate_token(access)
    _validate_token(refresh)
    return access, refresh


def _parse_login(data: object) -> tuple[str, str, str | None, str | None]:
    access, refresh = _parse_token_pair(data, operation="login")
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation="login")
    return (
        access,
        refresh,
        _optional_text(data.get("gwId"), operation="login"),
        _optional_text(data.get("beanId"), operation="login"),
    )


def _apply_user_info(state: RussiaAuthState, data: object) -> RussiaAuthState:
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation="get_user_info")
    gw_id = _optional_text(data.get("gwId"), operation="get_user_info")
    bean_id = _optional_text(data.get("beanId"), operation="get_user_info")
    return replace(
        state,
        gw_id=state.gw_id if gw_id is None else gw_id,
        bean_id=state.bean_id if bean_id is None else bean_id,
    )


def _required_text(
    data: object,
    key: str,
    *,
    operation: str,
    maximum: int,
    allow_integer: bool,
) -> str:
    if not isinstance(data, Mapping):
        raise GwmSchemaError(operation=operation)
    value = data.get(key)
    if allow_integer and isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise GwmSchemaError(operation=operation)
    return value


def _optional_text(value: object, *, operation: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ID_LENGTH
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


def _is_verification_challenge(error: GwmApiError) -> bool:
    return type(error) is GwmApiError and error.api_code == _VERIFICATION_REQUIRED_CODE


def _is_verification_rejection(error: GwmApiError) -> bool:
    return type(error) is GwmAuthenticationError


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


def _validate_optional_identifier(value: str | None) -> None:
    if value is not None and (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ID_LENGTH
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError("identifier_invalid")


def _create_default_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if (
        not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.minimum_version < ssl.TLSVersion.TLSv1_2
        or context.security_level <= 0
    ):
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
        return GwmAuthenticationError(
            operation=operation,
            api_code=error.api_code,
        )
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
    "RussiaAuthenticated",
    "RussiaAuthenticationResult",
    "RussiaAuthState",
    "RussiaCredentials",
    "RussiaVerificationRequired",
    "refresh_russia_session",
]
