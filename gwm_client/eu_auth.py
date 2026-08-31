"""EU authentication, verification, refresh, and certificate enrollment."""

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
from .crypto import GeneratedClientCertificateRequest, generate_client_certificate_request
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
from .eu_identity import (
    EuBootstrapMaterial,
    EuIdentityError,
    EuIssuedIdentity,
    create_eu_bootstrap_ssl_context,
    create_eu_issued_ssl_context,
)
from .models import GwmSession
from .regions import GatewayRole, Region, TlsMode, get_region_protocol
from .signing import SignedRequest, SigningProfile, sign_request

_ACCOUNT_BINDING = re.compile(r"[0-9a-f]{64}")
_DEVICE_ID = re.compile(r"[0-9a-f]{32}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_MAX_ACCOUNT_BYTES = 4 * 1024
_MAX_PASSWORD_BYTES = 64 * 1024
_MAX_TOKEN_LENGTH = 16 * 1024
_MAX_ID_LENGTH = 4 * 1024
_MAX_VERIFICATION_CODE_LENGTH = 64
_MAX_CA_BUNDLE_BYTES = 256 * 1024
_MAX_JSON_DEPTH = 64
_VERIFICATION_INTERVAL = timedelta(minutes=10)
_VERIFICATION_REQUIRED_CODES = frozenset({"308103", "110641"})
# This persisted hash-domain value is a compatibility contract, not a vehicle-scope name.
_LEGACY_ACCOUNT_BINDING_DOMAIN = b"gwm-ora-eu-account-v1\0"
_RENEWABLE_ISSUED_IDENTITY_ERRORS = frozenset(
    {
        "identity_basic_constraints_invalid",
        "identity_chain_invalid",
        "identity_expired",
        "identity_extended_key_usage_invalid",
        "identity_extensions_invalid",
        "identity_invalid",
        "identity_issuer_invalid",
        "identity_key_mismatch",
        "identity_key_usage_invalid",
        "identity_not_yet_valid",
        "identity_renewal_required",
        "identity_rsa_contract_invalid",
        "issued_certificate_encoding_invalid",
        "issued_identity_invalid",
        "issued_identity_key_invalid",
        "issued_private_key_encoding_invalid",
    }
)

_CALLING_CODES = MappingProxyType(
    {
        "AD": "+376",
        "AE": "+971",
        "AL": "+355",
        "AM": "+374",
        "AT": "+43",
        "AU": "+61",
        "AZ": "+994",
        "BA": "+387",
        "BE": "+32",
        "BG": "+359",
        "BY": "+375",
        "CH": "+41",
        "CY": "+357",
        "CZ": "+420",
        "DE": "+49",
        "DK": "+45",
        "EE": "+372",
        "ES": "+34",
        "FI": "+358",
        "FO": "+298",
        "FR": "+33",
        "GB": "+44",
        "GE": "+995",
        "GI": "+350",
        "GR": "+30",
        "HR": "+385",
        "HU": "+36",
        "IE": "+353",
        "IL": "+972",
        "IS": "+354",
        "IT": "+39",
        "KZ": "+7",
        "LI": "+423",
        "LT": "+370",
        "LU": "+352",
        "LV": "+371",
        "MC": "+377",
        "MD": "+373",
        "ME": "+382",
        "MK": "+389",
        "MT": "+356",
        "NL": "+31",
        "NO": "+47",
        "NZ": "+64",
        "PL": "+48",
        "PT": "+351",
        "RO": "+40",
        "RS": "+381",
        "RU": "+7",
        "SE": "+46",
        "SI": "+386",
        "SK": "+421",
        "SM": "+378",
        "TR": "+90",
        "UA": "+380",
        "UK": "+44",
        "VA": "+39",
        "ZA": "+27",
    }
)


@dataclass(frozen=True, slots=True)
class EuCredentials:
    """Normalized EU credentials and the stable per-installation device identity."""

    account: str = field(repr=False)
    password: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) for value in (self.account, self.password, self.country, self.device_id)):
            raise ValueError("credentials_invalid")
        account = self.account.strip()
        country = self.country.strip().upper()
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
            or country not in _CALLING_CODES
        ):
            raise ValueError("credentials_invalid")
        device = _normalize_stable_device_id(self.device_id)
        object.__setattr__(self, "account", account)
        object.__setattr__(self, "country", country)
        object.__setattr__(self, "device_id", device)

    @property
    def account_binding(self) -> str:
        """Return a domain-separated pseudonymous binding for persisted state."""

        digest = hashlib.sha256()
        digest.update(_LEGACY_ACCOUNT_BINDING_DOMAIN)
        digest.update(self.account.encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class EuAuthState:
    """Immutable state candidate for a caller-owned persistence boundary."""

    account_binding: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)
    access_token: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)
    gw_id: str | None = field(default=None, repr=False)
    bean_id: str | None = field(default=None, repr=False)
    issued_identity: EuIssuedIdentity | None = field(default=None, repr=False)
    verification_requested_at: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.account_binding, str)
            or _ACCOUNT_BINDING.fullmatch(self.account_binding) is None
            or not isinstance(self.country, str)
            or self.country not in _CALLING_CODES
            or not isinstance(self.device_id, str)
            or _DEVICE_ID.fullmatch(self.device_id) is None
        ):
            raise ValueError("auth_state_invalid")
        _validate_optional_token(self.access_token)
        _validate_optional_identifier(self.refresh_token, token=True)
        _validate_optional_identifier(self.gw_id)
        _validate_optional_identifier(self.bean_id)
        if self.issued_identity is not None and (
            type(self.issued_identity) is not EuIssuedIdentity or self.gw_id is None
        ):
            raise ValueError("auth_state_invalid")
        requested_at = self.verification_requested_at
        if requested_at is not None and (
            not isinstance(requested_at, datetime) or requested_at.tzinfo is None or requested_at.utcoffset() is None
        ):
            raise ValueError("auth_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: EuCredentials) -> EuAuthState:
        """Create an empty state candidate bound to the supplied credentials."""

        if type(credentials) is not EuCredentials:
            raise ValueError("credentials_invalid")
        return cls(
            account_binding=credentials.account_binding,
            country=credentials.country,
            device_id=credentials.device_id,
        )

    def matches(self, credentials: EuCredentials) -> bool:
        """Return whether this state can safely be reused for the credentials."""

        return type(credentials) is EuCredentials and (
            self.account_binding == credentials.account_binding
            and self.country == credentials.country
            and self.device_id == credentials.device_id
        )


@dataclass(frozen=True, slots=True)
class EuAuthenticated:
    """A fully validated state and issued-mTLS read session."""

    state: EuAuthState = field(repr=False)
    session: GwmSession = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.state) is not EuAuthState or type(self.session) is not GwmSession:
            raise ValueError("authentication_result_invalid")


@dataclass(frozen=True, slots=True)
class EuVerificationRequired:
    """A continuation outcome that never retains the submitted code or password."""

    state: EuAuthState = field(repr=False)
    code_requested: bool
    code_rejected: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.state) is not EuAuthState
            or type(self.code_requested) is not bool
            or type(self.code_rejected) is not bool
            or (self.code_requested and self.code_rejected)
        ):
            raise ValueError("authentication_result_invalid")


type EuAuthenticationResult = EuAuthenticated | EuVerificationRequired


@dataclass(slots=True)
class _EuAuthProgress:
    """Internal attempt state used to retire a definitively rejected session."""

    existing_access_rejected: bool = False
    existing_identity_rejected: bool = False

    @property
    def existing_session_rejected(self) -> bool:
        return self.existing_access_rejected or self.existing_identity_rejected


@dataclass(frozen=True, slots=True)
class _AuthEndpoint:
    operation: str
    role: GatewayRole
    path: str
    method: str
    access_token: bool
    require_data: bool


_LOGIN = _AuthEndpoint("login", GatewayRole.AUTH_V2, "userAuth/loginWithPassword", "POST", False, True)
_REQUEST_VERIFICATION = _AuthEndpoint(
    "request_verification", GatewayRole.AUTH_V2, "userAuth/getVerifyCode", "POST", False, False
)
_VERIFY_CODE = _AuthEndpoint("verify_code", GatewayRole.AUTH_V2, "userAuth/checkVerifyCode", "POST", False, False)
_REFRESH = _AuthEndpoint("refresh_token", GatewayRole.H5_V1, "userAuth/refreshToken", "POST", False, True)
_USER_INFO = _AuthEndpoint("get_user_info", GatewayRole.H5_V1, "user/getUserBaseInfo", "GET", True, True)
_ENROLL = _AuthEndpoint(
    "enroll_certificate", GatewayRole.CERTIFICATE_V1, "appAuth/applyCertificate", "POST", True, True
)
_AUTH_ENDPOINTS = MappingProxyType(
    {
        endpoint.operation: endpoint
        for endpoint in (
            _LOGIN,
            _REQUEST_VERIFICATION,
            _VERIFY_CODE,
            _REFRESH,
            _USER_INFO,
            _ENROLL,
        )
    }
)


async def authenticate_eu(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: EuCredentials,
    state: EuAuthState | None,
    verification_code: str | None,
    ca_bundle: bytes,
    bootstrap_material: EuBootstrapMaterial | None,
    deadline: _Deadline,
    progress: _EuAuthProgress,
    allow_password_login: bool = True,
) -> EuAuthenticationResult:
    """Run one serialized finite EU authentication continuation."""

    if (
        type(config) is not GwmClientConfig
        or config.region is not Region.EU
        or type(credentials) is not EuCredentials
        or (state is not None and type(state) is not EuAuthState)
        or type(allow_password_login) is not bool
        or not isinstance(ca_bundle, bytes)
        or not 0 < len(ca_bundle) <= _MAX_CA_BUNDLE_BYTES
        or (bootstrap_material is not None and type(bootstrap_material) is not EuBootstrapMaterial)
        or type(deadline) is not _Deadline
        or type(progress) is not _EuAuthProgress
        or (bootstrap_material is not None and bootstrap_material.ca_bundle != ca_bundle)
    ):
        raise GwmConfigurationError(operation="login")
    candidate = state if state is not None and state.matches(credentials) else EuAuthState.for_credentials(credentials)
    code = _normalize_verification_code(verification_code)
    bootstrap_context: ssl.SSLContext | None = None
    if candidate.issued_identity is None:
        if bootstrap_material is None:
            raise GwmConfigurationError(operation="enroll_certificate")
        try:
            bootstrap_context = await _blocking_call(
                lambda: create_eu_bootstrap_ssl_context(bootstrap_material, now=_utc_now())
            )
        except (TypeError, ValueError):
            raise GwmConfigurationError(operation="enroll_certificate") from None
        _ensure_deadline(deadline, operation="enroll_certificate")
    try:
        default_context = await _blocking_call(_create_default_ssl_context)
    except (OSError, ssl.SSLError, ValueError):
        raise GwmConfigurationError(operation="login") from None
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
            progress.existing_access_rejected = True
        else:
            candidate = _apply_user_info(candidate, profile)
            return await _finish_authentication(
                config=config,
                transport=transport,
                credentials=credentials,
                state=candidate,
                ca_bundle=ca_bundle,
                bootstrap_material=bootstrap_material,
                bootstrap_context=bootstrap_context,
                deadline=deadline,
                progress=progress,
            )

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
            access_token, refresh_token = _parse_token_pair(refreshed, operation="refresh_token")
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
                candidate = replace(
                    candidate,
                    access_token=None,
                    refresh_token=None,
                )
            else:
                candidate = _apply_user_info(
                    replace(candidate, access_token=access_token, refresh_token=refresh_token),
                    profile,
                )
                return await _finish_authentication(
                    config=config,
                    transport=transport,
                    credentials=credentials,
                    state=candidate,
                    ca_bundle=ca_bundle,
                    bootstrap_material=bootstrap_material,
                    bootstrap_context=bootstrap_context,
                    deadline=deadline,
                    progress=progress,
                )
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
            await _request_data(
                config=config,
                transport=transport,
                endpoint=_VERIFY_CODE,
                credentials=credentials,
                body=_verification_check_body(credentials, code),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmRateLimitError:
            raise
        except GwmApiError as error:
            if not _is_verification_challenge(error):
                raise
            return EuVerificationRequired(
                state=replace(candidate, verification_requested_at=None),
                code_requested=False,
                code_rejected=True,
            )
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=_LOGIN,
                credentials=credentials,
                body=_login_body(credentials, verification_code=code),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmApiError as error:
            if _is_verification_challenge(error):
                return EuVerificationRequired(
                    state=replace(candidate, verification_requested_at=None),
                    code_requested=False,
                    code_rejected=True,
                )
            raise
    else:
        try:
            login = await _request_data(
                config=config,
                transport=transport,
                endpoint=_LOGIN,
                credentials=credentials,
                body=_login_body(credentials, verification_code=None),
                access_token=None,
                ssl_context=default_context,
                deadline=deadline,
            )
        except GwmApiError as error:
            if not _is_verification_challenge(error):
                raise
            now = _utc_now()
            requested_at = candidate.verification_requested_at
            throttled = requested_at is not None and timedelta(0) <= now - requested_at < _VERIFICATION_INTERVAL
            if throttled:
                return EuVerificationRequired(
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
            return EuVerificationRequired(
                state=replace(candidate, verification_requested_at=now),
                code_requested=True,
            )

    access_token, refresh_token, gw_id, bean_id = _parse_login(login)
    identity = candidate.issued_identity if candidate.gw_id == gw_id else None
    candidate = replace(
        candidate,
        access_token=access_token,
        refresh_token=refresh_token,
        gw_id=gw_id,
        bean_id=bean_id,
        issued_identity=identity,
        verification_requested_at=None,
    )
    return await _finish_authentication(
        config=config,
        transport=transport,
        credentials=credentials,
        state=candidate,
        ca_bundle=ca_bundle,
        bootstrap_material=bootstrap_material,
        bootstrap_context=bootstrap_context,
        deadline=deadline,
        progress=progress,
    )


async def refresh_eu_session(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: EuCredentials,
    state: EuAuthState,
    ssl_context: ssl.SSLContext,
    deadline: _Deadline,
) -> EuAuthenticated:
    """Rotate one EU session while retaining its issued app identity."""

    if (
        type(config) is not GwmClientConfig
        or config.region is not Region.EU
        or type(credentials) is not EuCredentials
        or type(state) is not EuAuthState
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


async def _finish_authentication(
    *,
    config: GwmClientConfig,
    transport: _AsyncTransport,
    credentials: EuCredentials,
    state: EuAuthState,
    ca_bundle: bytes,
    bootstrap_material: EuBootstrapMaterial | None,
    bootstrap_context: ssl.SSLContext | None,
    deadline: _Deadline,
    progress: _EuAuthProgress,
) -> EuAuthenticated:
    _ensure_deadline(deadline, operation="enroll_certificate")
    access_token = state.access_token
    gw_id = state.gw_id
    if access_token is None or gw_id is None:
        raise GwmSchemaError(operation="login")

    identity = state.issued_identity
    if identity is not None:
        try:
            context = await _blocking_call(
                lambda: create_eu_issued_ssl_context(identity, ca_bundle=ca_bundle, now=_utc_now())
            )
        except EuIdentityError as error:
            if error.category not in _RENEWABLE_ISSUED_IDENTITY_ERRORS:
                raise GwmConfigurationError(operation="enroll_certificate") from None
            if error.category != "identity_renewal_required":
                progress.existing_identity_rejected = True
        except (TypeError, ValueError):
            raise GwmConfigurationError(operation="enroll_certificate") from None
        else:
            _ensure_deadline(deadline, operation="enroll_certificate")
            return _authenticated_result(state, context)
        _ensure_deadline(deadline, operation="enroll_certificate")

    if bootstrap_material is None:
        raise GwmConfigurationError(operation="enroll_certificate")
    if bootstrap_material.ca_bundle != ca_bundle:
        raise GwmConfigurationError(operation="enroll_certificate")
    now = _utc_now()
    try:
        generated = await _blocking_call(
            lambda: generate_client_certificate_request(
                credentials.country,
                credentials.device_id,
                now=now,
            )
        )
        if bootstrap_context is None:
            bootstrap_context = await _blocking_call(
                lambda: create_eu_bootstrap_ssl_context(bootstrap_material, now=now)
            )
    except (TypeError, ValueError):
        raise GwmConfigurationError(operation="enroll_certificate") from None
    _ensure_deadline(deadline, operation="enroll_certificate")
    enrolled = await _request_data(
        config=config,
        transport=transport,
        endpoint=_ENROLL,
        credentials=credentials,
        body=_enrollment_body(generated, gw_id),
        access_token=access_token,
        ssl_context=bootstrap_context,
        deadline=deadline,
        enrollment_device_id=_enrollment_device_id(credentials.device_id, now),
    )
    encoded = _required_text(enrolled, "encoded", operation="enroll_certificate", maximum=256 * 1024)
    try:
        issued_identity = EuIssuedIdentity(
            certificate=encoded,
            private_key=generated.private_key,
        )
        context = await _blocking_call(
            lambda: create_eu_issued_ssl_context(
                issued_identity,
                ca_bundle=ca_bundle,
                now=_utc_now(),
            )
        )
    except (TypeError, ValueError):
        raise GwmSchemaError(operation="enroll_certificate") from None
    _ensure_deadline(deadline, operation="enroll_certificate")
    completed = replace(state, issued_identity=issued_identity)
    return _authenticated_result(completed, context)


def _authenticated_result(state: EuAuthState, context: ssl.SSLContext) -> EuAuthenticated:
    access_token = state.access_token
    if access_token is None:
        raise GwmSchemaError(operation="login")
    return EuAuthenticated(
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
    credentials: EuCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
    deadline: _Deadline,
    enrollment_device_id: str | None = None,
) -> object:
    request = _prepare_request(
        endpoint=endpoint,
        credentials=credentials,
        body=body,
        access_token=access_token,
        ssl_context=ssl_context,
        enrollment_device_id=enrollment_device_id,
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
    credentials: EuCredentials,
    body: dict[str, object] | None,
    access_token: str | None,
    ssl_context: ssl.SSLContext,
    enrollment_device_id: str | None,
) -> _TransportRequest:
    if _AUTH_ENDPOINTS.get(endpoint.operation) is not endpoint:
        raise GwmRoutePolicyError(operation=endpoint.operation)
    protocol = get_region_protocol(Region.EU)
    gateway = protocol.gateway(endpoint.role)
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
    if (endpoint is _ENROLL) != (enrollment_device_id is not None):
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
        normal_device = protocol.normalize_device_id(credentials.device_id)
        header_device = enrollment_device_id or normal_device
        headers = {
            **protocol.base_headers,
            "country": credentials.country,
            "regionCode": credentials.country,
            "deviceId": header_device,
            "iccid": header_device,
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
    protocol = get_region_protocol(Region.EU)
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
    _validate_signing_headers(signed, gateway.signing_profile)


def _validate_signing_headers(signed: SignedRequest, profile: SigningProfile) -> None:
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
            and (context.maximum_version < ssl.TLSVersion.TLSv1_2 or context.maximum_version < context.minimum_version)
        )
    ):
        raise ValueError("tls_context_invalid")
    mode = get_region_protocol(Region.EU).gateway(endpoint.role).tls_mode
    if mode is TlsMode.DEFAULT:
        if context.security_level <= 0:
            raise ValueError("tls_context_invalid")
    elif mode in {TlsMode.EU_BOOTSTRAP_MTLS, TlsMode.EU_ISSUED_MTLS}:
        if context.security_level != 0:
            raise ValueError("tls_context_invalid")
    else:
        raise ValueError("tls_context_invalid")


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
    if response.status in {401, 403}:
        raise GwmAuthenticationError(operation=operation, api_code=code)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry_seconds = int(retry_after) if retry_after and len(retry_after) <= 10 and retry_after.isdecimal() else None
        raise GwmRateLimitError(
            operation=operation,
            api_code=code,
            retry_after_seconds=retry_seconds,
        )
    if not 200 <= response.status <= 299:
        raise GwmHttpError(operation=operation, status=response.status)
    if valid_json:
        assert isinstance(envelope, Mapping)
        if code != "000000":
            raise GwmApiError(operation=operation, api_code=code)
    if not valid_json:
        raise GwmSchemaError(operation=operation)
    assert isinstance(envelope, Mapping)
    if require_data:
        if "data" not in envelope:
            raise GwmSchemaError(operation=operation)
        return envelope["data"]
    return envelope.get("data")


def _login_body(credentials: EuCredentials, *, verification_code: str | None) -> dict[str, object]:
    body: dict[str, object] = {
        "account": credentials.account,
        "accountType": "2",
        "countryCode": _CALLING_CODES[credentials.country],
        "agreement": [1, 2],
        "password": credentials.password,
        "deviceId": credentials.device_id[:16],
        "appType": "0",
        "pushToken": "",
        "country": credentials.country,
    }
    if verification_code is not None:
        body["verifyCode"] = verification_code
        body["validCodeMode"] = "1"
    return body


def _verification_request_body(credentials: EuCredentials) -> dict[str, object]:
    return {
        "type": "17",
        "account": credentials.account,
        "accountType": "2",
        "countryCode": _CALLING_CODES[credentials.country],
        "validCodeMode": 1,
        "operateCode": "",
        "captchaType": "",
        "captchaId": "",
        "token": "",
    }


def _verification_check_body(credentials: EuCredentials, code: str) -> dict[str, object]:
    return {
        "account": credentials.account,
        "verifyCode": code,
        "type": "17",
        "accountType": "2",
        "countryCode": _CALLING_CODES[credentials.country],
        "validCodeMode": 1,
    }


def _refresh_body(credentials: EuCredentials, state: EuAuthState) -> dict[str, object]:
    if state.access_token is None or state.refresh_token is None:
        raise GwmConfigurationError(operation="refresh_token")
    return {
        "accessToken": state.access_token,
        "refreshToken": state.refresh_token,
        "deviceId": credentials.device_id[:16],
    }


def _enrollment_body(
    generated: GeneratedClientCertificateRequest,
    gw_id: str,
) -> dict[str, object]:
    if type(generated) is not GeneratedClientCertificateRequest:
        raise GwmConfigurationError(operation="enroll_certificate")
    return {"csr": generated.csr, "phone": gw_id}


def _enrollment_device_id(device_id: str, now: datetime) -> str:
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    elapsed = now.astimezone(UTC) - epoch
    milliseconds = elapsed.days * 86_400_000 + elapsed.seconds * 1_000 + elapsed.microseconds // 1_000
    return device_id[:32] + str(milliseconds)


def _parse_token_pair(data: object, *, operation: str) -> tuple[str, str]:
    access = _required_text(data, "accessToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    refresh = _required_text(data, "refreshToken", operation=operation, maximum=_MAX_TOKEN_LENGTH)
    _validate_token(access)
    _validate_token(refresh)
    return access, refresh


def _parse_login(data: object) -> tuple[str, str, str, str]:
    access, refresh = _parse_token_pair(data, operation="login")
    gw_id = _required_text(data, "gwId", operation="login", maximum=_MAX_ID_LENGTH)
    bean_id = _required_text(data, "beanId", operation="login", maximum=_MAX_ID_LENGTH)
    return access, refresh, gw_id, bean_id


def _apply_user_info(state: EuAuthState, data: object) -> EuAuthState:
    gw_id = _required_text(data, "gwId", operation="get_user_info", maximum=_MAX_ID_LENGTH)
    bean_id = _required_text(data, "beanId", operation="get_user_info", maximum=_MAX_ID_LENGTH)
    identity = state.issued_identity if state.gw_id == gw_id else None
    return replace(state, gw_id=gw_id, bean_id=bean_id, issued_identity=identity)


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
    return type(error) is GwmApiError and error.api_code in _VERIFICATION_REQUIRED_CODES


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
        raise ValueError("auth_state_invalid")


def _validate_optional_identifier(value: str | None, *, token: bool = False) -> None:
    if value is None:
        return
    maximum = _MAX_TOKEN_LENGTH if token else _MAX_ID_LENGTH
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError("auth_state_invalid")


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
        return GwmHttpError(operation=operation, status=error.status)
    if type(error) is GwmRateLimitError:
        return GwmRateLimitError(
            operation=operation,
            api_code=error.api_code,
            retry_after_seconds=error.retry_after_seconds,
        )
    if type(error) is GwmAuthenticationError:
        return GwmAuthenticationError(operation=operation, api_code=error.api_code)
    if type(error) is GwmApiError:
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
    "EuAuthenticated",
    "EuAuthenticationResult",
    "EuAuthState",
    "EuCredentials",
    "EuVerificationRequired",
    "refresh_eu_session",
]
