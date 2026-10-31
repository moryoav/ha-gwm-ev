"""APAC authentication primitives using explicitly injected contexts.

Home Assistant orchestrates these primitives and persists account-bound state separately.
They never initiate authentication or verification automatically.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from ._protocol import _AsyncTransport, _Deadline
from .apac_auth import ApacCredentials, login_body, verification_body
from .apac_identity import create_apac_bootstrap_context, create_apac_issued_context
from .apac_material import ApacMaterial
from .apac_request import prepare_apac_request
from .crypto import generate_client_certificate_request
from .errors import GwmDeadlineExceededError, GwmSchemaError
from .eu_auth import _decode_auth_envelope, _parse_login, _parse_token_pair, _required_text
from .eu_identity import EuIssuedIdentity


@dataclass(frozen=True, slots=True)
class ApacTokens:
    """Private token snapshot; the caller must bind it to the issuing account."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    gw_id: str = field(repr=False)
    bean_id: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject invalid private state before refresh or certificate enrollment."""
        for value, maximum in (
            (self.access_token, 16 * 1024),
            (self.refresh_token, 16 * 1024),
            (self.gw_id, 4 * 1024),
            (self.bean_id, 4 * 1024),
        ):
            if (
                not isinstance(value, str)
                or not 0 < len(value) <= maximum
                or any(not 0x21 <= ord(character) <= 0x7E for character in value)
            ):
                raise ValueError("apac_session_invalid")


@dataclass(frozen=True, slots=True)
class ApacIssued:
    """Validated APAC identity and its matching private vehicle TLS context."""

    identity: EuIssuedIdentity = field(repr=False)
    app_ssl_context: ssl.SSLContext = field(repr=False)


class ApacAuthClient:
    """Authentication requests with injected transport and TLS contexts."""

    def __init__(
        self,
        *,
        material: ApacMaterial,
        credentials: ApacCredentials,
        h5_context: ssl.SSLContext,
        transport: _AsyncTransport,
    ) -> None:
        """Retain caller-owned dependencies without initiating authentication."""
        if type(material) is not ApacMaterial or type(credentials) is not ApacCredentials:
            raise ValueError("apac_credentials_invalid")
        self._material = material
        self._credentials = credentials
        self._h5_context = h5_context
        self._transport = transport
        self._lock = asyncio.Lock()

    async def _post(
        self,
        operation: Literal["login", "request_verification", "verify_code", "refresh_token"],
        body: dict[str, object],
        *,
        require_data: bool,
    ) -> object:
        """Send one explicit authentication request under a bounded operation lock."""
        if operation not in {"login", "request_verification", "verify_code", "refresh_token"}:
            raise ValueError("apac_operation_not_supported")
        deadline = _Deadline(asyncio.get_running_loop().time() + 30)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                request = prepare_apac_request(
                    operation=operation,
                    material=self._material,
                    ssl_context=self._h5_context,
                    device_id=self._credentials.device_id,
                    body=body,
                    country=self._credentials.country,
                )
                response = await self._transport.execute(
                    request, deadline=deadline, connect_timeout=10, read_timeout=20
                )
                return _decode_auth_envelope(response, operation=operation, require_data=require_data)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None

    async def login(self, verification_code: str | None = None) -> ApacTokens:
        """Perform an explicitly requested password login, optionally with a code."""
        data = await self._post("login", login_body(self._credentials, verification_code), require_data=True)
        access, refresh, gw_id, bean_id = _parse_login(data)
        return ApacTokens(access, refresh, gw_id, bean_id)

    async def request_verification(self) -> None:
        """Request a verification code only when explicitly invoked."""
        await self._post("request_verification", verification_body(self._credentials), require_data=False)

    async def verify_code(self, code: str) -> None:
        """Check a user-supplied verification code."""
        if not isinstance(code, str):
            raise ValueError("apac_verification_invalid")
        await self._post("verify_code", verification_body(self._credentials, code), require_data=False)

    async def refresh(self, state: ApacTokens) -> ApacTokens:
        """Refresh only when explicitly invoked; no silent password fallback."""
        if type(state) is not ApacTokens:
            raise ValueError("apac_session_invalid")
        data = await self._post(
            "refresh_token",
            {
                "accessToken": state.access_token,
                "refreshToken": state.refresh_token,
                "deviceId": self._credentials.device_id,
            },
            require_data=True,
        )
        access, refresh = _parse_token_pair(data, operation="refresh_token")
        return ApacTokens(access, refresh, state.gw_id, state.bean_id)

    async def get_user_info(self, access_token: str) -> tuple[str, str]:
        """Read account identifiers so restored tokens cannot cross accounts."""
        deadline = _Deadline(asyncio.get_running_loop().time() + 30)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                request = prepare_apac_request(
                    operation="get_user_info",
                    material=self._material,
                    ssl_context=self._h5_context,
                    device_id=self._credentials.device_id,
                    access_token=access_token,
                    country=self._credentials.country,
                )
                response = await self._transport.execute(
                    request, deadline=deadline, connect_timeout=10, read_timeout=20
                )
                data = _decode_auth_envelope(response, operation="get_user_info", require_data=True)
                gw_id = _required_text(data, "gwId", operation="get_user_info", maximum=4096)
                bean_id = _required_text(data, "beanId", operation="get_user_info", maximum=4096)
                return gw_id, bean_id
        except TimeoutError:
            raise GwmDeadlineExceededError(operation="get_user_info") from None

    async def enroll_identity(self, state: ApacTokens) -> ApacIssued:
        """Explicitly enroll an identity, then strictly verify its chain."""
        if type(state) is not ApacTokens:
            raise ValueError("apac_session_invalid")
        deadline = _Deadline(asyncio.get_running_loop().time() + 30)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                return await self._enroll_identity(state, now=datetime.now(UTC), deadline=deadline)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation="enroll_certificate") from None

    async def _enroll_identity(self, state: ApacTokens, *, now: datetime, deadline: _Deadline) -> ApacIssued:
        """Enroll under the caller's lock and operation deadline."""
        generated = await asyncio.to_thread(
            generate_client_certificate_request, self._credentials.country, self._credentials.device_id, now=now
        )
        bootstrap_context = await asyncio.to_thread(create_apac_bootstrap_context, self._material.bootstrap)
        enrollment_device = self._credentials.device_id + str(int(now.timestamp() * 1000))
        request = prepare_apac_request(
            operation="enroll_certificate",
            material=self._material,
            ssl_context=bootstrap_context,
            device_id=self._credentials.device_id,
            enrollment_device_id=enrollment_device,
            access_token=state.access_token,
            body={"csr": generated.csr, "phone": state.gw_id},
            country=self._credentials.country,
        )
        response = await self._transport.execute(request, deadline=deadline, connect_timeout=10, read_timeout=20)
        data = _decode_auth_envelope(response, operation="enroll_certificate", require_data=True)
        if not isinstance(data, dict) or not isinstance(data.get("encoded"), str):
            raise GwmSchemaError(operation="enroll_certificate")
        identity = EuIssuedIdentity(certificate=data["encoded"], private_key=generated.private_key)
        context = await asyncio.to_thread(
            create_apac_issued_context, identity, ca_bundle=self._material.bootstrap.ca_bundle
        )
        return ApacIssued(identity, context)
