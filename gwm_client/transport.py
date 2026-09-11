"""Bounded aiohttp transport for already prepared GWM requests."""

from __future__ import annotations

import asyncio
import math
import ssl
from collections.abc import Mapping
from typing import Any, Self

import aiohttp
from yarl import URL

from ._diagnostics import log_failure, log_request, log_response
from ._protocol import _Deadline, _TransportRequest, _TransportResponse
from .errors import (
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmNetworkError,
    GwmProtocolError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmTlsError,
)

_READ_CHUNK_BYTES = 64 * 1024
_MAX_DECIMAL_HEADER_LENGTH = 20
_SAFE_RESPONSE_HEADERS = frozenset({"content-type", "retry-after"})
_SKIP_AUTO_HEADERS = frozenset({"Accept", "Accept-Encoding", "User-Agent"})


class AiohttpTransport:
    """Execute fixed requests without redirects, cookies, proxies, or retries."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        owns_session: bool = False,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        _validate_response_limit(max_response_bytes)
        if type(owns_session) is not bool:
            raise ValueError("session_ownership_invalid")
        self._session = session
        self._owns_session = owns_session
        self._max_response_bytes = max_response_bytes
        self._closed = False
        self._closing = False
        self._close_lock = asyncio.Lock()

    @classmethod
    def create_owned(
        cls,
        *,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> Self:
        """Create a dedicated session inside the caller's running event loop."""

        _validate_response_limit(max_response_bytes)
        if cls is not AiohttpTransport:
            raise TypeError("transport_subclass_not_supported")
        session = aiohttp.ClientSession(
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            middlewares=(),
            raise_for_status=False,
            skip_auto_headers=_SKIP_AUTO_HEADERS,
            trace_configs=[],
            trust_env=False,
        )
        # aiohttp retries an idempotent request once by default. There is no
        # public per-request switch, so this dedicated session must opt out.
        session._retry_connection = False
        return cls(
            session,
            owns_session=True,
            max_response_bytes=max_response_bytes,
        )

    @property
    def closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> Self:
        if self._closed or self._closing:
            raise GwmClosedError()
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            try:
                if self._owns_session and not self._session.closed:
                    await self._session.close()
            except BaseException:
                self._closing = False
                raise
            self._closed = True
            self._closing = False

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        """Send one prepared request and retain only a bounded response body."""

        if type(request) is not _TransportRequest:
            raise GwmRoutePolicyError()
        operation = request.operation
        if type(deadline) is not _Deadline or not all(
            _valid_phase_timeout(value) for value in (connect_timeout, read_timeout)
        ):
            raise GwmConfigurationError(operation=operation)
        if self._closed or self._closing or self._session.closed:
            raise GwmClosedError(operation=operation)
        self._validate_session_policy(request)

        loop = asyncio.get_running_loop()
        remaining = deadline.remaining(loop.time())
        if remaining <= 0:
            raise GwmDeadlineExceededError(operation=operation)
        timeout = aiohttp.ClientTimeout(
            total=remaining,
            connect=min(connect_timeout, remaining),
            sock_read=min(read_timeout, remaining),
        )

        log_request(request)
        failure: GwmClientError | None = None
        try:
            async with self._session.request(
                request.method,
                URL(request.url, encoded=True),
                allow_redirects=False,
                auto_decompress=False,
                auth=None,
                cookies={},
                data=request.body,
                headers=request.headers,
                middlewares=(),
                params=None,
                proxy=None,
                proxy_auth=None,
                raise_for_status=False,
                skip_auto_headers=_SKIP_AUTO_HEADERS,
                ssl=request.ssl_context,
                timeout=timeout,
            ) as response:
                result = await self._read_response(response, operation=operation)
                log_response(request, result)
                return result
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            log_failure(request, error)
            raise
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            aiohttp.ClientSSLError,
            aiohttp.ServerFingerprintMismatch,
            ssl.CertificateError,
            ssl.SSLError,
        ):
            failure = GwmTlsError(operation=operation)
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, OSError):
            failure = GwmNetworkError(operation=operation)
        except aiohttp.ClientError:
            failure = GwmNetworkError(operation=operation)

        if failure is not None:
            log_failure(request, failure)
            raise failure
        raise GwmNetworkError(operation=operation)

    async def _read_response(
        self,
        response: aiohttp.ClientResponse,
        *,
        operation: str,
    ) -> _TransportResponse:
        if 300 <= response.status <= 399:
            raise GwmRedirectError(operation=operation)

        content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise GwmProtocolError(operation=operation)

        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            if (
                not content_length.isdecimal()
                or len(content_length) > _MAX_DECIMAL_HEADER_LENGTH
            ):
                raise GwmProtocolError(operation=operation)
            if int(content_length) > self._max_response_bytes:
                raise GwmResponseTooLargeError(operation=operation)

        body = bytearray()
        async for chunk in response.content.iter_chunked(_READ_CHUNK_BYTES):
            if not isinstance(chunk, bytes | bytearray):
                raise GwmProtocolError(operation=operation)
            if len(body) + len(chunk) > self._max_response_bytes:
                raise GwmResponseTooLargeError(operation=operation)
            body.extend(chunk)

        return _TransportResponse(
            status=response.status,
            headers=_selected_headers(response.headers),
            body=bytes(body),
        )

    def _validate_session_policy(self, request: _TransportRequest) -> None:
        operation = request.operation
        if isinstance(self._session, aiohttp.ClientSession) and (
            type(self._session) is not aiohttp.ClientSession
            or type(self._session.connector) is not aiohttp.TCPConnector
        ):
            raise GwmConfigurationError(operation=operation)
        if self._session.trust_env:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_auth", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_proxy", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_default_proxy_auth", None) is not None:
            raise GwmConfigurationError(operation=operation)
        if self._session.headers:
            raise GwmConfigurationError(operation=operation)
        if not isinstance(self._session.cookie_jar, aiohttp.DummyCookieJar):
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_raise_for_status", None) is not False:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_retry_connection", None) is not False:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_middlewares", None) != ():
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_trace_configs", None) not in ([], ()):
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_request_class", None) is not aiohttp.ClientRequest:
            raise GwmConfigurationError(operation=operation)
        if getattr(self._session, "_response_class", None) is not aiohttp.ClientResponse:
            raise GwmConfigurationError(operation=operation)


def _selected_headers(headers: Mapping[str, Any]) -> Mapping[str, str]:
    return {
        str(name).lower(): str(value)
        for name, value in headers.items()
        if str(name).lower() in _SAFE_RESPONSE_HEADERS
    }


def _validate_response_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("response_limit_invalid")


def _valid_phase_timeout(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and math.isfinite(value)
        and value > 0
    )
