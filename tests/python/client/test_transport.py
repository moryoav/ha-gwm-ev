"""Offline transport policy, lifecycle, timeout, and cancellation tests."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator, Mapping
from typing import Any, cast

import aiohttp
import pytest
from yarl import URL

from gwm_client._protocol import _Deadline, _TransportRequest
from gwm_client.errors import (
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
from gwm_client.transport import AiohttpTransport

SENSITIVE = "SENSITIVE-transport-material-019fea1b"


class _FakeCookieJar:
    def __init__(self, cookies: Mapping[str, str] | None = None) -> None:
        self.cookies = dict(cookies or {})

    def filter_cookies(self, url: URL) -> Mapping[str, str]:
        assert isinstance(url, URL)
        return self.cookies


class _FakeContent:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        wait_after: int | None = None,
    ) -> None:
        self.chunks = chunks
        self.wait_after = wait_after
        self.waiting = asyncio.Event()

    async def iter_chunked(self, size: int) -> AsyncIterator[bytes]:
        assert size == 64 * 1024
        for index, chunk in enumerate(self.chunks):
            yield chunk
            if self.wait_after == index:
                self.waiting.set()
                await asyncio.Event().wait()


class _FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        chunks: list[bytes] | None = None,
        wait_after: int | None = None,
    ) -> None:
        self.status = status
        self.headers = dict(headers or {})
        self.content = _FakeContent(chunks or [b"{}"], wait_after=wait_after)
        self.exited = False


class _FakeRequestContext:
    def __init__(
        self,
        response: _FakeResponse | None,
        *,
        error: BaseException | None = None,
        wait_on_enter: bool = False,
    ) -> None:
        self.response = response
        self.error = error
        self.wait_on_enter = wait_on_enter

    async def __aenter__(self) -> Any:
        if self.wait_on_enter:
            await asyncio.Event().wait()
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response

    async def __aexit__(self, *_exc_info: object) -> None:
        if self.response is not None:
            self.response.exited = True


class _FakeSession:
    def __init__(
        self,
        response: _FakeResponse | None = None,
        *,
        error: BaseException | None = None,
        wait_on_enter: bool = False,
        wait_on_close: bool = False,
    ) -> None:
        self.response = response or _FakeResponse()
        self.error = error
        self.wait_on_enter = wait_on_enter
        self.closed = False
        self.close_calls = 0
        self.close_started = asyncio.Event()
        self.close_release = asyncio.Event()
        self.wait_on_close = wait_on_close
        self.trust_env = False
        self.headers: dict[str, str] = {}
        self.cookie_jar = aiohttp.DummyCookieJar()
        self._default_auth: object | None = None
        self._default_proxy: object | None = None
        self._default_proxy_auth: object | None = None
        self._raise_for_status = False
        self._retry_connection = False
        self._middlewares: tuple[object, ...] = ()
        self._trace_configs: list[object] = []
        self._request_class = aiohttp.ClientRequest
        self._response_class = aiohttp.ClientResponse
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def request(self, *args: object, **kwargs: object) -> _FakeRequestContext:
        self.calls.append((args, kwargs))
        return _FakeRequestContext(
            self.response,
            error=self.error,
            wait_on_enter=self.wait_on_enter,
        )

    async def close(self) -> None:
        self.close_calls += 1
        self.close_started.set()
        if self.wait_on_close:
            await self.close_release.wait()
        self.closed = True


def _context() -> ssl.SSLContext:
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


def _request(*, context: ssl.SSLContext | None = None) -> _TransportRequest:
    return _TransportRequest(
        operation="acquire_vehicles",
        url="https://example.invalid/app-api/api/v1.0/globalapp/vehicle/acquireVehicles",
        headers={"Accept": "application/json", "accessToken": "SYNTHETIC-TOKEN"},
        ssl_context=context or _context(),
    )


def _post_request(
    *,
    body: bytes = b'{"account":"synthetic@example.invalid"}',
    context: ssl.SSLContext | None = None,
) -> _TransportRequest:
    return _TransportRequest(
        operation="login",
        method="POST",
        url="https://example.invalid/app-api/api/v2.0/userAuth/loginWithPassword",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        },
        ssl_context=context or _context(),
        body=body,
    )


def _deadline(seconds: float = 10) -> _Deadline:
    return _Deadline(asyncio.get_running_loop().time() + seconds)


@pytest.mark.asyncio
async def test_transport_sends_exact_encoded_request_with_safe_options() -> None:
    context = _context()
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "application/json", "X-Sensitive": SENSITIVE},
        chunks=[b'{"code":', b'"000000"}'],
    )
    session = _FakeSession(response)
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session), max_response_bytes=64)

    result = await transport.execute(
        _request(context=context),
        deadline=_deadline(),
        connect_timeout=3,
        read_timeout=4,
    )

    assert result.status == 200
    assert result.body == b'{"code":"000000"}'
    assert result.headers == {"content-type": "application/json"}
    assert response.exited
    assert len(session.calls) == 1
    args, kwargs = session.calls[0]
    assert args[0] == "GET"
    assert isinstance(args[1], URL)
    assert str(args[1]) == _request().url
    assert kwargs["allow_redirects"] is False
    assert kwargs["auto_decompress"] is False
    assert kwargs["auth"] is None
    assert kwargs["cookies"] == {}
    assert kwargs["data"] is None
    assert kwargs["middlewares"] == ()
    assert kwargs["params"] is None
    assert kwargs["proxy"] is None
    assert kwargs["proxy_auth"] is None
    assert kwargs["raise_for_status"] is False
    assert kwargs["ssl"] is context
    assert kwargs["skip_auto_headers"] == {"Accept", "Accept-Encoding", "User-Agent"}
    assert "json" not in kwargs


@pytest.mark.asyncio
async def test_transport_sends_exact_post_bytes_without_json_or_retry() -> None:
    body = b'{"password":"SENSITIVE-request-body"}'
    session = _FakeSession()
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session))

    result = await transport.execute(
        _post_request(body=body),
        deadline=_deadline(),
        connect_timeout=3,
        read_timeout=4,
    )

    assert result.status == 200
    assert len(session.calls) == 1
    args, kwargs = session.calls[0]
    assert args[0] == "POST"
    assert kwargs["data"] is body
    assert "json" not in kwargs
    assert session._retry_connection is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("chunks", "content_length", "error"),
    [
        ([b"1234", b"5678"], None, None),
        ([b"1234", b"56789"], None, GwmResponseTooLargeError),
        ([b"small"], "9", GwmResponseTooLargeError),
        ([b"small"], "invalid", GwmProtocolError),
    ],
)
async def test_response_limit_is_streamed_and_content_length_is_not_trusted(
    chunks: list[bytes],
    content_length: str | None,
    error: type[Exception] | None,
) -> None:
    headers = {} if content_length is None else {"Content-Length": content_length}
    response = _FakeResponse(headers=headers, chunks=chunks)
    session = _FakeSession(response)
    transport = AiohttpTransport(
        cast(aiohttp.ClientSession, session),
        max_response_bytes=8,
    )

    if error is None:
        result = await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )
        assert result.body == b"12345678"
    else:
        with pytest.raises(error):
            await transport.execute(
                _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
            )
    assert response.exited


@pytest.mark.asyncio
async def test_redirect_and_compression_fail_closed_without_leaking_headers() -> None:
    redirect = _FakeResponse(status=302, headers={"Location": f"https://{SENSITIVE}.invalid"})
    transport = AiohttpTransport(cast(aiohttp.ClientSession, _FakeSession(redirect)))
    with pytest.raises(GwmRedirectError) as raised:
        await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )
    assert SENSITIVE not in repr(raised.value)
    assert redirect.exited

    compressed = _FakeResponse(headers={"Content-Encoding": "gzip"})
    transport = AiohttpTransport(cast(aiohttp.ClientSession, _FakeSession(compressed)))
    with pytest.raises(GwmProtocolError):
        await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )
    assert compressed.exited


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "mapped"),
    [
        (aiohttp.ClientConnectionError(SENSITIVE), GwmNetworkError),
        (ssl.SSLError(SENSITIVE), GwmTlsError),
        (TimeoutError(SENSITIVE), GwmDeadlineExceededError),
    ],
)
async def test_library_failures_are_mapped_without_source_context(
    source: BaseException,
    mapped: type[Exception],
) -> None:
    session = _FakeSession(error=source)
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session))

    with pytest.raises(mapped) as raised:
        await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )

    assert SENSITIVE not in str(raised.value)
    assert SENSITIVE not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_external_cancellation_propagates_and_closes_response() -> None:
    response = _FakeResponse(chunks=[b"first"], wait_after=0)
    transport = AiohttpTransport(cast(aiohttp.ClientSession, _FakeSession(response)))
    task = asyncio.create_task(
        transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )
    )
    await response.content.waiting.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert response.exited


@pytest.mark.asyncio
async def test_expired_deadline_never_reaches_session() -> None:
    session = _FakeSession()
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session))

    with pytest.raises(GwmDeadlineExceededError):
        await transport.execute(
            _request(),
            deadline=_Deadline(asyncio.get_running_loop().time() - 1),
            connect_timeout=1,
            read_timeout=1,
        )
    assert session.calls == []


@pytest.mark.asyncio
async def test_forged_request_and_invalid_phase_timeout_never_reach_session() -> None:
    class ForgedRequest:
        operation = "acquire_vehicles"
        method = "POST"
        url = _request().url
        headers: Mapping[str, str] = {}
        ssl_context = _context()

    session = _FakeSession()
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session))
    with pytest.raises(GwmRoutePolicyError):
        await transport.execute(
            cast(_TransportRequest, ForgedRequest()),
            deadline=_deadline(),
            connect_timeout=1,
            read_timeout=1,
        )
    with pytest.raises(GwmConfigurationError):
        await transport.execute(
            _request(),
            deadline=_deadline(),
            connect_timeout=0,
            read_timeout=1,
        )
    assert session.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe",
    [
        "trust_env",
        "auth",
        "proxy",
        "proxy_auth",
        "cookie",
        "header",
        "retry",
        "raise_for_status",
        "middleware",
        "trace",
        "request_class",
        "response_class",
    ],
)
async def test_unsafe_external_session_policy_is_rejected_before_send(unsafe: str) -> None:
    session = _FakeSession()
    if unsafe == "trust_env":
        session.trust_env = True
    elif unsafe == "auth":
        session._default_auth = object()
    elif unsafe == "proxy":
        session._default_proxy = object()
    elif unsafe == "proxy_auth":
        session._default_proxy_auth = object()
    elif unsafe == "cookie":
        session.cookie_jar = _FakeCookieJar({"session": SENSITIVE})
    elif unsafe == "header":
        session.headers["X-Arbitrary-Secret"] = SENSITIVE
    elif unsafe == "retry":
        session._retry_connection = True
    elif unsafe == "raise_for_status":
        session._raise_for_status = True
    elif unsafe == "middleware":
        session._middlewares = (object(),)
    elif unsafe == "trace":
        session._trace_configs = [object()]
    elif unsafe == "request_class":
        session._request_class = object
    else:
        session._response_class = object
    transport = AiohttpTransport(cast(aiohttp.ClientSession, session))

    with pytest.raises(GwmConfigurationError) as raised:
        await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )
    assert session.calls == []
    assert SENSITIVE not in repr(raised.value)


@pytest.mark.asyncio
async def test_real_external_cookie_jar_is_rejected_before_network() -> None:
    session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    session._retry_connection = False
    try:
        transport = AiohttpTransport(session)
        with pytest.raises(GwmConfigurationError):
            await transport.execute(
                _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
            )
    finally:
        await session.close()


@pytest.mark.asyncio
async def test_custom_connector_is_rejected_before_network() -> None:
    class CustomConnector(aiohttp.TCPConnector):
        pass

    session = aiohttp.ClientSession(
        connector=CustomConnector(),
        cookie_jar=aiohttp.DummyCookieJar(),
    )
    session._retry_connection = False
    try:
        transport = AiohttpTransport(session)
        with pytest.raises(GwmConfigurationError):
            await transport.execute(
                _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
            )
    finally:
        await session.close()


@pytest.mark.asyncio
async def test_transport_lifecycle_distinguishes_owned_and_external_sessions() -> None:
    owned_session = _FakeSession()
    owned = AiohttpTransport(
        cast(aiohttp.ClientSession, owned_session),
        owns_session=True,
    )
    await owned.aclose()
    await owned.aclose()
    assert owned.closed
    assert owned_session.close_calls == 1
    with pytest.raises(GwmClosedError):
        await owned.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )

    external_session = _FakeSession()
    external = AiohttpTransport(cast(aiohttp.ClientSession, external_session))
    await external.aclose()
    assert external_session.close_calls == 0
    assert not external_session.closed


@pytest.mark.asyncio
async def test_cancelled_owned_close_can_be_retried() -> None:
    session = _FakeSession(wait_on_close=True)
    transport = AiohttpTransport(
        cast(aiohttp.ClientSession, session),
        owns_session=True,
    )
    closing = asyncio.create_task(transport.aclose())
    await session.close_started.wait()
    closing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closing

    assert not transport.closed
    session.wait_on_close = False
    await transport.aclose()
    assert transport.closed
    assert session.closed
    assert session.close_calls == 2


@pytest.mark.asyncio
async def test_factory_prevalidates_limits_subclasses_and_ownership() -> None:
    class UnsupportedTransport(AiohttpTransport):
        pass

    with pytest.raises(ValueError, match="^response_limit_invalid$"):
        AiohttpTransport.create_owned(max_response_bytes=0)
    with pytest.raises(TypeError, match="^transport_subclass_not_supported$"):
        UnsupportedTransport.create_owned()
    with pytest.raises(ValueError, match="^session_ownership_invalid$"):
        AiohttpTransport(
            cast(aiohttp.ClientSession, _FakeSession()),
            owns_session=1,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_owned_factory_uses_isolated_session_defaults() -> None:
    transport = AiohttpTransport.create_owned(max_response_bytes=32)
    try:
        session = transport._session
        assert not session.trust_env
        assert not session.auto_decompress
        assert isinstance(session.cookie_jar, aiohttp.DummyCookieJar)
        assert not session.headers
        assert session._retry_connection is False
        assert session._middlewares == ()
        assert session._trace_configs == []
    finally:
        await transport.aclose()
    assert transport.closed
    assert session.closed


@pytest.mark.asyncio
async def test_oversized_decimal_content_length_is_protocol_error() -> None:
    response = _FakeResponse(headers={"Content-Length": "9" * 5000})
    transport = AiohttpTransport(cast(aiohttp.ClientSession, _FakeSession(response)))

    with pytest.raises(GwmProtocolError):
        await transport.execute(
            _request(), deadline=_deadline(), connect_timeout=1, read_timeout=1
        )


def test_wire_request_rejects_unsupported_method_unsafe_headers_origins_and_tls() -> None:
    context = _context()
    context.check_hostname = False
    with pytest.raises(ValueError, match="^tls_context_invalid$"):
        _request(context=context)
    with pytest.raises(ValueError, match="^method_not_allowed$"):
        _TransportRequest(
            operation="request",
            method="PUT",
            url="https://example.invalid/read",
            headers={},
            ssl_context=_context(),
        )
    with pytest.raises(ValueError, match="^url_invalid$"):
        _TransportRequest(
            operation="request",
            url="https://user:secret@example.invalid/read",
            headers={},
            ssl_context=_context(),
        )
    with pytest.raises(ValueError, match="^header_invalid$"):
        _TransportRequest(
            operation="request",
            url="https://example.invalid/read",
            headers={"Cookie": SENSITIVE},
            ssl_context=_context(),
        )


def test_wire_request_enforces_safe_get_and_post_body_contracts() -> None:
    sensitive = b'SENSITIVE-request-body-019fea1b'
    request = _post_request(body=sensitive)
    assert request.body is sensitive
    assert sensitive.decode() not in repr(request)
    assert _post_request(body=b"x" * (512 * 1024)).body == b"x" * (512 * 1024)
    assert _TransportRequest(
        operation="request",
        method="POST",
        url="https://example.invalid/read",
        headers={"content-type": "application/json; charset=utf-8"},
        ssl_context=_context(),
        body=b"{}",
    ).body == b"{}"
    assert _TransportRequest(
        operation="request",
        method="POST",
        url="https://example.invalid/read",
        headers={"content-type": "application/json"},
        ssl_context=_context(),
        body=b"{}",
    ).body == b"{}"

    invalid_requests = [
        {
            "method": "GET",
            "headers": {},
            "body": b"{}",
        },
        {
            "method": "GET",
            "headers": {"content-type": "application/json; charset=utf-8"},
            "body": None,
        },
        {
            "method": "POST",
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": None,
        },
        {
            "method": "POST",
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": b"",
        },
        {
            "method": "POST",
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": bytearray(b"{}"),
        },
        {
            "method": "POST",
            "headers": {},
            "body": b"{}",
        },
        {
            "method": "POST",
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": b"x" * (512 * 1024 + 1),
        },
    ]
    for values in invalid_requests:
        with pytest.raises(ValueError):
            _TransportRequest(
                operation="request",
                url="https://example.invalid/read",
                ssl_context=_context(),
                **values,  # type: ignore[arg-type]
            )


def test_wire_request_rejects_headers_duplicated_case_insensitively() -> None:
    with pytest.raises(ValueError, match="^header_invalid$"):
        _TransportRequest(
            operation="request",
            method="POST",
            url="https://example.invalid/read",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "content-type": "application/json; charset=utf-8",
            },
            ssl_context=_context(),
            body=b"{}",
        )

    with pytest.raises(ValueError, match="^header_invalid$"):
        _TransportRequest(
            operation="request",
            url="https://example.invalid/read",
            headers={"X-Trace": "one", "x-trace": "two"},
            ssl_context=_context(),
        )
