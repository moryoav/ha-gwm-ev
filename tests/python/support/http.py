"""Controllable aiohttp boundary without network access."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from typing import Any

import aiohttp

from custom_components.gwm_ora.gwm_client._protocol import _Deadline


class _FakeContent:
    def __init__(self, chunks: list[object]) -> None:
        self.chunks = chunks

    async def iter_chunked(self, size: int) -> AsyncIterator[object]:
        assert size == 64 * 1024
        for chunk in self.chunks:
            yield chunk

class _FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        chunks: list[object] | None = None,
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self.content = _FakeContent(chunks or [b"{}"])
        self.exited = False

class _FakeRequestContext:
    def __init__(
        self,
        response: _FakeResponse | None,
        *,
        error: BaseException | None = None,
        wait: bool = False,
    ) -> None:
        self.response = response
        self.error = error
        self.wait = wait

    async def __aenter__(self) -> Any:
        if self.wait:
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
        wait: bool = False,
    ) -> None:
        self.response = response or _FakeResponse()
        self.error = error
        self.wait = wait
        self.closed = False
        self.close_calls = 0
        self.trust_env = False
        self.auto_decompress = False
        self.skip_auto_headers = frozenset({"Accept", "Accept-Encoding", "User-Agent"})
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
        return _FakeRequestContext(self.response, error=self.error, wait=self.wait)

    async def close(self) -> None:
        self.close_calls += 1
        self.closed = True

def _deadline() -> _Deadline:
    return _Deadline(asyncio.get_running_loop().time() + 10)
