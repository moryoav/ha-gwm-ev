"""Synthetic overseas HTTP responses and recording transports."""
from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Mapping, Sequence
from typing import Any

from custom_components.gwm_ora.gwm_client import Region, create_gwm_ssl_context
from custom_components.gwm_ora.gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse


class _QueueTransport:
    def __init__(
        self,
        responses: Sequence[_TransportResponse | BaseException] | None = None,
        *,
        delay: float = 0,
        hang: bool = False,
    ) -> None:
        self.responses = list(responses or [])
        self.requests: list[_TransportRequest] = []
        self.deadlines: list[_Deadline] = []
        self.delay = delay
        self.hang = hang
        self.entered = asyncio.Event()
        self.active = 0
        self.max_active = 0
        self.close_calls = 0

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        del connect_timeout, read_timeout
        self.requests.append(request)
        self.deadlines.append(deadline)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            if not self.responses:
                raise AssertionError("unexpected request")
            response = self.responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        self.close_calls += 1

def _response(
    data: object = ...,
    *,
    code: str = "000000",
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    description: str | None = None,
) -> _TransportResponse:
    envelope: dict[str, object] = {"code": code}
    if description is not None:
        envelope["description"] = description
    if data is not ...:
        envelope["data"] = data
    return _TransportResponse(
        status=status,
        headers={} if headers is None else headers,
        body=json.dumps(envelope, separators=(",", ":")).encode(),
    )

def _default_context() -> ssl.SSLContext:
    return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


class _RecordingTransport:
    def __init__(self, responses: list[_TransportResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[_TransportRequest] = []

    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse:
        assert deadline.remaining(0) > 0
        assert connect_timeout > 0
        assert read_timeout > 0
        self.requests.append(request)
        return self.responses.pop(0)

    async def aclose(self) -> None:
        return None

def _context(region: Region) -> ssl.SSLContext:
    return ssl.create_default_context() if region is Region.ANZ else create_gwm_ssl_context()

def _body(request: _TransportRequest) -> dict[str, Any]:
    assert request.body is not None
    return json.loads(request.body)
