"""Private immutable wire contracts shared by client and transport."""

from __future__ import annotations

import math
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

_OPERATION_ALIAS = re.compile(r"[a-z][a-z0-9_]{0,63}")
_HEADER_NAME = re.compile(r"[-!#$%&'*+.^_`|~0-9A-Za-z]+")
_JSON_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/json; charset=utf-8",
    }
)
_MAX_REQUEST_BODY_BYTES = 512 * 1024
_FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
    }
)


@dataclass(frozen=True, slots=True)
class _TransportRequest:
    operation: str
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    ssl_context: ssl.SSLContext = field(repr=False)
    method: str = "GET"
    body: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if _OPERATION_ALIAS.fullmatch(self.operation) is None:
            raise ValueError("operation_invalid")
        if self.method not in {"GET", "POST"}:
            raise ValueError("method_not_allowed")
        _validate_https_url(self.url)
        if (
            not isinstance(self.ssl_context, ssl.SSLContext)
            or not self.ssl_context.check_hostname
            or self.ssl_context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError("tls_context_invalid")

        copied: dict[str, str] = {}
        normalized_names: set[str] = set()
        for name, value in self.headers.items():
            normalized_name = name.lower() if isinstance(name, str) else ""
            if (
                not isinstance(name, str)
                or _HEADER_NAME.fullmatch(name) is None
                or normalized_name in _FORBIDDEN_HEADERS
                or normalized_name in normalized_names
                or not isinstance(value, str)
                or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
                or "\r" in value
                or "\n" in value
            ):
                raise ValueError("header_invalid")
            normalized_names.add(normalized_name)
            copied[name] = value

        content_type = next(
            (value for name, value in copied.items() if name.lower() == "content-type"),
            None,
        )
        if self.method == "GET":
            if self.body is not None:
                raise ValueError("request_body_invalid")
            if content_type is not None:
                raise ValueError("header_invalid")
        else:
            if (
                not isinstance(self.body, bytes)
                or not self.body
                or len(self.body) > _MAX_REQUEST_BODY_BYTES
            ):
                raise ValueError("request_body_invalid")
            if content_type not in _JSON_CONTENT_TYPES:
                raise ValueError("header_invalid")
        object.__setattr__(self, "headers", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class _TransportResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int) or not 100 <= self.status <= 599:
            raise ValueError("http_status_invalid")
        if not isinstance(self.body, bytes):
            raise ValueError("response_body_invalid")
        object.__setattr__(
            self,
            "headers",
            MappingProxyType(
                {
                    str(name).lower(): str(value)
                    for name, value in self.headers.items()
                    if str(name).lower() in {"content-type", "retry-after"}
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class _Deadline:
    expires_at: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, int | float)
            or not math.isfinite(self.expires_at)
        ):
            raise ValueError("deadline_invalid")

    def remaining(self, now: float) -> float:
        return max(0.0, self.expires_at - now)


class _AsyncTransport(Protocol):
    async def execute(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _TransportResponse: ...

    async def aclose(self) -> None: ...


def _validate_https_url(url: str) -> None:
    if not isinstance(url, str):
        raise ValueError("url_invalid")
    invalid = False
    try:
        url.encode("ascii")
        parsed = urlsplit(url)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        invalid = True
        parsed = urlsplit("")
        port = None
    if invalid:
        raise ValueError("url_invalid")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "\\" in url
        or any(character.isspace() for character in url)
    ):
        raise ValueError("url_invalid")
