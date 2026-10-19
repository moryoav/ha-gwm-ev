"""Validated configuration for the HA-independent async client."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .regions import Region, get_region_protocol

_DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_ALLOWED_RESPONSE_BYTES = 16 * 1024 * 1024
_ANZ_AUTHENTICATION_METHODS = frozenset({"legacy_v1", "current_v2"})


@dataclass(frozen=True, slots=True)
class RequestTimeouts:
    """One monotonic request budget and its socket phase ceilings."""

    total: float = 30.0
    connect: float = 10.0
    read: float = 20.0

    def __post_init__(self) -> None:
        values = (self.total, self.connect, self.read)
        if any(
            isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) or value <= 0
            for value in values
        ):
            raise ValueError("timeouts_invalid")
        if self.connect > self.total or self.read > self.total:
            raise ValueError("timeouts_invalid")


@dataclass(frozen=True, slots=True)
class GwmClientConfig:
    """Stable non-secret client configuration."""

    region: Region | str
    timeouts: RequestTimeouts = field(default_factory=RequestTimeouts)
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES
    anz_authentication_method: str | None = None

    def __post_init__(self) -> None:
        if type(self.timeouts) is not RequestTimeouts:
            raise ValueError("timeouts_invalid")
        try:
            normalized_region = get_region_protocol(self.region).region
        except (TypeError, ValueError) as error:
            raise ValueError("region_invalid") from error
        object.__setattr__(self, "region", normalized_region)
        authentication_method = self.anz_authentication_method
        if normalized_region is Region.ANZ:
            if authentication_method in (None, ""):
                authentication_method = "legacy_v1"
            if authentication_method not in _ANZ_AUTHENTICATION_METHODS:
                raise ValueError("anz_authentication_method_invalid")
            object.__setattr__(self, "anz_authentication_method", authentication_method)
        elif authentication_method not in (None, ""):
            raise ValueError("anz_authentication_method_invalid")
        else:
            object.__setattr__(self, "anz_authentication_method", None)
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 0 < self.max_response_bytes <= _MAX_ALLOWED_RESPONSE_BYTES
        ):
            raise ValueError("response_limit_invalid")
