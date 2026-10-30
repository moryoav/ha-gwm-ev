"""An isolated APAC vehicle-read client with injected transport and TLS.

This draft does not manage login, enrollment, persistence or Home Assistant.
It exposes no vehicle-control or charging-write method.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Literal

from ._protocol import _AsyncTransport, _Deadline
from .apac_material import ApacMaterial
from .apac_policy import validate_apac_country
from .apac_request import prepare_apac_request
from .client import _decode_envelope
from .errors import GwmDeadlineExceededError, GwmSchemaError
from .models import (
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)


@dataclass(frozen=True, slots=True)
class ApacReadSession:
    """Private pre-authenticated session supplied by the future auth layer."""

    device_id: str = field(repr=False)
    access_token: str = field(repr=False)
    app_ssl_context: ssl.SSLContext = field(repr=False)
    country: str

    def __post_init__(self) -> None:
        """Reject countries outside the app-listed APAC family."""
        validate_apac_country(self.country)


class ApacReadClient:
    """Only discovery and status reads, with a caller-owned transport."""

    def __init__(self, *, material: ApacMaterial, session: ApacReadSession, transport: _AsyncTransport) -> None:
        if type(material) is not ApacMaterial or type(session) is not ApacReadSession:
            raise ValueError("apac_session_invalid")
        self._material = material
        self._session = session
        self._transport = transport
        self._lock = asyncio.Lock()

    async def _read(
        self,
        operation: Literal["acquire_vehicles", "get_last_status", "get_vehicle_basics"],
        vehicle_id: str | None = None,
    ) -> object:
        if operation not in {"acquire_vehicles", "get_last_status", "get_vehicle_basics"}:
            raise ValueError("apac_operation_not_supported")
        request = prepare_apac_request(
            operation=operation,
            material=self._material,
            ssl_context=self._session.app_ssl_context,
            device_id=self._session.device_id,
            access_token=self._session.access_token,
            country=self._session.country,
            vehicle_id=vehicle_id,
        )
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + 30.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                response = await self._transport.execute(request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0)
                return _decode_envelope(response, operation=operation)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
        """Discover account vehicles without sending a control request."""
        data = await self._read("acquire_vehicles")
        try:
            return parse_cloud_vehicles(data, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="acquire_vehicles") from None

    async def get_last_status(self, vehicle_id: str) -> CloudVehicleStatus:
        """Read the last reported status for one vehicle."""
        data = await self._read("get_last_status", vehicle_id)
        try:
            return parse_cloud_vehicle_status(data, allow_stringified_numbers=True, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="get_last_status") from None

    async def get_vehicle_basics(self, vehicle_id: str) -> CloudVehicleBasics:
        """Read supported vehicle configuration values."""
        data = await self._read("get_vehicle_basics", vehicle_id)
        try:
            return parse_cloud_vehicle_basics(data, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="get_vehicle_basics") from None
