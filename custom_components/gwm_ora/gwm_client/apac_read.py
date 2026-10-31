"""Isolated APAC reads and climate commands with injected transport and TLS."""

from __future__ import annotations

import asyncio
import ssl
import uuid
from dataclasses import dataclass, field
from typing import Literal

from ._protocol import _AsyncTransport, _Deadline
from .apac_climate import climate_payload
from .apac_material import ApacMaterial
from .apac_policy import validate_apac_country
from .apac_request import prepare_apac_request
from .client import _decode_envelope
from .commands import ClimateCommand, RemoteCommandAcceptance, RemoteCommandResultItem, parse_remote_command_results
from .errors import GwmClosedError, GwmDeadlineExceededError, GwmSchemaError
from .models import (
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    VehicleIdentifier,
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)


@dataclass(frozen=True, slots=True)
class ApacReadSession:
    """Private account-bound session supplied by the APAC authentication flow."""

    device_id: str = field(repr=False)
    access_token: str = field(repr=False)
    app_ssl_context: ssl.SSLContext = field(repr=False)
    country: str

    def __post_init__(self) -> None:
        """Reject countries outside the app-listed APAC family."""
        validate_apac_country(self.country)


class ApacReadClient:
    """Discovery, status and limited climate operations on a scoped transport."""

    def __init__(
        self,
        *,
        material: ApacMaterial,
        session: ApacReadSession,
        transport: _AsyncTransport,
        owns_transport: bool = False,
    ) -> None:
        """Retain a private session and caller-owned read transport."""
        if (
            type(material) is not ApacMaterial
            or type(session) is not ApacReadSession
            or type(owns_transport) is not bool
        ):
            raise ValueError("apac_session_invalid")
        self._material = material
        self._session = session
        self._transport = transport
        self._owns_transport = owns_transport
        self._closed = False
        self._closing = False
        self._lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()

    @property
    def authenticated(self) -> bool:
        """Report whether this private read session is still usable locally."""
        return not self._closed and not self._closing

    def replace_session(self, session: ApacReadSession) -> None:
        """Accept a refreshed session only for the same country and device."""
        if (
            type(session) is not ApacReadSession
            or session.country != self._session.country
            or session.device_id != self._session.device_id
            or self._closed
            or self._closing
        ):
            raise ValueError("apac_session_invalid")
        self._session = session

    async def aclose(self) -> None:
        """Drain active reads and close only owned resources, allowing retries."""
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            try:
                async with self._lock:
                    if self._owns_transport:
                        await self._transport.aclose()
                    self._closed = True
            except BaseException:
                self._closing = False
                raise
            self._closing = False

    async def _read(
        self,
        operation: Literal["acquire_vehicles", "get_last_status", "get_vehicle_basics"],
        vehicle_id: str | None = None,
    ) -> object:
        """Execute one allowlisted vehicle read with a bounded deadline."""
        if operation not in {"acquire_vehicles", "get_last_status", "get_vehicle_basics"}:
            raise ValueError("apac_operation_not_supported")
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + 30.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                if self._closed or self._closing:
                    raise GwmClosedError(operation=operation)
                request = prepare_apac_request(
                    operation=operation,
                    material=self._material,
                    ssl_context=self._session.app_ssl_context,
                    device_id=self._session.device_id,
                    access_token=self._session.access_token,
                    country=self._session.country,
                    vehicle_id=vehicle_id,
                )
                response = await self._transport.execute(
                    request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0
                )
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

    async def send_climate_command(
        self, command: ClimateCommand, *, security_password_hash: str
    ) -> RemoteCommandAcceptance:
        """Send a single climate request, without replaying uncertain writes."""
        sequence = uuid.uuid4().hex + "1234"
        payload = climate_payload(command, security_password_hash=security_password_hash, sequence_number=sequence)
        await self._climate_exchange("send_climate_command", command.identifier, body=payload)
        return RemoteCommandAcceptance(sequence)

    async def get_remote_command_results(
        self, identifier: VehicleIdentifier, command_id: str
    ) -> tuple[RemoteCommandResultItem, ...]:
        """Read results for an accepted climate request."""
        data = await self._climate_exchange("get_remote_command_result", identifier, command_id=command_id)
        try:
            return parse_remote_command_results(data, allow_integer_strings=True)
        except (TypeError, ValueError):
            raise GwmSchemaError(operation="get_remote_command_result") from None

    async def _climate_exchange(
        self, operation: str, identifier: VehicleIdentifier, *,
        body: dict[str, object] | None = None, command_id: str | None = None,
    ) -> object:
        """Perform one bounded APAC climate exchange using the owned session."""
        if type(identifier) is not VehicleIdentifier or self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        deadline = _Deadline(asyncio.get_running_loop().time() + 30.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                if self._closed or self._closing:
                    raise GwmClosedError(operation=operation)
                request = prepare_apac_request(
                    operation=operation, material=self._material, ssl_context=self._session.app_ssl_context,
                    device_id=self._session.device_id, access_token=self._session.access_token,
                    country=self._session.country, vehicle_id=identifier.value, body=body, command_id=command_id,
                )
                response = await self._transport.execute(request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0)
                return _decode_envelope(response, operation=operation)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None

    async def get_last_status(self, vehicle_id: str | VehicleIdentifier) -> CloudVehicleStatus:
        """Read the last reported status for one vehicle."""
        data = await self._read(
            "get_last_status", vehicle_id.value if isinstance(vehicle_id, VehicleIdentifier) else vehicle_id
        )
        try:
            return parse_cloud_vehicle_status(data, allow_stringified_numbers=True, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="get_last_status") from None

    async def get_vehicle_basics(self, vehicle_id: str | VehicleIdentifier) -> CloudVehicleBasics:
        """Read supported vehicle configuration values."""
        data = await self._read(
            "get_vehicle_basics", vehicle_id.value if isinstance(vehicle_id, VehicleIdentifier) else vehicle_id
        )
        try:
            return parse_cloud_vehicle_basics(data, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="get_vehicle_basics") from None
