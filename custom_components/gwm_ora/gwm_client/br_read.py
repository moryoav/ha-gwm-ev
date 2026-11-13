"""Isolated BR client: vehicle discovery and last status, plus the charging-plan write.

Only ``acquire_vehicles``, ``get_last_status`` and ``set_charging_plan`` exist; the
write is allowed only when the cloud client's charging opt-in is on. There is no
command, climate, lock or ``sendCmd`` path in this region.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from ._protocol import _AsyncTransport, _Deadline
from .br_auth_client import BrAuthClient, BrSession, BrTokens
from .br_identity import BrCredentials
from .br_material import create_br_ssl_context, load_br_material
from .br_request import GwmBrCredentialError, decode_br_envelope, prepare_br_request
from .charging import ChargingPlanCommand
from .errors import (
    GwmAuthenticationError,
    GwmClosedError,
    GwmDeadlineExceededError,
    GwmSchemaError,
)
from .models import (
    CloudVehicle,
    CloudVehicleStatus,
    VehicleIdentifier,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)
from .transport import AiohttpTransport


class BrReadClient:
    """Discovery and status over an injected transport, TLS context and session."""

    def __init__(
        self,
        *,
        session: BrSession,
        ssl_context: ssl.SSLContext,
        transport: _AsyncTransport,
        owns_transport: bool = False,
    ) -> None:
        """Retain caller-owned dependencies; nothing is sent until a read."""
        if type(session) is not BrSession or type(owns_transport) is not bool:
            raise ValueError("br_session_invalid")
        self._session = session
        self._ssl_context = ssl_context
        self._transport = transport
        self._owns_transport = owns_transport
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def session(self) -> BrSession:
        """The session, so the caller can persist tokens privately."""
        return self._session

    async def aclose(self) -> None:
        """Close only an owned transport; safe to repeat."""
        async with self._lock:
            if not self._closed:
                if self._owns_transport:
                    await self._transport.aclose()
                self._closed = True

    async def _read(
        self,
        operation: str,
        vehicle_id: str | None = None,
        plan: ChargingPlanCommand | None = None,
    ) -> object:
        """One bounded read; on a rejected token, re-login once and repeat (reads are idempotent)."""
        if self._closed:
            raise GwmClosedError(operation=operation)
        deadline = _Deadline(asyncio.get_running_loop().time() + 60.0)
        try:
            async with asyncio.timeout_at(deadline.expires_at), self._lock:
                if self._closed:
                    raise GwmClosedError(operation=operation)
                tokens = await self._session.ensure()
                try:
                    return await self._exchange(operation, vehicle_id, tokens, deadline, plan)
                except GwmBrCredentialError:
                    raise
                except GwmAuthenticationError:
                    tokens = await self._session.ensure(rejected=tokens)
                    return await self._exchange(operation, vehicle_id, tokens, deadline, plan)
        except TimeoutError:
            raise GwmDeadlineExceededError(operation=operation) from None

    async def _exchange(
        self,
        operation: str,
        vehicle_id: str | None,
        tokens: BrTokens,
        deadline: _Deadline,
        plan: ChargingPlanCommand | None = None,
    ) -> object:
        """Send one prepared read with the given token snapshot."""
        request = prepare_br_request(
            operation=operation,
            ssl_context=self._ssl_context,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            vehicle_id=vehicle_id,
            plan=plan,
        )
        response = await self._transport.execute(request, deadline=deadline, connect_timeout=10.0, read_timeout=20.0)
        return decode_br_envelope(response, operation=operation)

    async def acquire_vehicles(self) -> tuple[CloudVehicle, ...]:
        """Discover account vehicles."""
        data = await self._read("acquire_vehicles")
        try:
            return parse_cloud_vehicles(data, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="acquire_vehicles") from None

    async def get_last_status(self, vehicle_id: str | VehicleIdentifier) -> CloudVehicleStatus:
        """Read the last reported status for one vehicle."""
        identifier = vehicle_id.value if isinstance(vehicle_id, VehicleIdentifier) else vehicle_id
        data = await self._read("get_last_status", identifier)
        try:
            return parse_cloud_vehicle_status(data, allow_stringified_numbers=True, allow_numbers_for_strings=True)
        except ValueError:
            raise GwmSchemaError(operation="get_last_status") from None

    async def set_charging_plan(self, command: ChargingPlanCommand) -> None:
        """Set or clear the charging plan (opt-in, gated by the cloud client; no PIN)."""
        await self._read("set_charging_plan", plan=command)


async def open_br_read_client(material_directory: Path, credentials: BrCredentials) -> BrReadClient:
    """Entry point for tools and tests: build context, transport and client.

    ``material_directory`` is injected (the bundled files live in ``resources/br``). The
    caller must ``await client.aclose()``. The Home Assistant integration builds its
    own client through ``br_flow.create_br_reader`` instead.
    """
    context = await asyncio.to_thread(lambda: create_br_ssl_context(load_br_material(material_directory)))
    transport = AiohttpTransport.create_owned()
    session = BrSession(BrAuthClient(credentials=credentials, transport=transport, refresh_context=context))
    return BrReadClient(session=session, ssl_context=context, transport=transport, owns_transport=True)
