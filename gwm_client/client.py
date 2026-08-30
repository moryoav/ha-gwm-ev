"""Typed async GWM client for authenticated overseas reads and closed commands."""

from __future__ import annotations

import asyncio
import json
import math
import re
import ssl
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Self, cast
from urllib.parse import quote, urlsplit

from ._dotnet_json import encode_dotnet_json
from ._protocol import _AsyncTransport, _Deadline, _TransportRequest, _TransportResponse
from .anz_auth import (
    AnzAuthenticated,
    AnzAuthenticationResult,
    AnzAuthState,
    AnzCredentials,
    _AnzAuthProgress,
)
from .anz_auth import authenticate_anz as _run_anz_authentication
from .charging import (
    ChargingPlanCommand,
    ChargingPlanInfo,
    parse_charging_plan_info,
)
from .commands import (
    ClimateCommand,
    CloseWindowsCommand,
    DoorLockCommand,
    RemoteCommandAcceptance,
    RemoteCommandResultItem,
    parse_remote_command_results,
    validate_overseas_command_inputs,
)
from .config import GwmClientConfig
from .errors import (
    GwmApiError,
    GwmAuthenticationError,
    GwmClientError,
    GwmClosedError,
    GwmConfigurationError,
    GwmDeadlineExceededError,
    GwmHttpError,
    GwmNetworkError,
    GwmOptionalEndpointError,
    GwmProtocolError,
    GwmRateLimitError,
    GwmRedirectError,
    GwmResponseTooLargeError,
    GwmRoutePolicyError,
    GwmSchemaError,
    GwmTlsError,
)
from .eu_auth import (
    EuAuthenticated,
    EuAuthenticationResult,
    EuAuthState,
    EuCredentials,
    _EuAuthProgress,
)
from .eu_auth import authenticate_eu as _run_eu_authentication
from .eu_identity import EuBootstrapMaterial
from .models import (
    CloudVehicle,
    CloudVehicleBasics,
    CloudVehicleStatus,
    GwmSession,
    VehicleIdentifier,
    parse_cloud_vehicle_basics,
    parse_cloud_vehicle_status,
    parse_cloud_vehicles,
)
from .regions import GatewayRole, Region, RegionProtocol, TlsMode, get_region_protocol
from .russia_auth import (
    RussiaAuthenticated,
    RussiaAuthenticationResult,
    RussiaAuthState,
    RussiaCredentials,
    _RussiaAuthProgress,
)
from .russia_auth import authenticate_russia as _run_russia_authentication
from .russia_identity import RussiaBootstrapMaterial
from .signing import SignedRequest, SigningProfile, sign_request
from .transport import AiohttpTransport

_MAX_JSON_DEPTH = 64
_CHARGING_SEQUENCE = re.compile(r"[0-9a-f]{32}1234")


@dataclass(frozen=True, slots=True)
class _ReadEndpoint[T]:
    operation: str
    path: str
    query_kind: str
    decoder: Callable[[object, Region], T] = field(repr=False)


_ACQUIRE_VEHICLES = _ReadEndpoint(
    operation="acquire_vehicles",
    path="globalapp/vehicle/acquireVehicles",
    query_kind="none",
    decoder=lambda data, region: parse_cloud_vehicles(
        data,
        allow_numbers_for_strings=region is Region.RUSSIA,
    ),
)
_LAST_STATUS = _ReadEndpoint(
    operation="get_last_status",
    path="vehicle/getLastStatus",
    query_kind="last_status",
    decoder=lambda data, region: parse_cloud_vehicle_status(
        data,
        allow_stringified_numbers=region in {Region.ANZ, Region.RUSSIA},
        allow_numbers_for_strings=region is Region.RUSSIA,
    ),
)
_VEHICLE_BASICS = _ReadEndpoint(
    operation="get_vehicle_basics",
    path="vehicle/vehicleBasicsInfo",
    query_kind="vehicle_basics",
    decoder=lambda data, region: parse_cloud_vehicle_basics(
        data,
        allow_numbers_for_strings=region is Region.RUSSIA,
    ),
)
_READ_ENDPOINTS = MappingProxyType(
    {
        endpoint.operation: endpoint
        for endpoint in (_ACQUIRE_VEHICLES, _LAST_STATUS, _VEHICLE_BASICS)
    }
)


class GwmClient:
    """A lifecycle-managed regional authentication, read, and command client."""

    def __init__(
        self,
        config: GwmClientConfig,
        session: GwmSession | None = None,
        *,
        transport: _AsyncTransport | None = None,
        sequence_source: Callable[[], str] | None = None,
    ) -> None:
        if type(config) is not GwmClientConfig:
            raise GwmConfigurationError()
        self._config = config
        self._protocol = get_region_protocol(config.region)
        self._session = None if session is None else self._validated_session(session)
        self._session_revision = 0
        if sequence_source is not None and not callable(sequence_source):
            raise GwmConfigurationError()
        self._sequence_source = sequence_source or (lambda: uuid.uuid4().hex + "1234")
        self._h5_ssl_context: ssl.SSLContext | None = None
        self._transport: _AsyncTransport
        if transport is None:
            self._transport = AiohttpTransport.create_owned(
                max_response_bytes=config.max_response_bytes
            )
            self._owns_transport = True
        else:
            self._transport = transport
            self._owns_transport = False
        self._closed = False
        self._closing = False
        self._close_lock = asyncio.Lock()
        self._h5_ssl_context_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()

    @property
    def region(self) -> Region:
        return self._protocol.region

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def authenticated(self) -> bool:
        """Return whether future reads have a complete authenticated session."""

        return self._session is not None

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
                async with self._request_lock:
                    if self._owns_transport:
                        await self._transport.aclose()
            except BaseException:
                self._closing = False
                raise
            self._closed = True
            self._closing = False

    def replace_session(self, session: GwmSession) -> None:
        """Atomically replace future request state without changing in-flight requests."""

        if self._closed or self._closing:
            raise GwmClosedError()
        self._session = self._validated_session(session)
        self._session_revision += 1

    async def authenticate_eu(
        self,
        credentials: EuCredentials,
        *,
        state: EuAuthState | None = None,
        verification_code: str | None = None,
        allow_password_login: bool = True,
        ca_bundle: bytes,
        bootstrap_material: EuBootstrapMaterial | None = None,
        timeout: float | None = None,
    ) -> EuAuthenticationResult:
        """Authenticate one EU account and atomically install its future read session."""

        operation = "login"
        if (
            self._protocol.region is not Region.EU
            or type(credentials) is not EuCredentials
            or (state is not None and type(state) is not EuAuthState)
            or type(allow_password_login) is not bool
            or not isinstance(ca_bundle, bytes)
            or not ca_bundle
            or (
                bootstrap_material is not None
                and (type(bootstrap_material) is not EuBootstrapMaterial or bootstrap_material.ca_bundle != ca_bundle)
            )
        ):
            raise GwmConfigurationError(operation=operation)
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total_timeout = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total_timeout)
        failure: GwmClientError | None = None
        progress = _EuAuthProgress()

        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    reusable = state is not None and state.matches(credentials)
                    current = self._session
                    attempt_revision = self._session_revision
                    if reusable and state is not None and current is not None:
                        reusable = (
                            current.country == state.country
                            and current.device_id == state.device_id
                            and current.access_token == state.access_token
                        )
                    if not reusable:
                        self._session = None
                        self._session_revision += 1
                        attempt_revision = self._session_revision
                    try:
                        result = await _run_eu_authentication(
                            config=self._config,
                            transport=self._transport,
                            credentials=credentials,
                            state=state,
                            verification_code=verification_code,
                            allow_password_login=allow_password_login,
                            ca_bundle=ca_bundle,
                            bootstrap_material=bootstrap_material,
                            deadline=deadline,
                            progress=progress,
                        )
                        if type(result) is EuAuthenticated:
                            replacement = self._validated_session(result.session)
                        else:
                            replacement = None
                        self._replace_session_if_revision(
                            expected_revision=attempt_revision,
                            session=replacement,
                        )
                        return result
                    except BaseException:
                        if progress.existing_session_rejected:
                            self._replace_session_if_revision(
                                expected_revision=attempt_revision,
                                session=None,
                            )
                        raise
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else _sanitized_client_error(error, operation=error.operation)
            )
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except Exception:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else GwmNetworkError(operation=operation)
            )

        if failure is not None:
            raise failure
        raise GwmNetworkError(operation=operation)

    async def authenticate_anz(
        self,
        credentials: AnzCredentials,
        *,
        state: AnzAuthState | None = None,
        verification_code: str | None = None,
        allow_session_reclaim: bool = False,
        timeout: float | None = None,
    ) -> AnzAuthenticationResult:
        """Authenticate ANZ, requiring opt-in before any single-session login."""

        operation = "login"
        if (
            self._protocol.region is not Region.ANZ
            or type(credentials) is not AnzCredentials
            or (state is not None and type(state) is not AnzAuthState)
            or type(allow_session_reclaim) is not bool
        ):
            raise GwmConfigurationError(operation=operation)
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total_timeout = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total_timeout)
        failure: GwmClientError | None = None
        progress = _AnzAuthProgress()

        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    reusable = state is not None and state.matches(credentials)
                    current = self._session
                    attempt_revision = self._session_revision
                    if reusable and state is not None and current is not None:
                        reusable = (
                            current.country == state.country
                            and current.device_id == state.device_id
                            and current.access_token == state.access_token
                        )
                    if not reusable:
                        self._session = None
                        self._session_revision += 1
                        attempt_revision = self._session_revision
                    try:
                        result = await _run_anz_authentication(
                            config=self._config,
                            transport=self._transport,
                            credentials=credentials,
                            state=state,
                            verification_code=verification_code,
                            allow_session_reclaim=allow_session_reclaim,
                            deadline=deadline,
                            progress=progress,
                        )
                        replacement = (
                            self._validated_session(result.session)
                            if type(result) is AnzAuthenticated
                            else None
                        )
                        self._replace_session_if_revision(
                            expected_revision=attempt_revision,
                            session=replacement,
                        )
                        return result
                    except BaseException:
                        if progress.existing_session_rejected:
                            self._replace_session_if_revision(
                                expected_revision=attempt_revision,
                                session=None,
                            )
                        raise
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else _sanitized_client_error(error, operation=error.operation)
            )
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except Exception:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else GwmNetworkError(operation=operation)
            )

        if failure is not None:
            raise failure
        raise GwmNetworkError(operation=operation)

    async def authenticate_russia(
        self,
        credentials: RussiaCredentials,
        *,
        state: RussiaAuthState | None = None,
        verification_code: str | None = None,
        allow_password_login: bool = True,
        bootstrap_material: RussiaBootstrapMaterial,
        timeout: float | None = None,
    ) -> RussiaAuthenticationResult:
        """Authenticate Russia and install its static-bootstrap-mTLS read session."""

        operation = "login"
        if (
            self._protocol.region is not Region.RUSSIA
            or type(credentials) is not RussiaCredentials
            or (state is not None and type(state) is not RussiaAuthState)
            or type(allow_password_login) is not bool
            or type(bootstrap_material) is not RussiaBootstrapMaterial
        ):
            raise GwmConfigurationError(operation=operation)
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total_timeout = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total_timeout)
        failure: GwmClientError | None = None
        progress = _RussiaAuthProgress()

        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    reusable = state is not None and state.matches(credentials)
                    current = self._session
                    attempt_revision = self._session_revision
                    if reusable and state is not None and current is not None:
                        reusable = (
                            current.country == state.country
                            and current.device_id == state.device_id
                            and current.access_token == state.access_token
                        )
                    if not reusable:
                        self._session = None
                        self._session_revision += 1
                        attempt_revision = self._session_revision
                    try:
                        result = await _run_russia_authentication(
                            config=self._config,
                            transport=self._transport,
                            credentials=credentials,
                            state=state,
                            verification_code=verification_code,
                            allow_password_login=allow_password_login,
                            bootstrap_material=bootstrap_material,
                            deadline=deadline,
                            progress=progress,
                        )
                        replacement = (
                            self._validated_session(result.session)
                            if type(result) is RussiaAuthenticated
                            else None
                        )
                        self._replace_session_if_revision(
                            expected_revision=attempt_revision,
                            session=replacement,
                        )
                        return result
                    except BaseException:
                        if progress.existing_session_rejected:
                            self._replace_session_if_revision(
                                expected_revision=attempt_revision,
                                session=None,
                            )
                        raise
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else _sanitized_client_error(error, operation=error.operation)
            )
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except Exception:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else GwmNetworkError(operation=operation)
            )

        if failure is not None:
            raise failure
        raise GwmNetworkError(operation=operation)

    def _replace_session_if_revision(
        self,
        *,
        expected_revision: int,
        session: GwmSession | None,
    ) -> None:
        if self._session_revision == expected_revision:
            self._session = session
            self._session_revision += 1

    async def acquire_vehicles(
        self,
        *,
        timeout: float | None = None,
    ) -> tuple[CloudVehicle, ...]:
        return await self._execute(_ACQUIRE_VEHICLES, identifier=None, timeout=timeout)

    async def get_last_status(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> CloudVehicleStatus:
        return await self._execute(_LAST_STATUS, identifier=identifier, timeout=timeout)

    async def get_vehicle_basics(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> CloudVehicleBasics:
        return await self._execute(_VEHICLE_BASICS, identifier=identifier, timeout=timeout)

    async def get_charging_plan(
        self,
        identifier: VehicleIdentifier,
        *,
        timeout: float | None = None,
    ) -> ChargingPlanInfo:
        """Read one overseas vehicle's charging plan from the H5 gateway."""

        operation = "get_charging_plan"
        if type(identifier) is not VehicleIdentifier:
            raise GwmConfigurationError(operation=operation)
        encoded_vin = quote(
            identifier.value,
            safe="",
            encoding="utf-8",
            errors="strict",
        )

        async def action(
            session: GwmSession,
            deadline: _Deadline,
        ) -> ChargingPlanInfo:
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.H5_V1,
                method="GET",
                path=f"vehicleCharge/getChargingInfos?vin={encoded_vin}",
                body=None,
                session=session,
                vin_header=identifier if self.region is Region.ANZ else None,
            )
            data = await self._send_command_request(request, deadline=deadline)
            try:
                return parse_charging_plan_info(
                    data,
                    allow_numeric_strings=self.region is Region.RUSSIA,
                )
            except (TypeError, ValueError):
                raise GwmSchemaError(operation=operation) from None

        return await self._execute_authenticated_command(
            operation,
            timeout=timeout,
            action=action,
        )

    async def set_charging_plan(
        self,
        command: ChargingPlanCommand,
        *,
        timeout: float | None = None,
    ) -> None:
        """Set or clear one overseas charging plan without a security PIN."""

        operation = "set_charging_plan"
        try:
            sequence_number = self._sequence_source()
            if (
                type(command) is not ChargingPlanCommand
                or not isinstance(sequence_number, str)
                or _CHARGING_SEQUENCE.fullmatch(sequence_number) is None
            ):
                raise ValueError("charging_plan_invalid")
        except (TypeError, ValueError):
            raise GwmConfigurationError(operation=operation) from None
        payload: dict[str, object] = {
            "enable": command.enable,
            "seqNo": sequence_number,
            "vin": command.identifier.value,
        }
        if command.enable:
            payload.update(
                {
                    "planType": command.plan_type or 0,
                    "startTime": str(command.start_time_ms),
                    "endTime": str(command.end_time_ms),
                    "weeks": command.weeks or "",
                }
            )
        body = encode_dotnet_json(payload)

        async def action(session: GwmSession, deadline: _Deadline) -> None:
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.H5_V1,
                method="POST",
                path="vehicleCharge/setChargingPlan",
                body=body,
                session=session,
                vin_header=(
                    command.identifier if self.region is Region.ANZ else None
                ),
            )
            await self._send_command_request(request, deadline=deadline)

        await self._execute_authenticated_command(
            operation,
            timeout=timeout,
            action=action,
        )

    async def update_climate_defaults(
        self,
        identifier: VehicleIdentifier,
        *,
        temperature: int,
        operation_time_minutes: int,
        timeout: float | None = None,
    ) -> None:
        """Persist the temperature/runtime pair used by the next climate command."""

        operation = "update_climate_defaults"
        if (
            type(identifier) is not VehicleIdentifier
            or isinstance(temperature, bool)
            or not isinstance(temperature, int)
            or not 16 <= temperature <= 32
            or isinstance(operation_time_minutes, bool)
            or not isinstance(operation_time_minutes, int)
            or not 5 <= operation_time_minutes <= 30
        ):
            raise GwmConfigurationError(operation=operation)
        body = encode_dotnet_json(
            {
                "airConditionerTemperature": str(temperature),
                "airConditionerTime": str(operation_time_minutes * 60),
                "vin": identifier.value,
            }
        )

        async def action(session: GwmSession, deadline: _Deadline) -> None:
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.H5_V1,
                method="POST",
                path="vehicle/modifyVehicleRemoteCtlInfo",
                body=body,
                session=session,
                vin_header=identifier if self.region is Region.RUSSIA else None,
            )
            await self._send_command_request(request, deadline=deadline)

        await self._execute_authenticated_command(operation, timeout=timeout, action=action)

    async def send_climate_command(
        self,
        command: ClimateCommand,
        *,
        security_password_hash: str,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one overseas climate operation and return its provider sequence."""

        operation = "send_climate_command"
        try:
            sequence_number = self._sequence_source()
            validate_overseas_command_inputs(
                command,
                security_password_hash=security_password_hash,
                sequence_number=sequence_number,
                region=self.region,
            )
        except (TypeError, ValueError):
            raise GwmConfigurationError(operation=operation) from None
        switch_order = "0" if command.mode == "off" else "1"
        command_type = 3 if self.region is Region.RUSSIA else 2
        body = encode_dotnet_json(
            {
                "instructions": {
                    "0x04": {
                        "airConditioner": {
                            "operationTime": str(command.operation_time_minutes),
                            "switchOrder": switch_order,
                            "temperature": str(command.temperature),
                        }
                    }
                },
                "remoteType": "0",
                "securityPassword": security_password_hash,
                "seqNo": sequence_number,
                "type": command_type,
                "vin": command.identifier.value,
            }
        )

        async def action(session: GwmSession, deadline: _Deadline) -> RemoteCommandAcceptance:
            if self.region is Region.RUSSIA:
                check_body = encode_dotnet_json(
                    {"securityPassword": security_password_hash, "type": "3"}
                )
                check = self._prepare_command_request(
                    operation=operation,
                    gateway_role=GatewayRole.H5_V1,
                    method="POST",
                    path="userAuth/checkSecurityPassword",
                    body=check_body,
                    session=session,
                    vin_header=None,
                )
                await self._send_command_request(check, deadline=deadline)
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.APP_V1,
                method="POST",
                path="vehicle/T5/sendCmd",
                body=body,
                session=session,
                vin_header=command.identifier if self.region is Region.RUSSIA else None,
            )
            await self._send_command_request(request, deadline=deadline)
            return RemoteCommandAcceptance(sequence_number)

        return await self._execute_authenticated_command(operation, timeout=timeout, action=action)

    async def send_lock_command(
        self,
        command: DoorLockCommand,
        *,
        security_password_hash: str,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one overseas lock or unlock operation."""

        if type(command) is not DoorLockCommand:
            raise GwmConfigurationError(operation="send_lock_command")
        return await self._send_overseas_remote_command(
            operation="send_lock_command",
            command=command,
            security_password_hash=security_password_hash,
            instructions={
                "0x05": {
                    "operationTime": "0",
                    "switchOrder": "2" if command.lock else "1",
                }
            },
            timeout=timeout,
        )

    async def send_close_windows_command(
        self,
        command: CloseWindowsCommand,
        *,
        security_password_hash: str,
        timeout: float | None = None,
    ) -> RemoteCommandAcceptance:
        """Send one overseas close-all-windows operation."""

        window = {
            "leftFront": "0",
            "leftBack": "0",
            "rightFront": "0",
            "rightBack": "0",
        }
        if self.region is not Region.RUSSIA:
            window["skyLight"] = ""
        return await self._send_overseas_remote_command(
            operation="send_close_windows_command",
            command=command,
            security_password_hash=security_password_hash,
            instructions={
                "0x08": {
                    "switchOrder": "2" if self.region is Region.RUSSIA else "0",
                    "window": window,
                }
            },
            timeout=timeout,
        )

    async def _send_overseas_remote_command(
        self,
        *,
        operation: str,
        command: DoorLockCommand | CloseWindowsCommand,
        security_password_hash: str,
        instructions: Mapping[str, object],
        timeout: float | None,
    ) -> RemoteCommandAcceptance:
        try:
            sequence_number = self._sequence_source()
            validate_overseas_command_inputs(
                command,
                security_password_hash=security_password_hash,
                sequence_number=sequence_number,
                region=self.region,
            )
        except (TypeError, ValueError):
            raise GwmConfigurationError(operation=operation) from None
        body = encode_dotnet_json(
            {
                "instructions": instructions,
                "remoteType": "0",
                "securityPassword": security_password_hash,
                "seqNo": sequence_number,
                "type": 3 if self.region is Region.RUSSIA else 2,
                "vin": command.identifier.value,
            }
        )

        async def action(session: GwmSession, deadline: _Deadline) -> RemoteCommandAcceptance:
            if self.region is Region.RUSSIA:
                check = self._prepare_command_request(
                    operation=operation,
                    gateway_role=GatewayRole.H5_V1,
                    method="POST",
                    path="userAuth/checkSecurityPassword",
                    body=encode_dotnet_json(
                        {"securityPassword": security_password_hash, "type": "3"}
                    ),
                    session=session,
                    vin_header=None,
                )
                await self._send_command_request(check, deadline=deadline)
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.APP_V1,
                method="POST",
                path="vehicle/T5/sendCmd",
                body=body,
                session=session,
                vin_header=command.identifier if self.region is Region.RUSSIA else None,
            )
            await self._send_command_request(request, deadline=deadline)
            return RemoteCommandAcceptance(sequence_number)

        return await self._execute_authenticated_command(operation, timeout=timeout, action=action)

    async def get_remote_command_results(
        self,
        identifier: VehicleIdentifier,
        command_id: str,
        *,
        timeout: float | None = None,
    ) -> tuple[RemoteCommandResultItem, ...]:
        """Return the bounded result candidates for one accepted climate command."""

        operation = "get_remote_command_result"
        if (
            type(identifier) is not VehicleIdentifier
            or not isinstance(command_id, str)
            or not command_id
            or len(command_id) > 512
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in command_id)
        ):
            raise GwmConfigurationError(operation=operation)
        encoded_command_id = quote(command_id, safe="", encoding="utf-8", errors="strict")

        async def action(
            session: GwmSession,
            deadline: _Deadline,
        ) -> tuple[RemoteCommandResultItem, ...]:
            request = self._prepare_command_request(
                operation=operation,
                gateway_role=GatewayRole.APP_V1,
                method="GET",
                path=f"vehicle/getRemoteCtrlResultT5?seqNo={encoded_command_id}",
                body=None,
                session=session,
                vin_header=(
                    identifier if self.region in {Region.ANZ, Region.RUSSIA} else None
                ),
            )
            data = await self._send_command_request(request, deadline=deadline)
            try:
                return parse_remote_command_results(
                    data,
                    allow_integer_strings=self.region is Region.RUSSIA,
                )
            except (TypeError, ValueError):
                raise GwmSchemaError(operation=operation) from None

        return await self._execute_authenticated_command(operation, timeout=timeout, action=action)

    async def _execute_authenticated_command[T](
        self,
        operation: str,
        *,
        timeout: float | None,
        action: Callable[[GwmSession, _Deadline], Awaitable[T]],
    ) -> T:
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total_timeout = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total_timeout)
        attempt_revision: int | None = None
        failure: GwmClientError | None = None
        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    if self._session is None:
                        raise GwmAuthenticationError(operation=operation)
                    attempt_revision = self._session_revision
                    session = self._validated_session(self._session)
                    await self._async_prepare_h5_ssl_context(operation=operation)
                    result = await action(session, deadline)
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    return result
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            if (
                self.region in {Region.ANZ, Region.RUSSIA}
                and attempt_revision is not None
                and type(error) is GwmAuthenticationError
            ):
                self._replace_session_if_revision(
                    expected_revision=attempt_revision,
                    session=None,
                )
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else _sanitized_client_error(error, operation=operation)
            )
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except Exception:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else GwmNetworkError(operation=operation)
            )
        raise failure or GwmNetworkError(operation=operation)

    async def _async_prepare_h5_ssl_context(self, *, operation: str) -> None:
        """Load system trust off the event loop before command preparation."""

        if self._h5_ssl_context is not None:
            return
        async with self._h5_ssl_context_lock:
            if self._h5_ssl_context is not None:
                return
            try:
                context = await asyncio.to_thread(
                    ssl.create_default_context,
                    ssl.Purpose.SERVER_AUTH,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise GwmTlsError(operation=operation) from None
            if not isinstance(context, ssl.SSLContext):
                raise GwmTlsError(operation=operation)
            self._h5_ssl_context = context

    def _prepare_command_request(
        self,
        *,
        operation: str,
        gateway_role: GatewayRole,
        method: str,
        path: str,
        body: str | None,
        session: GwmSession,
        vin_header: VehicleIdentifier | None,
    ) -> _TransportRequest:
        try:
            gateway = self._protocol.gateway(gateway_role)
            unsigned_url = gateway.base_url + path
            signed = sign_request(gateway.signing_profile, method, unsigned_url, body)
            headers = {
                **self._protocol.authenticated_headers(
                    country=session.country,
                    device_id=session.device_id,
                    access_token=session.access_token,
                ),
                "Accept": "application/json",
                **signed.headers,
            }
            if body is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            if vin_header is not None:
                headers["vin"] = vin_header.value
            ssl_context = (
                session.app_ssl_context
                if gateway_role is GatewayRole.APP_V1
                else self._h5_ssl_context
            )
            if ssl_context is None:
                raise GwmConfigurationError(operation=operation)
            return _TransportRequest(
                operation=operation,
                method=method,
                url=signed.url,
                headers=headers,
                ssl_context=ssl_context,
                body=None if body is None else body.encode("utf-8"),
            )
        except (TypeError, UnicodeError, ValueError):
            raise GwmRoutePolicyError(operation=operation) from None

    async def _send_command_request(
        self,
        request: _TransportRequest,
        *,
        deadline: _Deadline,
    ) -> object:
        response = await self._transport.execute(
            request,
            deadline=deadline,
            connect_timeout=self._config.timeouts.connect,
            read_timeout=self._config.timeouts.read,
        )
        if type(response) is not _TransportResponse:
            raise GwmProtocolError(operation=request.operation)
        return _decode_envelope(response, operation=request.operation)

    async def _execute[T](
        self,
        endpoint: _ReadEndpoint[T],
        *,
        identifier: VehicleIdentifier | None,
        timeout: float | None,
    ) -> T:
        if _READ_ENDPOINTS.get(endpoint.operation) is not endpoint:
            raise GwmRoutePolicyError()
        operation = endpoint.operation
        if endpoint.query_kind == "none":
            if identifier is not None:
                raise GwmRoutePolicyError(operation=operation)
        elif type(identifier) is not VehicleIdentifier:
            raise GwmRoutePolicyError(operation=operation)
        if self._closed or self._closing:
            raise GwmClosedError(operation=operation)
        total_timeout = self._validated_timeout(timeout, operation=operation)
        loop = asyncio.get_running_loop()
        deadline = _Deadline(loop.time() + total_timeout)
        failure: GwmClientError | None = None
        attempt_revision: int | None = None

        try:
            async with asyncio.timeout_at(deadline.expires_at):
                async with self._request_lock:
                    if self._closed or self._closing:
                        raise GwmClosedError(operation=operation)
                    if self._session is None:
                        raise GwmAuthenticationError(operation=operation)
                    attempt_revision = self._session_revision
                    session = self._validated_session(self._session)
                    request = self._prepare_read_request(endpoint, session, identifier)
                    response = await self._transport.execute(
                        request,
                        deadline=deadline,
                        connect_timeout=self._config.timeouts.connect,
                        read_timeout=self._config.timeouts.read,
                    )
                    if type(response) is not _TransportResponse:
                        raise GwmProtocolError(operation=operation)
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    regional_error = _classify_regional_read_error(
                        response,
                        endpoint=endpoint,
                        region=self._protocol.region,
                    )
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    if regional_error == "authentication":
                        raise GwmAuthenticationError(
                            operation=operation,
                            api_code="607501",
                        )
                    if regional_error == "optional":
                        raise GwmOptionalEndpointError(
                            operation=operation,
                            api_code="607099",
                        )
                    data = _decode_envelope(response, operation=operation)
                    if deadline.remaining(loop.time()) <= 0:
                        raise GwmDeadlineExceededError(operation=operation)
                    try:
                        result = endpoint.decoder(
                            data,
                            self._protocol.region,
                        )
                    except (KeyError, OverflowError, RecursionError, TypeError, ValueError):
                        if deadline.remaining(loop.time()) <= 0:
                            raise GwmDeadlineExceededError(operation=operation) from None
                        failure = GwmSchemaError(operation=operation)
                    else:
                        if deadline.remaining(loop.time()) <= 0:
                            raise GwmDeadlineExceededError(operation=operation)
                        return result
        except asyncio.CancelledError:
            raise
        except GwmClientError as error:
            if (
                self._protocol.region in {Region.ANZ, Region.RUSSIA}
                and attempt_revision is not None
                and type(error) is GwmAuthenticationError
            ):
                self._replace_session_if_revision(
                    expected_revision=attempt_revision,
                    session=None,
                )
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else _sanitized_client_error(error, operation=operation)
            )
        except TimeoutError:
            failure = GwmDeadlineExceededError(operation=operation)
        except Exception:
            failure = (
                GwmDeadlineExceededError(operation=operation)
                if deadline.remaining(loop.time()) <= 0
                else GwmNetworkError(operation=operation)
            )

        if failure is not None:
            raise failure
        raise GwmSchemaError(operation=operation)

    def _prepare_read_request[T](
        self,
        endpoint: _ReadEndpoint[T],
        session: GwmSession,
        identifier: VehicleIdentifier | None,
    ) -> _TransportRequest:
        operation = endpoint.operation
        route_failure = False
        try:
            gateway = self._protocol.gateway(GatewayRole.APP_V1)
            relative_url = endpoint.path + _logical_query(endpoint, identifier)
            unsigned_url = gateway.base_url + relative_url
            signed = sign_request(gateway.signing_profile, "GET", unsigned_url)
            _validate_signed_read(
                signed,
                endpoint=endpoint,
                protocol=self._protocol,
                identifier=identifier,
            )
            headers = {
                **self._protocol.authenticated_headers(
                    country=session.country,
                    device_id=session.device_id,
                    access_token=session.access_token,
                ),
                "Accept": "application/json",
                **signed.headers,
            }
            return _TransportRequest(
                operation=operation,
                method="GET",
                url=signed.url,
                headers=headers,
                ssl_context=session.app_ssl_context,
            )
        except (TypeError, ValueError):
            route_failure = True
        if route_failure:
            raise GwmRoutePolicyError(operation=operation)
        raise GwmRoutePolicyError(operation=operation)

    def _validated_session(self, session: GwmSession) -> GwmSession:
        if type(session) is not GwmSession:
            raise GwmConfigurationError()
        invalid = False
        try:
            self._protocol.validate_country(session.country)
            self._protocol.normalize_device_id(session.device_id)
            self._protocol.authenticated_headers(
                country=session.country,
                device_id=session.device_id,
                access_token=session.access_token,
            )
            _validate_app_tls_context(self._protocol, session.app_ssl_context)
        except (AttributeError, TypeError, ValueError):
            invalid = True
        if invalid:
            raise GwmConfigurationError()
        return session

    def _validated_timeout(self, value: float | None, *, operation: str) -> float:
        if value is None:
            return self._config.timeouts.total
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
            or value <= 0
            or value > self._config.timeouts.total
        ):
            raise GwmConfigurationError(operation=operation)
        return float(value)


def _logical_query[T](
    endpoint: _ReadEndpoint[T],
    identifier: VehicleIdentifier | None,
) -> str:
    if endpoint.query_kind == "none":
        if identifier is not None:
            raise ValueError("route_invalid")
        return ""
    if identifier is None:
        raise ValueError("route_invalid")
    if endpoint.query_kind == "last_status":
        return f"?vin={identifier.encoded}&seqNo="
    if endpoint.query_kind == "vehicle_basics":
        return f"?vin={identifier.encoded}&flag=true"
    raise ValueError("route_invalid")


def _validate_signed_read[T](
    signed: SignedRequest,
    *,
    endpoint: _ReadEndpoint[T],
    protocol: RegionProtocol,
    identifier: VehicleIdentifier | None,
) -> None:
    gateway = protocol.gateway(GatewayRole.APP_V1)
    parsed = urlsplit(signed.url)
    expected_base = urlsplit(gateway.base_url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("route_invalid") from None

    expected_path = expected_base.path + endpoint.path
    if endpoint.query_kind == "none":
        expected_query = ""
    elif identifier is None:
        raise ValueError("route_invalid")
    elif endpoint.query_kind == "last_status":
        expected_query = f"vin={identifier.encoded}" + (
            "&seqNo=" if protocol.region is Region.EU else ""
        )
    elif endpoint.query_kind == "vehicle_basics":
        expected_query = (
            f"vin={identifier.encoded}&flag=true"
            if protocol.region is Region.EU
            else f"flag=true&vin={identifier.encoded}"
        )
    else:
        raise ValueError("route_invalid")

    if (
        signed.method != "GET"
        or signed.body is not None
        or parsed.scheme != "https"
        or parsed.hostname != expected_base.hostname
        or parsed.path != expected_path
        or parsed.query != expected_query
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("route_invalid")
    _validate_signing_headers(signed, gateway.signing_profile)


def _validate_signing_headers(
    signed: SignedRequest,
    profile: SigningProfile,
) -> None:
    prefix = profile.prefix
    expected_names = {
        f"{prefix}-auth-appkey",
        f"{prefix}-auth-nonce",
        f"{prefix}-auth-timestamp",
        f"{prefix}-auth-sign",
    }
    if set(signed.headers) != expected_names:
        raise ValueError("route_invalid")
    nonce = signed.headers[f"{prefix}-auth-nonce"]
    timestamp = signed.headers[f"{prefix}-auth-timestamp"]
    signature = signed.headers[f"{prefix}-auth-sign"]
    if (
        signed.headers[f"{prefix}-auth-appkey"] != profile.app_key
        or re.fullmatch(r"[0-9A-Fa-f]{16}", nonce) is None
        or (profile.uppercase_nonce and nonce != nonce.upper())
        or (not profile.uppercase_nonce and nonce != nonce.lower())
        or not 10 <= len(timestamp) <= 17
        or not timestamp.isdecimal()
        or re.fullmatch(r"[0-9a-f]{64}", signature) is None
    ):
        raise ValueError("route_invalid")


def _validate_app_tls_context(protocol: RegionProtocol, context: object) -> None:
    if (
        not isinstance(context, ssl.SSLContext)
        or not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("tls_context_invalid")
    minimum_version = context.minimum_version
    maximum_version = context.maximum_version
    if minimum_version < ssl.TLSVersion.TLSv1_2 or (
        maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
        and (
            maximum_version < ssl.TLSVersion.TLSv1_2
            or maximum_version < minimum_version
        )
    ):
        raise ValueError("tls_context_invalid")
    tls_mode = protocol.gateway(GatewayRole.APP_V1).tls_mode
    if tls_mode is TlsMode.DEFAULT:
        if context.security_level <= 0:
            raise ValueError("tls_context_invalid")
    elif tls_mode in {TlsMode.EU_ISSUED_MTLS, TlsMode.RUSSIA_BOOTSTRAP_MTLS}:
        if context.security_level != 0:
            raise ValueError("tls_context_invalid")
    else:
        raise ValueError("tls_context_invalid")


def _classify_regional_read_error[T](
    response: _TransportResponse,
    *,
    endpoint: _ReadEndpoint[T],
    region: Region,
) -> str | None:
    """Classify only exact, evidence-backed ANZ application codes."""

    if region is not Region.ANZ or not 200 <= response.status <= 299:
        return None
    try:
        envelope = json.loads(
            response.body.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        _validate_json_depth(envelope)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(envelope, Mapping):
        return None
    code = envelope.get("code")
    if code == "607501":
        return "authentication"
    if endpoint is _VEHICLE_BASICS and code == "607099":
        return "optional"
    return None


def _decode_envelope(response: _TransportResponse, *, operation: str) -> object:
    if response.status in {401, 403}:
        raise GwmAuthenticationError(operation=operation)
    if response.status == 429:
        retry_after = response.headers.get("retry-after")
        retry_seconds = (
            int(retry_after)
            if retry_after and len(retry_after) <= 10 and retry_after.isdecimal()
            else None
        )
        raise GwmRateLimitError(
            operation=operation,
            retry_after_seconds=retry_seconds,
        )
    if not 200 <= response.status <= 299:
        raise GwmHttpError(operation=operation, status=response.status)

    invalid = False
    try:
        text = response.body.decode("utf-8", errors="strict")
        envelope = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        _validate_json_depth(envelope)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        invalid = True
        envelope = None
    if invalid or not isinstance(envelope, Mapping):
        raise GwmSchemaError(operation=operation)

    code = envelope.get("code")
    if code != "000000":
        raise GwmApiError(operation=operation, api_code=code)
    if "data" not in envelope:
        raise GwmSchemaError(operation=operation)
    return envelope["data"]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("invalid_json_number")


def _validate_json_depth(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("json_too_deep")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("invalid_json_number")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth=depth + 1)


def _sanitized_client_error(error: GwmClientError, *, operation: str) -> GwmClientError:
    error_type = type(error)
    if error_type is GwmHttpError:
        return GwmHttpError(
            operation=operation,
            status=cast(GwmHttpError, error).status,
        )
    if error_type is GwmRateLimitError:
        rate_error = cast(GwmRateLimitError, error)
        return GwmRateLimitError(
            operation=operation,
            api_code=rate_error.api_code,
            retry_after_seconds=rate_error.retry_after_seconds,
        )
    if error_type is GwmAuthenticationError:
        return GwmAuthenticationError(
            operation=operation,
            api_code=cast(GwmAuthenticationError, error).api_code,
        )
    if error_type is GwmOptionalEndpointError:
        return GwmOptionalEndpointError(
            operation=operation,
            api_code=cast(GwmOptionalEndpointError, error).api_code,
        )
    if error_type is GwmApiError:
        return GwmApiError(
            operation=operation,
            api_code=cast(GwmApiError, error).api_code,
        )
    if error_type is GwmClosedError:
        return GwmClosedError(operation=operation)
    if error_type is GwmConfigurationError:
        return GwmConfigurationError(operation=operation)
    if error_type is GwmDeadlineExceededError:
        return GwmDeadlineExceededError(operation=operation)
    if error_type is GwmNetworkError:
        return GwmNetworkError(operation=operation)
    if error_type is GwmProtocolError:
        return GwmProtocolError(operation=operation)
    if error_type is GwmRedirectError:
        return GwmRedirectError(operation=operation)
    if error_type is GwmResponseTooLargeError:
        return GwmResponseTooLargeError(operation=operation)
    if error_type is GwmRoutePolicyError:
        return GwmRoutePolicyError(operation=operation)
    if error_type is GwmSchemaError:
        return GwmSchemaError(operation=operation)
    if error_type is GwmTlsError:
        return GwmTlsError(operation=operation)
    return GwmNetworkError(operation=operation)


__all__ = ["GwmClient"]
