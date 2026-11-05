"""Synthetic mainland-China sessions and a fail-closed cloud transport."""
from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from custom_components.gwm_ora.gwm_client._protocol import _Deadline
from custom_components.gwm_ora.gwm_client.china_client import (
    ChinaAuthState,
    ChinaClient,
    ChinaClientConfig,
    ChinaCredentials,
)
from custom_components.gwm_ora.gwm_client.china_transport import _ChinaTransportRequest, _ChinaTransportResponse

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "client" / "fixtures" / "china_auth_contracts_v1.json").read_text(
        encoding="utf-8"
    )
)

BEAN_FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "client" / "fixtures" / "china_beantech_status_v1.json").read_text(
        encoding="utf-8"
    )
)

CLOCK = datetime.fromisoformat(FIXTURE["clock"])

DEVICE_ID = FIXTURE["credentials"]["device_id"]

PHONE = FIXTURE["credentials"]["phone"]

CODE = FIXTURE["credentials"]["verification_code"]

VIN = "LGWTEST0000000001"

UNSUPPORTED_VIN = "LGWTEST0000000002"

BEAN_VIN = BEAN_FIXTURE["vin"]

BEAN_COMMAND_ID = "0123456789abcdef0123456789abcdef1234"

SENSITIVE = "SENSITIVE-PRIVATE-VALUE-MUST-NOT-LEAK"

class _Wait:
    pass

class _FakeTransport:
    def __init__(self, **plans: list[object]) -> None:
        self.plans = {operation: deque(items) for operation, items in plans.items()}
        self.calls: list[_ChinaTransportRequest] = []
        self.close_calls = 0

    async def execute(
        self,
        request: _ChinaTransportRequest,
        *,
        deadline: _Deadline,
        connect_timeout: float,
        read_timeout: float,
    ) -> _ChinaTransportResponse:
        del deadline, connect_timeout, read_timeout
        self.calls.append(request)
        queue = self.plans.get(request.operation)
        if queue is None or not queue:
            raise AssertionError(f"unexpected operation {request.operation}")
        item = queue.popleft()
        if isinstance(item, _Wait):
            await asyncio.Event().wait()
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, _ChinaTransportResponse):
            return item
        return _response(item)

    async def aclose(self) -> None:
        self.close_calls += 1

def _response(value: object, *, status: int = 200, headers: Mapping[str, str] | None = None) -> _ChinaTransportResponse:
    return _ChinaTransportResponse(
        status=status,
        headers={} if headers is None else headers,
        body=json.dumps(value, separators=(",", ":")).encode(),
    )

def _credentials(*, phone: str = PHONE, device_id: str = DEVICE_ID) -> ChinaCredentials:
    return ChinaCredentials(phone=phone, device_id=device_id)

def _empty_state(credentials: ChinaCredentials | None = None) -> ChinaAuthState:
    return ChinaAuthState.for_credentials(credentials or _credentials())

def _partial_state(credentials: ChinaCredentials | None = None, **changes: object) -> ChinaAuthState:
    credentials = credentials or _credentials()
    values: dict[str, object] = {
        "account_binding": credentials.account_binding,
        "device_id": credentials.device_id,
        **FIXTURE["g_app_state"],
    }
    values.update(changes)
    return ChinaAuthState(**values)  # type: ignore[arg-type]

def _complete_state(credentials: ChinaCredentials | None = None, **changes: object) -> ChinaAuthState:
    values: dict[str, object] = {
        **{
            name: getattr(_partial_state(credentials), name)
            for name in ChinaAuthState.__dataclass_fields__
        },
        **FIXTURE["complete_state"],
    }
    values.update(changes)
    return ChinaAuthState(**values)  # type: ignore[arg-type]

def _success_plans(*, login: bool = True) -> dict[str, list[object]]:
    plans: dict[str, list[object]] = {
        "initialize_bean_tech": [FIXTURE["responses"]["bean_tech"]],
        "initialize_auto_ai": [FIXTURE["responses"]["auto_ai"]],
        "acquire_vehicles": [FIXTURE["responses"]["discovery"]],
    }
    if login:
        plans["login"] = [FIXTURE["responses"]["login"]]
    return plans

def _client(
    transport: _FakeTransport,
    *,
    clock: Any = lambda: CLOCK,
    sleeper: Any = None,
    config: ChinaClientConfig | None = None,
) -> ChinaClient:
    return ChinaClient(
        config or ChinaClientConfig(),
        transport=transport,
        clock=clock,
        salt_source=lambda: bytes.fromhex(FIXTURE["salt_hex"]),
        nonce_source=lambda: FIXTURE["nonce"],
        sequence_source=lambda: BEAN_COMMAND_ID,
        sleeper=sleeper,
    )

def _charging_setting(**updates):
    return {
        "chargingMode": 1, "chargeStrategy": 5,
        "chargeSetParam": {
            "customTime": {"startTime": "23:03", "endTime": "07:07", "extension": "keep"},
            "drivingPlanTimes": [{"day": 1, "departure": "08:15"}],
            "futureField": {"nested": [1, None, True]},
        }, **updates,
    }


def _assert_request(request: _ChinaTransportRequest, expected_name: str) -> None:
    expected = FIXTURE["requests"][expected_name]
    assert request.method == expected["method"]
    assert request.service == expected["service"]
    assert request.url == expected["url"]
    assert dict(request.headers) == expected["headers"]
    assert (None if request.body is None else request.body.decode()) == expected["body"]


def _auto_ai_payload(request: _ChinaTransportRequest) -> dict[str, Any]:
    parsed = urlsplit(request.url)
    assert parsed.query.startswith("p=")
    return json.loads(unquote(parsed.query[2:]))
