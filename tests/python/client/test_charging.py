"""Offline regional charging-plan request and parsing tests."""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from custom_components.gwm_ora.gwm_client import (
    ChargingPlanCommand,
    GwmApiError,
    GwmClient,
    GwmClientConfig,
    GwmConfigurationError,
    GwmSession,
    Region,
    VehicleIdentifier,
    create_gwm_ssl_context,
)
from custom_components.gwm_ora.gwm_client._protocol import _Deadline, _TransportRequest, _TransportResponse

FIXTURE_PATH = Path(__file__).with_name("fixtures") / "command_contracts_v1.json"


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


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _response(data: object = None, *, code: str = "000000") -> _TransportResponse:
    return _TransportResponse(
        200,
        {"content-type": "application/json"},
        json.dumps({"code": code, "data": data}, separators=(",", ":")).encode(),
    )


def _context(region: Region) -> ssl.SSLContext:
    return (
        ssl.create_default_context()
        if region is Region.ANZ
        else create_gwm_ssl_context()
    )


def _body(request: _TransportRequest) -> dict[str, Any]:
    assert request.body is not None
    return json.loads(request.body)


@pytest.mark.asyncio
@pytest.mark.parametrize("region", list(Region))
async def test_regional_charging_read_set_and_clear_contracts_are_exact(
    region: Region,
) -> None:
    fixture = _fixture()
    case = fixture["regions"][region.value]

    def numeric(value: int) -> int | str:
        return str(value) if region is Region.RUSSIA else value

    transport = _RecordingTransport(
        [
            _response(
                {
                    "chargePlanList": [
                        {
                            "planId": numeric(41),
                            "planType": "0",
                            "startTime": numeric(1_800_000_000_000),
                            "endTime": numeric(1_800_007_200_000),
                            "weeks": "",
                        }
                    ]
                }
            ),
            _response({}),
            _response({}),
        ]
    )
    client = GwmClient(
        GwmClientConfig(region),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-CHARGING-TOKEN",
            app_ssl_context=_context(region),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )
    identifier = VehicleIdentifier(fixture["vin"])

    current = await client.get_charging_plan(identifier)
    await client.set_charging_plan(
        ChargingPlanCommand(
            identifier,
            True,
            1_800_000_000_000,
            1_800_007_200_000,
            0,
            "",
        )
    )
    await client.set_charging_plan(ChargingPlanCommand(identifier, False))

    assert current.as_dict() == {
        "charge_plan_list": [
            {
                "plan_id": 41,
                "plan_type": "0",
                "start_time": 1_800_000_000_000,
                "end_time": 1_800_007_200_000,
                "weeks": "",
            }
        ]
    }
    read, set_request, clear_request = transport.requests
    assert urlsplit(read.url).path.endswith("/vehicleCharge/getChargingInfos")
    assert urlsplit(read.url).query.startswith("vin=" + fixture["vin"])
    assert urlsplit(read.url).scheme + "://" + urlsplit(read.url).netloc == case[
        "modify_origin"
    ]
    assert (read.headers.get("vin") == fixture["vin"]) is (region is Region.ANZ)
    assert urlsplit(set_request.url).path.endswith("/vehicleCharge/setChargingPlan")
    assert (set_request.headers.get("vin") == fixture["vin"]) is (
        region is Region.ANZ
    )
    assert _body(set_request) == {
        "enable": True,
        "seqNo": fixture["sequence_number"],
        "vin": fixture["vin"],
        "planType": 0,
        "startTime": "1800000000000",
        "endTime": "1800007200000",
        "weeks": "",
    }
    assert _body(clear_request) == {
        "enable": False,
        "seqNo": fixture["sequence_number"],
        "vin": fixture["vin"],
    }
    assert (clear_request.headers.get("vin") == fixture["vin"]) is (
        region is Region.ANZ
    )


@pytest.mark.asyncio
async def test_charging_validation_and_provider_rejection_fail_closed() -> None:
    fixture = _fixture()
    case = fixture["regions"]["aus"]
    identifier = VehicleIdentifier(fixture["vin"])
    transport = _RecordingTransport([_response(code="607777")])
    client = GwmClient(
        GwmClientConfig(Region.ANZ),
        GwmSession(
            country=case["country"],
            device_id=case["device_id"],
            access_token="SYNTHETIC-CHARGING-TOKEN",
            app_ssl_context=_context(Region.ANZ),
        ),
        transport=transport,
        sequence_source=lambda: fixture["sequence_number"],
    )

    for values in (
        (True, 1_800_000_000_000, 1_800_000_299_999, 0, ""),
        (True, 1_800_000_000_000, 1_800_000_300_000, 1, ""),
        (True, 1_800_000_000_000, 1_800_000_300_000, False, ""),
        (True, 1_800_000_000_000, 1_800_000_300_000, 0.0, ""),
        (True, 1_800_000_000_000, 1_800_000_300_000, 0, "bad"),
        (False, None, None, 0, None),
    ):
        with pytest.raises(ValueError, match="charging_plan_command_invalid"):
            ChargingPlanCommand(identifier, *values)  # type: ignore[arg-type]

    with pytest.raises(GwmApiError):
        await client.set_charging_plan(
            ChargingPlanCommand(
                identifier,
                True,
                1_800_000_000_000,
                1_800_000_300_000,
            )
        )
    assert len(transport.requests) == 1

    invalid_sequence = GwmClient(
        GwmClientConfig(Region.ANZ),
        client._session,
        transport=_RecordingTransport([]),
        sequence_source=lambda: "invalid",
    )
    with pytest.raises(GwmConfigurationError):
        await invalid_sequence.set_charging_plan(ChargingPlanCommand(identifier, False))
