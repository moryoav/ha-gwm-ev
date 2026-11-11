"""BR login/session/read flow against a scripted transport (no network)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from support.br import FakeTransport, envelope, fake_jwt, html, write_dummy_material

from custom_components.gwm_ora.gwm_client.br_auth_client import BrAuthClient, BrSession, BrTokens, jwt_expiry
from custom_components.gwm_ora.gwm_client.br_identity import BrCredentials
from custom_components.gwm_ora.gwm_client.br_material import create_br_ssl_context, load_br_material
from custom_components.gwm_ora.gwm_client.br_read import BrReadClient
from custom_components.gwm_ora.gwm_client.br_request import GwmBrCredentialError
from custom_components.gwm_ora.gwm_client.errors import GwmClosedError, GwmSchemaError
from custom_components.gwm_ora.gwm_client.models import CloudVehicleBasics
from custom_components.gwm_ora.gwm_client.snapshots import map_vehicle_snapshot

DEVICE = "0123456789abcdef0123456789abcdef"
VIN = "SYNTHETICVIN000001"
NOW = 1_800_000_000.0

VEHICLES = [
    {
        "vin": VIN,
        "modelName": "SYNTHETIC EV",
        "appShowSeriesName": "SYNTHETIC",
        "powerType": "EV",
        "belongPlatform": "beantech",
        "agreementVersion": "T5",
        "hasScyPwd": True,
    }
]
STATUS = {
    "latitude": "-1.25",
    "longitude": "2.5",
    "items": [
        {"code": "2013021", "value": "80"},
        {"code": "2011501", "value": "310"},
        {"code": "2103010", "value": "1234"},
        {"code": "2042082", "value": "1"},
        {"code": "2208001", "value": "1"},
        {"code": "2202001", "value": "0"},
        {"code": "2201001", "value": "22"},
    ],
}


def _login(exp_offset: int = 86_400) -> object:
    return envelope({"accessToken": fake_jwt(int(NOW) + exp_offset), "refreshToken": "synthetic-refresh"})


def _client(tmp_path: Path, *responses, clock=lambda: NOW) -> tuple[BrReadClient, FakeTransport]:
    write_dummy_material(tmp_path)
    context = create_br_ssl_context(load_br_material(tmp_path))
    transport = FakeTransport(*responses)
    credentials = BrCredentials.from_password("someone@example.invalid", "Synthetic1", DEVICE)
    session = BrSession(BrAuthClient(credentials=credentials, transport=transport), clock=clock)
    return BrReadClient(session=session, ssl_context=context, transport=transport), transport


def test_jwt_expiry_reads_exp_without_trusting_signature() -> None:
    assert jwt_expiry(fake_jwt(123)) == 123.0
    assert jwt_expiry("not-a-jwt") is None


@pytest.mark.asyncio
async def test_login_then_discovery_and_golden_status(tmp_path: Path) -> None:
    client, transport = _client(tmp_path, _login(), envelope(VEHICLES), envelope(STATUS))
    vehicles = await client.acquire_vehicles()
    assert [v.identifier.value for v in vehicles] == [VIN]
    assert vehicles[0].model_name == "SYNTHETIC EV"
    assert vehicles[0].platform == "beantech"
    status = await client.get_last_status(VIN)
    assert [r.operation for r in transport.requests] == ["login", "acquire_vehicles", "get_last_status"]
    assert transport.requests[2].headers["accessToken"].count(".") == 2

    snapshot = map_vehicle_snapshot(
        vehicles[0], status, CloudVehicleBasics(), refreshed_at=datetime.now(UTC),
        remote_commands_available=False,
    )
    assert snapshot.values.soc == 80
    assert snapshot.values.range_km == 310
    assert snapshot.values.odometer_km == 1234
    assert snapshot.values.charge_plug_connected is True
    assert snapshot.values.ac_active is False
    # 2201001 is tenths of a degree Celsius: raw "22" is 2.2 C. Locks the code-to-field mapping.
    assert any(item.code == "2201001" and item.value == "22" for item in status.items)
    assert snapshot.values.interior_temperature_c == pytest.approx(2.2)
    assert snapshot.raw_items["2201001"] is not None
    assert snapshot.location is not None
    assert (snapshot.location.latitude, snapshot.location.longitude) == (-1.25, 2.5)


@pytest.mark.asyncio
async def test_login_is_done_once_while_token_is_valid(tmp_path: Path) -> None:
    client, transport = _client(tmp_path, _login(), envelope(VEHICLES), envelope(VEHICLES))
    await client.acquire_vehicles()
    await client.acquire_vehicles()
    assert [r.operation for r in transport.requests].count("login") == 1


@pytest.mark.asyncio
async def test_expired_token_triggers_relogin_before_request(tmp_path: Path) -> None:
    client, transport = _client(tmp_path, _login(), envelope(VEHICLES))
    # first token expires within the 5 minute margin -> next use logs in again
    client.session.restore(BrTokens(fake_jwt(int(NOW) + 100), "r", float(int(NOW) + 100)))
    await client.acquire_vehicles()
    assert [r.operation for r in transport.requests] == ["login", "acquire_vehicles"]


@pytest.mark.asyncio
async def test_rejected_token_relogs_once_and_repeats_the_read(tmp_path: Path) -> None:
    client, transport = _client(tmp_path, _login(), html(401, "x"), _login(), envelope(VEHICLES))
    assert len(await client.acquire_vehicles()) == 1
    assert [r.operation for r in transport.requests] == ["login", "acquire_vehicles", "login", "acquire_vehicles"]


@pytest.mark.asyncio
async def test_credential_error_is_not_retried(tmp_path: Path) -> None:
    client, transport = _client(tmp_path, envelope(None, code="308001"))
    with pytest.raises(GwmBrCredentialError):
        await client.acquire_vehicles()
    assert [r.operation for r in transport.requests] == ["login"]


@pytest.mark.asyncio
async def test_malformed_payload_and_closed_client(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, _login(), envelope({"not": "a list"}))
    with pytest.raises(GwmSchemaError) as error:
        await client.acquire_vehicles()
    assert error.value.operation == "acquire_vehicles"
    await client.aclose()
    with pytest.raises(GwmClosedError):
        await client.acquire_vehicles()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "temperature"),
    [
        ({"latitude": "-1.25", "longitude": "2.5"}, None),  # items missing
        ({"items": None}, None),
        ({"items": [{"code": "2201001", "value": "not-a-number"}]}, None),  # non-numeric temperature
        ({"items": [{"code": "2201001", "value": None}, None, {"code": "  "}]}, None),
    ],
)
async def test_malformed_status_never_breaks_the_snapshot(tmp_path: Path, payload: dict, temperature: object) -> None:
    client, _ = _client(tmp_path, _login(), envelope(VEHICLES), envelope(payload))
    vehicles = await client.acquire_vehicles()
    status = await client.get_last_status(VIN)
    snapshot = map_vehicle_snapshot(
        vehicles[0], status, CloudVehicleBasics(), refreshed_at=datetime.now(UTC), remote_commands_available=False,
    )
    assert snapshot.values.interior_temperature_c is temperature
    assert snapshot.values.soc is None and snapshot.values.odometer_km is None


@pytest.mark.asyncio
@pytest.mark.parametrize("items", ["text", {"code": "2013021"}, 7])
async def test_status_items_of_invalid_type_are_a_schema_error_not_a_crash(tmp_path: Path, items: object) -> None:
    client, _ = _client(tmp_path, _login(), envelope({"items": items}))
    with pytest.raises(GwmSchemaError) as error:
        await client.get_last_status(VIN)
    assert error.value.operation == "get_last_status"
