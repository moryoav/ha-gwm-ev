"""Offline APAC climate contract tests with deliberately synthetic values."""

import asyncio
import json
import logging
import ssl
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from custom_components.gwm_ora.cloud_commands import GwmCommandApi
from custom_components.gwm_ora.cloud_runtime import GwmCloudClient
from custom_components.gwm_ora.cloud_storage import GwmCommandJournalEntry
from custom_components.gwm_ora.const import REGION_APAC
from custom_components.gwm_ora.gwm_client._protocol import _TransportResponse
from custom_components.gwm_ora.gwm_client.apac_climate import (
    climate_defaults_payload,
    climate_payload,
    validate_climate_defaults_payload,
    validate_climate_payload,
)
from custom_components.gwm_ora.gwm_client.apac_identity import _register_validated_context
from custom_components.gwm_ora.gwm_client.apac_material import ApacMaterial
from custom_components.gwm_ora.gwm_client.apac_read import ApacReadClient, ApacReadSession
from custom_components.gwm_ora.gwm_client.commands import ClimateCommand, RemoteCommandResultItem
from custom_components.gwm_ora.gwm_client.errors import GwmDeadlineExceededError, GwmRoutePolicyError
from custom_components.gwm_ora.gwm_client.eu_identity import EuBootstrapMaterial
from custom_components.gwm_ora.gwm_client.models import VehicleIdentifier
from custom_components.gwm_ora.gwm_client.regions import TlsMode


@pytest.mark.parametrize(("mode", "switch", "duration"), [("auto", "1", "15"), ("off", "2", "0")])
def test_climate_payload_matches_observed_apac_contract(mode, switch, duration):
    """Preserve the separate APAC start/stop values and minute-based duration."""
    command = ClimateCommand(VehicleIdentifier("SYNTHETIC-VEHICLE"), mode, 22, 15)
    payload = climate_payload(command, security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")
    assert payload == {
        "instructions": {"0x04": {"airConditioner": {
            "operationTime": duration, "switchOrder": switch, "temperature": "22",
        }}},
        "remoteType": "0",
        "securityPassword": "a" * 32,
        "seqNo": "b" * 32 + "1234",
        "type": 2,
        "vin": "SYNTHETIC-VEHICLE",
    }


@pytest.mark.parametrize(("pin_hash", "sequence"), [("bad", "b" * 32 + "1234"), ("a" * 32, "bad")])
def test_climate_payload_rejects_invalid_command_material(pin_hash, sequence):
    """Reject malformed credentials and sequence numbers before network I/O."""
    command = ClimateCommand(VehicleIdentifier("SYNTHETIC-VEHICLE"), "auto", 22, 15)
    with pytest.raises(ValueError, match="apac_climate_command_invalid"):
        climate_payload(command, security_password_hash=pin_hash, sequence_number=sequence)


def test_climate_request_rejects_other_vehicle_instructions():
    """Do not allow the climate endpoint to become a generic command route."""
    command = ClimateCommand(VehicleIdentifier("SYNTHETIC-VEHICLE"), "auto", 22, 15)
    payload = climate_payload(command, security_password_hash="a" * 32, sequence_number="b" * 32 + "1234")
    payload["instructions"]["0x05"] = {"switchOrder": "1"}
    with pytest.raises(ValueError, match="apac_climate_command_invalid"):
        validate_climate_payload(payload, command.identifier.value)


def test_climate_defaults_follow_previous_apac_seconds_format():
    """Retain the previously used settings write and reject unrelated fields."""
    vehicle = VehicleIdentifier("SYNTHETIC-VEHICLE")
    body = climate_defaults_payload(vehicle, 22, 15)
    assert body == {"airConditionerTemperature": "22", "airConditionerTime": "900", "vin": vehicle.value}
    validate_climate_defaults_payload(body, vehicle.value)
    body["unrelated"] = "synthetic"
    with pytest.raises(ValueError):
        validate_climate_defaults_payload(body, vehicle.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_id", [None, "different-provider-id"])
async def test_apac_result_uses_legacy_fallback_when_id_does_not_match(monkeypatch, provider_id, caplog):
    """Verify the test build accepts the first result returned for the queried command."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    entry = GwmCommandJournalEntry("a" * 32, "SYNTHETIC-VEHICLE", "A/C", "b" * 32 + "1234", "polling", now, now)
    class Cloud:
        region = REGION_APAC
        async def async_get_remote_command_results(self, identifier, command_id):
            assert command_id == entry.cloud_command_id
            return (RemoteCommandResultItem(provider_id, "0x04", "0", "Success"),)
    api = object.__new__(GwmCommandApi)
    api._cloud = Cloud()
    api._commands = {entry.journal_id: entry}
    api._timeout_ids = set()
    api._clock = lambda: now
    async def update(current, **changes):
        updated = replace(current, **changes)
        api._commands[updated.journal_id] = updated
        return updated
    monkeypatch.setattr(api, "_durably_update_command", update)
    with caplog.at_level(logging.DEBUG, logger="custom_components.gwm_ora.cloud_commands"):
        result = await api.async_get_command(entry.journal_id)
    assert result["state"] == "completed"
    assert "APAC command result candidates=1 matching_id=0" in caplog.text
    assert ("missing_id=1" if provider_id is None else "different_id=1") in caplog.text
    assert "SYNTHETIC-VEHICLE" not in caplog.text
    assert entry.cloud_command_id not in caplog.text
    assert "different-provider-id" not in caplog.text


@pytest.mark.asyncio
async def test_climate_client_sends_one_request_and_reads_its_result():
    """Use synthetic transport to verify command path, headers, body and response."""
    class Transport:
        def __init__(self): self.requests = []
        async def execute(self, request, **kwargs):
            self.requests.append(request)
            data = [] if request.method == "GET" else None
            return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": data}).encode())
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    result = await client.send_climate_command(ClimateCommand(identifier, "auto", 22, 15), security_password_hash="a" * 32)
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request.method == "POST" and request.url.endswith("/vehicle/T5/sendCmd")
    assert request.headers["vin"] == identifier.value
    assert json.loads(request.body)["seqNo"] == result.command_id
    assert await client.get_remote_command_results(identifier, result.command_id) == ()
    assert transport.requests[1].url.endswith("?seqNo=" + result.command_id)
    assert transport.requests[1].headers["vin"] == identifier.value


@pytest.mark.asyncio
async def test_runtime_requires_explicit_apac_consent_and_never_replays_timeout():
    """A write with an uncertain outcome is sent only once and is not retried."""
    class Transport:
        def __init__(self): self.calls = 0
        async def execute(self, request, **kwargs):
            self.calls += 1
            raise TimeoutError
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    command = ClimateCommand(identifier, "auto", 22, 15)
    disabled = GwmCloudClient(REGION_APAC, client, climate_commands_enabled=True)
    disabled._vehicles[identifier.value] = object()
    with pytest.raises(GwmRoutePolicyError):
        await disabled.async_send_climate_command(command, security_password_hash="a" * 32)
    assert transport.calls == 0
    enabled = GwmCloudClient(REGION_APAC, client, apac_climate_enabled=True)
    enabled._vehicles[identifier.value] = object()
    with pytest.raises(GwmDeadlineExceededError):
        await enabled.async_send_climate_command(command, security_password_hash="a" * 32)
    assert transport.calls == 1


@pytest.mark.asyncio
async def test_runtime_does_not_send_if_session_validation_fails(monkeypatch):
    """Account/session validation must complete before an APAC vehicle write."""
    from custom_components.gwm_ora.gwm_client.errors import GwmAuthenticationError

    class Transport:
        def __init__(self): self.calls = 0
        async def execute(self, request, **kwargs): self.calls += 1
    context = ssl.create_default_context()
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_climate_enabled=True)
    cloud._vehicles[identifier.value] = object()
    cloud._credentials = object()
    retired = []
    async def retire(): retired.append(True)
    monkeypatch.setattr(cloud, "async_authentication_rejected", retire)
    async def reject(*, force_refresh):
        assert force_refresh is False
        raise GwmAuthenticationError(operation="get_user_info")
    monkeypatch.setattr(cloud, "_async_validate_apac_session", reject)
    with pytest.raises(GwmAuthenticationError):
        await cloud.async_send_climate_command(ClimateCommand(identifier, "auto", 22, 15), security_password_hash="a" * 32)
    assert transport.calls == 0
    assert retired == [True]


@pytest.mark.asyncio
async def test_rejected_write_session_is_retired_without_retry(monkeypatch):
    """An expiry response to a write is not resent and invalidates the session."""
    from custom_components.gwm_ora.gwm_client.errors import GwmApiError, GwmAuthenticationError

    class Transport:
        def __init__(self): self.calls = 0
        async def execute(self, request, **kwargs):
            self.calls += 1
            raise GwmApiError(operation="send_climate_command", api_code="551004")
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_climate_enabled=True)
    cloud._vehicles[identifier.value] = object()
    retired = []
    async def retire(): retired.append(True)
    monkeypatch.setattr(cloud, "async_authentication_rejected", retire)
    with pytest.raises(GwmAuthenticationError):
        await cloud.async_send_climate_command(ClimateCommand(identifier, "auto", 22, 15), security_password_hash="a" * 32)
    assert transport.calls == 1
    assert retired == [True]


@pytest.mark.asyncio
async def test_climate_api_dispatches_only_after_consent(monkeypatch):
    """Exercise the Home Assistant command adapter through a synthetic transport."""
    class Transport:
        def __init__(self): self.operations = []
        async def execute(self, request, **kwargs):
            self.operations.append(request.operation)
            return _TransportResponse(200, {}, json.dumps({"code": "000000", "data": {}}).encode())
    context = ssl.create_default_context()
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    _register_validated_context(context, TlsMode.APAC_ISSUED_MTLS)
    material = ApacMaterial(EuBootstrapMaterial(b"fake", b"fake", b"fake"), "fake-key", "fake-secret")
    transport = Transport()
    client = ApacReadClient(material=material, session=ApacReadSession("a" * 32, "fake-token", context, "PK"), transport=transport)
    identifier = VehicleIdentifier("SYNTHETIC-VEHICLE")
    cloud = GwmCloudClient(REGION_APAC, client, apac_climate_enabled=True)
    cloud._vehicles[identifier.value] = object()
    api = object.__new__(GwmCommandApi)
    api._cloud = cloud
    api._enabled = True
    api._apac_climate_enabled = True
    api._security_pin = "1234"
    api._climate_defaults = {}
    async def record(identifier, name, command_id):
        return {"name": name, "command_id": command_id}
    monkeypatch.setattr(api, "_record_acceptance", record)
    result = await api.async_set_climate(identifier.value, mode="auto", temperature=22)
    assert result["name"] == "A/C"
    assert transport.operations == ["get_vehicle_basics", "update_climate_defaults", "send_climate_command"]


@pytest.mark.asyncio
async def test_cancelled_apac_command_finishes_recording_accepted_result(monkeypatch):
    """Cancellation waits for the single send and acceptance journal to finish."""
    from custom_components.gwm_ora.gwm_client.apac_dispatch import mark_apac_dispatch_started
    from custom_components.gwm_ora.gwm_client.commands import RemoteCommandAcceptance

    api = object.__new__(GwmCommandApi)
    started = asyncio.Event()
    release = asyncio.Event()
    recorded = []
    async def send():
        mark_apac_dispatch_started()
        started.set()
        await release.wait()
        return RemoteCommandAcceptance("synthetic-command")
    async def record(identifier, name, command_id):
        recorded.append((name, command_id))
        return {"state": "in_progress"}
    monkeypatch.setattr(api, "_record_acceptance", record)
    task = asyncio.create_task(api._async_submit_apac(VehicleIdentifier("SYNTHETIC-VEHICLE"), "A/C", send))
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert recorded == [("A/C", "synthetic-command")]
