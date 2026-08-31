"""Durable GWM cloud state and restart-safe journal tests."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("homeassistant")

from homeassistant.core import HomeAssistant

from custom_components.gwm_ora.cloud_auth import (
    CloudAuthState,
    GwmCloudCredentials,
    cloud_entry_data,
    cloud_unique_id,
)
from custom_components.gwm_ora.cloud_storage import (
    GwmOwnedChargingPlan,
    async_remove_cloud_state,
    cloud_authentication_context_binding,
    cloud_state_store,
)
from custom_components.gwm_ora.const import (
    ANZ_AUTHENTICATION_METHOD_CURRENT,
    ANZ_AUTHENTICATION_METHOD_LEGACY,
)
from gwm_client import (
    AnzAuthState,
    ChinaAuthState,
    EuAuthState,
    EuIssuedIdentity,
    RussiaAuthState,
)

_DEVICE_ID = "0123456789abcdef0123456789abcdef"
_NOW = datetime(2026, 8, 28, 18, 0, tzinfo=UTC)


def _credentials(
    region: str = "eu",
    *,
    password: str | None = "private-password",
    authentication_method: str | None = None,
) -> GwmCloudCredentials:
    countries = {"eu": "DE", "aus": "AU", "rus": "RU", "cn": "CN"}
    return GwmCloudCredentials(
        region,
        countries[region],
        "private-account",
        None if region == "cn" else password,
        _DEVICE_ID,
        authentication_method,
    )


def _state(credentials: GwmCloudCredentials) -> CloudAuthState:
    regional = credentials.client_credentials()
    if credentials.region == "eu":
        return replace(
            EuAuthState.for_credentials(regional),
            access_token="private-eu-access",
            refresh_token="private-eu-refresh",
            gw_id="private-eu-gw",
            bean_id="private-eu-bean",
            issued_identity=EuIssuedIdentity(
                certificate=base64.b64encode(b"synthetic-certificate").decode(),
                private_key=base64.b64encode(b"synthetic-private-key").decode(),
            ),
            verification_requested_at=_NOW,
        )
    if credentials.region == "aus":
        return replace(
            AnzAuthState.for_credentials(regional),
            access_token="private-anz-access",
            refresh_token="private-anz-refresh",
            verification_requested_at=_NOW,
        )
    if credentials.region == "rus":
        return replace(
            RussiaAuthState.for_credentials(regional),
            access_token="private-russia-access",
            refresh_token="private-russia-refresh",
            gw_id="private-russia-gw",
            bean_id="private-russia-bean",
            verification_requested_at=_NOW,
        )
    assert credentials.region == "cn"
    return replace(
        ChinaAuthState.for_credentials(regional),
        g_token="private-china-access",
        g_refresh_token="private-china-refresh",
        sso_token="private-china-sso",
        pt_token="private-china-pt",
        user_id="private-china-user",
        bean_id="private-china-bean",
        verification_requested_at=_NOW,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("region", ["eu", "aus", "rus", "cn"])
async def test_regional_auth_state_survives_a_process_restart(
    tmp_path: Path,
    region: str,
) -> None:
    credentials = _credentials(region)
    unique_id = cloud_unique_id(credentials)
    first_hass = HomeAssistant(str(tmp_path))
    first = cloud_state_store(first_hass, unique_id)

    await first.async_save_auth_state(credentials, _state(credentials))

    second_hass = HomeAssistant(str(tmp_path))
    restored = await cloud_state_store(
        second_hass,
        unique_id,
    ).async_load_auth_state(cloud_entry_data(credentials))

    assert restored == _state(credentials)
    assert "private" not in repr(restored)
    if isinstance(restored, ChinaAuthState):
        assert restored.has_g_app
        assert not restored.complete


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    [
        _credentials(password="replacement-password"),
        GwmCloudCredentials(
            "eu",
            "FR",
            "private-account",
            "private-password",
            _DEVICE_ID,
        ),
        GwmCloudCredentials(
            "eu",
            "DE",
            "replacement-account",
            "private-password",
            _DEVICE_ID,
        ),
        GwmCloudCredentials(
            "aus",
            "AU",
            "private-account",
            "private-password",
            _DEVICE_ID,
        ),
    ],
)
async def test_account_context_change_atomically_retires_state_and_commands(
    tmp_path: Path,
    changed: GwmCloudCredentials,
) -> None:
    credentials = _credentials()
    unique_id = cloud_unique_id(credentials)
    hass = HomeAssistant(str(tmp_path))
    store = cloud_state_store(hass, unique_id)
    await store.async_save_auth_state(credentials, _state(credentials))
    await store.async_record_accepted_command(
        credentials,
        vehicle_id="SYNTHETIC-VEHICLE",
        command_name="climate",
        cloud_command_id="SYNTHETIC-CLOUD-COMMAND",
        accepted_at=_NOW,
    )
    await store.async_set_owned_charging_plan(
        credentials,
        GwmOwnedChargingPlan(
            vehicle_id="LGWTEST0000000001",
            plan_id=42,
            plan_type=0,
            start_time_ms=1_800_000_000_000,
            end_time_ms=1_800_003_600_000,
        ),
    )

    assert cloud_authentication_context_binding(changed) != (
        cloud_authentication_context_binding(credentials)
    )
    assert await store.async_load_auth_state(cloud_entry_data(changed)) is None
    assert await store.async_get_command_journal(cloud_entry_data(changed)) == ()
    assert await store.async_get_owned_charging_plans(cloud_entry_data(changed)) == ()

    stored_text = next((tmp_path / ".storage").glob("gwm_ora.direct_cloud.*")).read_text()
    assert "private-eu-access" not in stored_text
    assert "SYNTHETIC-CLOUD-COMMAND" not in stored_text
    assert "LGWTEST0000000001" not in stored_text
    assert "private-account" not in stored_text
    assert "replacement-password" not in stored_text
    assert "replacement-account" not in stored_text


@pytest.mark.asyncio
async def test_anz_authentication_method_change_retires_legacy_session(
    tmp_path: Path,
) -> None:
    legacy = _credentials(
        "aus",
        authentication_method=ANZ_AUTHENTICATION_METHOD_LEGACY,
    )
    implicit_legacy = _credentials("aus")
    current = _credentials(
        "aus",
        authentication_method=ANZ_AUTHENTICATION_METHOD_CURRENT,
    )
    assert cloud_authentication_context_binding(legacy) == (
        cloud_authentication_context_binding(implicit_legacy)
    )
    assert cloud_authentication_context_binding(current) != (
        cloud_authentication_context_binding(legacy)
    )
    assert cloud_unique_id(current) == cloud_unique_id(legacy)

    hass = HomeAssistant(str(tmp_path))
    store = cloud_state_store(hass, cloud_unique_id(legacy))
    await store.async_save_auth_state(legacy, _state(legacy))

    assert await store.async_load_auth_state(cloud_entry_data(current)) is None

    current_state = _state(current)
    await store.async_save_auth_state(current, current_state)
    restarted_hass = HomeAssistant(str(tmp_path))
    restarted_store = cloud_state_store(restarted_hass, cloud_unique_id(current))
    assert await restarted_store.async_load_auth_state(
        cloud_entry_data(current)
    ) == current_state


@pytest.mark.asyncio
async def test_accepted_commands_are_serialized_and_restart_safe(
    tmp_path: Path,
) -> None:
    credentials = _credentials("aus")
    unique_id = cloud_unique_id(credentials)
    first_hass = HomeAssistant(str(tmp_path))
    first = cloud_state_store(first_hass, unique_id)
    await first.async_save_auth_state(credentials, _state(credentials))

    accepted = await asyncio.gather(
        *(
            first.async_record_accepted_command(
                credentials,
                vehicle_id="SYNTHETIC-VEHICLE",
                command_name="climate",
                cloud_command_id=f"SYNTHETIC-CLOUD-{index}",
                accepted_at=_NOW + timedelta(seconds=index),
            )
            for index in range(105)
        )
    )
    assert len({entry.journal_id for entry in accepted}) == 105
    assert all(entry.cloud_command_id not in repr(entry) for entry in accepted)
    assert "private" not in repr(first)

    second_hass = HomeAssistant(str(tmp_path))
    second = cloud_state_store(second_hass, unique_id)
    restored = await second.async_get_command_journal(cloud_entry_data(credentials))
    assert len(restored) == 100
    assert {entry.cloud_command_id for entry in restored} <= {
        f"SYNTHETIC-CLOUD-{index}" for index in range(105)
    }

    updated = await second.async_update_command(
        credentials,
        restored[0].journal_id,
        state="polling",
        updated_at=_NOW + timedelta(minutes=1),
    )
    assert updated.state == "polling"

    completed = await second.async_update_command(
        credentials,
        restored[0].journal_id,
        state="completed",
        updated_at=_NOW + timedelta(minutes=2),
    )
    with pytest.raises(ValueError):
        await second.async_update_command(
            credentials,
            completed.journal_id,
            state="polling",
            updated_at=_NOW + timedelta(minutes=3),
        )

    third_hass = HomeAssistant(str(tmp_path))
    after_update = await cloud_state_store(
        third_hass,
        unique_id,
    ).async_get_command_journal(cloud_entry_data(credentials))
    assert after_update[0].state == "completed"


@pytest.mark.asyncio
async def test_owned_charging_plan_is_restart_safe_replaceable_and_removable(
    tmp_path: Path,
) -> None:
    credentials = _credentials()
    unique_id = cloud_unique_id(credentials)
    first_hass = HomeAssistant(str(tmp_path))
    first = cloud_state_store(first_hass, unique_id)
    await first.async_save_auth_state(credentials, _state(credentials))
    initial = GwmOwnedChargingPlan(
        vehicle_id="LGWTEST0000000001",
        plan_id=None,
        plan_type=0,
        start_time_ms=1_800_000_000_000,
        end_time_ms=1_800_003_600_000,
        weeks="0101010",
    )
    await first.async_set_owned_charging_plan(credentials, initial)

    second_hass = HomeAssistant(str(tmp_path))
    second = cloud_state_store(second_hass, unique_id)
    assert await second.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == (initial,)
    confirmed = replace(initial, plan_id=42)
    await second.async_set_owned_charging_plan(credentials, confirmed)
    assert await second.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == (confirmed,)

    await second.async_remove_owned_charging_plan(credentials, initial.vehicle_id)
    assert await second.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == ()


@pytest.mark.asyncio
async def test_pre_task20_storage_without_charging_key_remains_loadable(
    tmp_path: Path,
) -> None:
    credentials = _credentials()
    unique_id = cloud_unique_id(credentials)
    first_hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(first_hass, unique_id).async_save_auth_state(
        credentials,
        _state(credentials),
    )
    path = next((tmp_path / ".storage").glob("gwm_ora.direct_cloud.*"))
    document = json.loads(path.read_text())
    document["data"].pop("charging_plans")
    path.write_text(json.dumps(document))

    second_hass = HomeAssistant(str(tmp_path))
    second = cloud_state_store(second_hass, unique_id)
    assert await second.async_load_auth_state(cloud_entry_data(credentials)) == _state(
        credentials
    )
    assert await second.async_get_owned_charging_plans(
        cloud_entry_data(credentials)
    ) == ()


@pytest.mark.asyncio
async def test_config_entry_removal_deletes_private_state(
    tmp_path: Path,
) -> None:
    credentials = _credentials("rus")
    unique_id = cloud_unique_id(credentials)
    hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(hass, unique_id).async_save_auth_state(
        credentials,
        _state(credentials),
    )
    paths = list((tmp_path / ".storage").glob("gwm_ora.direct_cloud.*"))
    assert len(paths) == 1

    await async_remove_cloud_state(hass, unique_id)

    assert not paths[0].exists()


@pytest.mark.asyncio
async def test_semantically_invalid_storage_fails_closed_and_is_overwritten(
    tmp_path: Path,
) -> None:
    credentials = _credentials()
    unique_id = cloud_unique_id(credentials)
    first_hass = HomeAssistant(str(tmp_path))
    await cloud_state_store(first_hass, unique_id).async_save_auth_state(
        credentials,
        _state(credentials),
    )
    path = next((tmp_path / ".storage").glob("gwm_ora.direct_cloud.*"))
    document = json.loads(path.read_text())
    document["data"]["auth_state"]["unexpected_secret"] = "must-be-removed"
    path.write_text(json.dumps(document))

    second_hass = HomeAssistant(str(tmp_path))
    restored = await cloud_state_store(
        second_hass,
        unique_id,
    ).async_load_auth_state(cloud_entry_data(credentials))

    assert restored is None
    rewritten = path.read_text()
    assert "must-be-removed" not in rewritten
    assert "private-eu-access" not in rewritten
