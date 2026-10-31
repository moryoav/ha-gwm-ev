"""Ensure APAC-shaped credentials never appear in diagnostics."""

from types import SimpleNamespace

import pytest

from custom_components.gwm_ora.diagnostics import async_get_config_entry_diagnostics


@pytest.mark.asyncio
async def test_apac_diagnostics_redact_synthetic_authentication_and_signing_data():
    """Exclude synthetic credentials, tokens, identity, and signing data from diagnostics."""
    secrets = {
        "account": "private-account",
        "password": "private-password",
        "accessToken": "private-access",
        "refreshToken": "private-refresh",
        "gwId": "private-gw-id",
        "beanId": "private-bean-id",
        "deviceId": "private-device",
        "app_key": "private-app-key",
        "app_secret": "private-signing-secret",
        "vin": "private-vehicle",
        "latitude": 12.345678,
        "longitude": 87.654321,
    }
    entry = SimpleNamespace(
        data={"region": "ap", "country": "PK", **secrets},
        options={},
        title="GWM APAC",
        unique_id="private-unique-id",
        runtime_data=SimpleNamespace(coordinator=SimpleNamespace(data={"vehicles": [secrets]})),
    )
    result = await async_get_config_entry_diagnostics(None, entry)
    assert result["entry"]["data"]["country"] == "PK"
    for secret in secrets.values():
        assert str(secret) not in str(result)
    assert "private-unique-id" not in str(result)
