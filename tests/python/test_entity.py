"""Tests for shared GWM entity helpers."""

from __future__ import annotations

import logging

import pytest


@pytest.mark.asyncio
async def test_cloud_call_failure_logs_only_sanitized_client_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pytest.importorskip("homeassistant")
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.gwm_ora import entity
    from gwm_client import GwmApiError

    async def rejected_call() -> None:
        raise GwmApiError(
            operation="send_cabin_clean_command",
            api_code="550002",
        )

    with caplog.at_level(logging.WARNING), pytest.raises(HomeAssistantError) as raised:
        await entity.async_call_gwm_api(rejected_call())

    assert raised.value.translation_key == "cloud_request_failed"
    records = [record for record in caplog.records if record.name == entity.__name__]
    assert len(records) == 1
    assert records[0].getMessage() == (
        "GWM cloud call failed: type=GwmApiError category=api_error "
        "operation=send_cabin_clean_command api_code=550002 "
        "http_status=None retry_after_seconds=None"
    )
