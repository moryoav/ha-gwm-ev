"""Async-client configuration contract tests."""

from __future__ import annotations

import math

import pytest

from gwm_client.config import GwmClientConfig, RequestTimeouts
from gwm_client.regions import Region


def test_client_config_normalizes_region_and_uses_bounded_defaults() -> None:
    config = GwmClientConfig(region=" EU ")

    assert config.region is Region.EU
    assert config.timeouts == RequestTimeouts()
    assert config.max_response_bytes == 4 * 1024 * 1024
    assert config.anz_authentication_method is None


def test_anz_config_defaults_to_legacy_and_accepts_current_method() -> None:
    assert GwmClientConfig(Region.ANZ).anz_authentication_method == "legacy_v1"
    assert (
        GwmClientConfig(
            Region.ANZ,
            anz_authentication_method="current_v2",
        ).anz_authentication_method
        == "current_v2"
    )


@pytest.mark.parametrize("method", ["unknown", "CURRENT", 1, False])
def test_anz_config_rejects_unknown_authentication_method(method: object) -> None:
    with pytest.raises(ValueError, match="^anz_authentication_method_invalid$"):
        GwmClientConfig(
            Region.ANZ,
            anz_authentication_method=method,  # type: ignore[arg-type]
        )


def test_non_anz_config_rejects_anz_authentication_method() -> None:
    with pytest.raises(ValueError, match="^anz_authentication_method_invalid$"):
        GwmClientConfig(Region.EU, anz_authentication_method="current_v2")


@pytest.mark.parametrize("region", ["", "usa", "eu/../rus", 1, None])
def test_client_config_rejects_unknown_region(region: object) -> None:
    with pytest.raises(ValueError, match="^region_invalid$"):
        GwmClientConfig(region=region)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "timeouts",
    [
        RequestTimeouts,
        lambda: RequestTimeouts(total=0),
        lambda: RequestTimeouts(total=-1),
        lambda: RequestTimeouts(total=math.inf),
        lambda: RequestTimeouts(total=math.nan),
        lambda: RequestTimeouts(total=1, connect=2),
        lambda: RequestTimeouts(total=1, read=2),
    ],
)
def test_request_timeouts_reject_invalid_values(timeouts: object) -> None:
    if timeouts is RequestTimeouts:
        assert RequestTimeouts().total == 30
        return
    with pytest.raises(ValueError, match="^timeouts_invalid$"):
        timeouts()  # type: ignore[operator]


@pytest.mark.parametrize("timeouts", [None, {}, object(), "not-timeouts"])
def test_client_config_requires_request_timeouts_instance(timeouts: object) -> None:
    with pytest.raises(ValueError, match="^timeouts_invalid$"):
        GwmClientConfig(region=Region.EU, timeouts=timeouts)  # type: ignore[arg-type]


@pytest.mark.parametrize("limit", [0, -1, True, 16 * 1024 * 1024 + 1])
def test_client_config_rejects_unsafe_response_limits(limit: int) -> None:
    with pytest.raises(ValueError, match="^response_limit_invalid$"):
        GwmClientConfig(region=Region.EU, max_response_bytes=limit)
