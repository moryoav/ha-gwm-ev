"""Account and installation binding for APAC private state."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials
from custom_components.gwm_ora.gwm_client.apac_auth_client import ApacTokens
from custom_components.gwm_ora.gwm_client.apac_state import ApacAuthState, decode_apac_state, encode_apac_state
from custom_components.gwm_ora.gwm_client.eu_identity import EuIssuedIdentity


def _credentials(account: str = "synthetic@example.invalid", country: str = "PK", device: str = "a" * 32):
    """Construct credentials for a synthetic APAC account."""
    return ApacCredentials(account=account, password="synthetic-password", device_id=device, country=country)


def test_private_state_is_bound_to_account_country_and_device() -> None:
    """Bind APAC private state to the account, app country, and device identifier."""
    credentials = _credentials()
    state = ApacAuthState.for_credentials(credentials)
    assert state.matches(credentials)
    assert not state.matches(_credentials(account="different@example.invalid"))
    assert not state.matches(_credentials(country="TH"))
    assert not state.matches(_credentials(device="b" * 32))
    assert "synthetic" not in repr(state)
    assert credentials.account_binding != _credentials(country="TH").account_binding


def test_partial_state_and_identity_require_valid_dependencies() -> None:
    """Reject incomplete token and issued-identity dependency combinations."""
    state = ApacAuthState.for_credentials(_credentials())
    with pytest.raises(ValueError, match="^apac_state_invalid$"):
        replace(state, verification_requested_at=datetime(2026, 1, 1))
    identity = EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj")
    with pytest.raises(ValueError, match="^apac_state_invalid$"):
        replace(state, issued_identity=identity)
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    complete = replace(state, tokens=tokens, issued_identity=identity)
    assert complete.matches(_credentials())
    assert "synthetic" not in repr(complete)


def test_private_state_roundtrip_rejects_other_account_and_tampering() -> None:
    """Round-trip strict private state while rejecting account substitution and tampering."""
    credentials = _credentials()
    tokens = ApacTokens("synthetic-access", "synthetic-refresh", "synthetic-gw", "synthetic-bean")
    identity = EuIssuedIdentity("c3ludGhldGlj", "c3ludGhldGlj")
    state = replace(
        ApacAuthState.for_credentials(credentials),
        tokens=tokens,
        issued_identity=identity,
        verification_requested_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    encoded = encode_apac_state(state)
    assert decode_apac_state(encoded, credentials) == state
    for different in (
        _credentials(account="different@example.invalid"),
        _credentials(country="TH"),
        _credentials(device="b" * 32),
    ):
        with pytest.raises(ValueError, match="^apac_state_invalid$"):
            decode_apac_state(encoded, different)
    malformed = dict(encoded)
    malformed["tokens"] = {"access_token": "synthetic-access"}
    with pytest.raises(ValueError, match="^apac_state_invalid$"):
        decode_apac_state(malformed, credentials)
