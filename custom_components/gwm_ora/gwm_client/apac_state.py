"""Account-bound APAC state for private Home Assistant storage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .apac_auth import ApacCredentials
from .apac_auth_client import ApacTokens
from .apac_policy import validate_apac_country
from .eu_identity import EuIssuedIdentity

_BINDING = re.compile(r"[0-9a-f]{64}\Z")
_DEVICE = re.compile(r"[0-9a-fA-F]{32}\Z")


@dataclass(frozen=True, slots=True)
class ApacAuthState:
    """Private session state tied to an account, country, and installation."""

    account_binding: str = field(repr=False)
    country: str
    device_id: str = field(repr=False)
    tokens: ApacTokens | None = field(default=None, repr=False)
    issued_identity: EuIssuedIdentity | None = field(default=None, repr=False)
    verification_requested_at: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject invalid or incomplete persisted session state."""
        if (
            not isinstance(self.account_binding, str)
            or _BINDING.fullmatch(self.account_binding) is None
            or not isinstance(self.device_id, str)
            or _DEVICE.fullmatch(self.device_id) is None
        ):
            raise ValueError("apac_state_invalid")
        try:
            validate_apac_country(self.country)
        except (TypeError, ValueError):
            raise ValueError("apac_state_invalid") from None
        if self.tokens is not None and type(self.tokens) is not ApacTokens:
            raise ValueError("apac_state_invalid")
        if self.issued_identity is not None and (
            type(self.issued_identity) is not EuIssuedIdentity or self.tokens is None
        ):
            raise ValueError("apac_state_invalid")
        timestamp = self.verification_requested_at
        if timestamp is not None and (
            not isinstance(timestamp, datetime) or timestamp.tzinfo is None or timestamp.utcoffset() is None
        ):
            raise ValueError("apac_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: ApacCredentials) -> ApacAuthState:
        """Create an empty state for a single account and device."""
        if type(credentials) is not ApacCredentials:
            raise ValueError("apac_credentials_invalid")
        return cls(credentials.account_binding, credentials.country, credentials.device_id)

    def matches(self, credentials: ApacCredentials) -> bool:
        """Prevent reuse after the account, country or device changes."""
        return type(credentials) is ApacCredentials and (
            self.account_binding == credentials.account_binding
            and self.country == credentials.country
            and self.device_id == credentials.device_id
        )


def encode_apac_state(state: ApacAuthState) -> dict[str, object]:
    """Serialize state for private, account-bound storage; never log output."""
    if type(state) is not ApacAuthState:
        raise ValueError("apac_state_invalid")
    tokens = state.tokens
    identity = state.issued_identity
    return {
        "account_binding": state.account_binding,
        "country": state.country,
        "device_id": state.device_id,
        "tokens": None if tokens is None else {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "gw_id": tokens.gw_id,
            "bean_id": tokens.bean_id,
        },
        "issued_identity": None if identity is None else {
            "certificate": identity.certificate,
            "private_key": identity.private_key,
        },
        "verification_requested_at": (
            None if state.verification_requested_at is None else state.verification_requested_at.isoformat()
        ),
    }


def decode_apac_state(data: object, credentials: ApacCredentials | None = None) -> ApacAuthState:
    """Decode a strict record, optionally enforcing the caller's account context."""
    try:
        if (credentials is not None and type(credentials) is not ApacCredentials) or not isinstance(data, dict):
            raise ValueError("apac_state_invalid")
        if set(data) != {"account_binding", "country", "device_id", "tokens", "issued_identity", "verification_requested_at"}:
            raise ValueError("apac_state_invalid")
        token_data = data["tokens"]
        if token_data is not None and (
            not isinstance(token_data, dict)
            or set(token_data) != {"access_token", "refresh_token", "gw_id", "bean_id"}
        ):
            raise ValueError("apac_state_invalid")
        tokens = None if token_data is None else ApacTokens(**token_data)
        identity_data = data["issued_identity"]
        if identity_data is not None and (
            not isinstance(identity_data, dict) or set(identity_data) != {"certificate", "private_key"}
        ):
            raise ValueError("apac_state_invalid")
        identity = None if identity_data is None else EuIssuedIdentity(**identity_data)
        timestamp_value = data["verification_requested_at"]
        if timestamp_value is not None and not isinstance(timestamp_value, str):
            raise ValueError("apac_state_invalid")
        timestamp = None if timestamp_value is None else datetime.fromisoformat(timestamp_value)
        state = ApacAuthState(
            account_binding=data["account_binding"], country=data["country"], device_id=data["device_id"],
            tokens=tokens, issued_identity=identity, verification_requested_at=timestamp,
        )
        if credentials is not None and not state.matches(credentials):
            raise ValueError("apac_state_invalid")
        return state
    except (TypeError, ValueError, KeyError, OverflowError):
        raise ValueError("apac_state_invalid") from None
