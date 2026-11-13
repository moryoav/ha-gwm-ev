"""Account-bound BR credentials and private session state, read-only region."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .br_auth_client import BrTokens
from .br_identity import BrCredentials

BR_COUNTRY = "BR"
_BINDING = re.compile(r"[0-9a-f]{64}\Z")
_DEVICE = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class BrAccountCredentials:
    """Account, password and installation ID with the shape the cloud layer expects.

    Never log or repr this object. ``to_br_credentials`` derives the digest-only
    credential used on the wire.
    """

    account: str = field(repr=False)
    password: str = field(repr=False)
    device_id: str = field(repr=False)
    country: str = BR_COUNTRY

    def __post_init__(self) -> None:
        """Validate through the BR client's own credential rules."""
        if self.country != BR_COUNTRY:
            raise ValueError("br_credentials_invalid")
        # Raises ValueError("br_credentials_invalid") for any malformed value.
        self.to_br_credentials()

    def to_br_credentials(self) -> BrCredentials:
        """Build the wire credential (MD5 digest of the password)."""
        return BrCredentials.from_password(self.account, self.password, self.device_id)

    @property
    def account_binding(self) -> str:
        """Bind private session state to this region, country and account."""
        digest = hashlib.sha256()
        digest.update(b"gwm-br-account-binding-v1\0")
        digest.update(self.country.encode("ascii"))
        digest.update(b"\0")
        digest.update(self.account.encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class BrAuthState:
    """Private session state tied to an account and installation."""

    account_binding: str = field(repr=False)
    device_id: str = field(repr=False)
    country: str = BR_COUNTRY
    tokens: BrTokens | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject invalid or incomplete persisted session state."""
        if (
            not isinstance(self.account_binding, str)
            or _BINDING.fullmatch(self.account_binding) is None
            or not isinstance(self.device_id, str)
            or _DEVICE.fullmatch(self.device_id) is None
            or self.country != BR_COUNTRY
            or (self.tokens is not None and type(self.tokens) is not BrTokens)
        ):
            raise ValueError("br_state_invalid")

    @classmethod
    def for_credentials(cls, credentials: BrAccountCredentials) -> BrAuthState:
        """Create an empty state for one account and installation."""
        if type(credentials) is not BrAccountCredentials:
            raise ValueError("br_credentials_invalid")
        return cls(credentials.account_binding, credentials.device_id)

    def matches(self, credentials: BrAccountCredentials) -> bool:
        """Prevent reuse after the account or installation changes."""
        return type(credentials) is BrAccountCredentials and (
            self.account_binding == credentials.account_binding and self.device_id == credentials.device_id
        )


def encode_br_state(state: BrAuthState) -> dict[str, object]:
    """Serialize for private, account-bound storage; never log the output."""
    if type(state) is not BrAuthState:
        raise ValueError("br_state_invalid")
    tokens = state.tokens
    return {
        "account_binding": state.account_binding,
        "device_id": state.device_id,
        "tokens": None
        if tokens is None
        else {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_at": tokens.expires_at,
        },
    }


def decode_br_state(data: object) -> BrAuthState:
    """Decode a strict record."""
    try:
        if not isinstance(data, dict) or set(data) != {"account_binding", "device_id", "tokens"}:
            raise ValueError("br_state_invalid")
        token_data = data["tokens"]
        if token_data is not None and (
            not isinstance(token_data, dict) or set(token_data) != {"access_token", "refresh_token", "expires_at"}
        ):
            raise ValueError("br_state_invalid")
        expires_at = None if token_data is None else token_data["expires_at"]
        if expires_at is not None and (isinstance(expires_at, bool) or not isinstance(expires_at, int | float)):
            raise ValueError("br_state_invalid")
        tokens = (
            None
            if token_data is None
            else BrTokens(
                token_data["access_token"],
                token_data["refresh_token"],
                None if expires_at is None else float(expires_at),
            )
        )
        return BrAuthState(account_binding=data["account_binding"], device_id=data["device_id"], tokens=tokens)
    except (TypeError, ValueError, KeyError):
        raise ValueError("br_state_invalid") from None
