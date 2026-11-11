"""BR account credentials, password digest and the persisted installation ID."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

_DEVICE_ID = re.compile(r"[0-9a-f]{32}\Z")
_MAX_ACCOUNT = 256
_MAX_PASSWORD = 256


def br_password_md5(password: str) -> str:
    """Lower-case MD5 hex of the plain password, as the BR login expects."""
    if not isinstance(password, str) or not password or len(password) > _MAX_PASSWORD:
        raise ValueError("br_credentials_invalid")
    return hashlib.md5(password.encode("utf-8"), usedforsecurity=False).hexdigest()


def generate_br_device_id() -> str:
    """MD5 hex of a random value; generate once per installation and persist it."""
    return hashlib.md5(secrets.token_bytes(16), usedforsecurity=False).hexdigest()


def validate_br_device_id(device_id: object) -> str:
    """Accept only a lower-case 32-hex installation ID."""
    if not isinstance(device_id, str) or _DEVICE_ID.fullmatch(device_id) is None:
        raise ValueError("br_device_id_invalid")
    return device_id


def load_or_create_br_device_id(path: Path) -> str:
    """Read or create a private file holding the installation ID (development helper).

    Home Assistant persists the ID in its own storage; this helper serves offline
    tools. The path must be supplied by the caller and kept outside the repository.
    """
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("br_device_id_invalid")
    try:
        return validate_br_device_id(path.read_text(encoding="ascii").strip())
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError):
        raise ValueError("br_device_id_invalid") from None
    device_id = generate_br_device_id()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(device_id)
    except OSError:
        raise ValueError("br_device_id_invalid") from None
    return device_id


@dataclass(frozen=True, slots=True)
class BrCredentials:
    """Account, password digest and installation ID. Never log or repr this object."""

    account: str = field(repr=False)
    password_md5: str = field(repr=False)
    device_id: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject malformed private state."""
        if (
            not isinstance(self.account, str)
            or not self.account.strip()
            or len(self.account) > _MAX_ACCOUNT
            or not isinstance(self.password_md5, str)
            or re.fullmatch(r"[0-9a-f]{32}", self.password_md5) is None
        ):
            raise ValueError("br_credentials_invalid")
        validate_br_device_id(self.device_id)

    @classmethod
    def from_password(cls, account: str, password: str, device_id: str) -> BrCredentials:
        """Build credentials, keeping only the MD5 digest of the password."""
        return cls(account, br_password_md5(password), device_id)

    def login_body(self) -> dict[str, object]:
        """Login payload: no verification code exists in this backend."""
        return {"deviceid": self.device_id, "password": self.password_md5, "account": self.account}
