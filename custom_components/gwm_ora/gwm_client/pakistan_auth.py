"""Pakistan authentication request bodies; no network operations are performed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_DEVICE = re.compile(r"[0-9a-fA-F]{32}\Z")


@dataclass(frozen=True, slots=True)
class PakistanCredentials:
    """Private credentials for a Pakistan account and stable device identity."""

    account: str = field(repr=False)
    password: str = field(repr=False)
    device_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.account, self.password, self.device_id)):
            raise ValueError("pakistan_credentials_invalid")
        try:
            account_length = len(self.account.encode("utf-8"))
            password_length = len(self.password.encode("utf-8"))
        except UnicodeError:
            raise ValueError("pakistan_credentials_invalid") from None
        if (
            account_length > 1024
            or password_length > 1024
            or any(ord(c) < 0x20 for c in self.account + self.password)
            or _DEVICE.fullmatch(self.device_id) is None
        ):
            raise ValueError("pakistan_credentials_invalid")

    @property
    def account_type(self) -> str:
        return "2" if "@" in self.account else "1"


def login_body(credentials: PakistanCredentials, verification_code: str | None = None) -> dict[str, object]:
    """Construct a Pakistan login body from explicitly supplied credentials."""
    if type(credentials) is not PakistanCredentials:
        raise ValueError("pakistan_credentials_invalid")
    if verification_code is not None and (not isinstance(verification_code, str) or not verification_code):
        raise ValueError("pakistan_verification_invalid")
    body: dict[str, object] = {
        "account": credentials.account,
        "accountType": credentials.account_type,
        "countryCode": "+92",
        "agreement": [1, 2],
        "password": credentials.password,
        "deviceId": credentials.device_id,
        "appType": "0",
        "pushToken": "",
        "country": "PK",
    }
    if verification_code is not None:
        body.update(verifyCode=verification_code, validCodeMode="1")
    return body


def verification_body(credentials: PakistanCredentials, code: str | None = None) -> dict[str, object]:
    """Build either a verification request or code-check body."""
    if type(credentials) is not PakistanCredentials:
        raise ValueError("pakistan_credentials_invalid")
    if code is not None and (not isinstance(code, str) or not code):
        raise ValueError("pakistan_verification_invalid")
    body: dict[str, object] = {
        "type": "17",
        "account": credentials.account,
        "accountType": credentials.account_type,
        "countryCode": "+92",
        "validCodeMode": 1,
    }
    if code is None:
        body.update(operateCode="", captchaType="", captchaId="", token="")
    else:
        body["verifyCode"] = code
    return body
