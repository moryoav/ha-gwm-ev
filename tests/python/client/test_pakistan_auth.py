"""Pakistan authentication payloads use only synthetic inputs."""

import pytest

from custom_components.gwm_ora.gwm_client.pakistan_auth import PakistanCredentials, login_body, verification_body


def test_synthetic_login_preserves_account_and_device() -> None:
    credentials = PakistanCredentials("0123456789", "synthetic-password", "a" * 32)
    assert "synthetic-password" not in repr(credentials)
    body = login_body(credentials, "123456")
    assert body["account"] == "0123456789"
    assert body["country"] == "PK"
    assert body["countryCode"] == "+92"
    assert body["accountType"] == "1"
    assert body["deviceId"] == "a" * 32
    assert body["validCodeMode"] == "1"


def test_email_verification_request_and_check() -> None:
    credentials = PakistanCredentials("person@example.invalid", "synthetic-password", "b" * 32)
    request = verification_body(credentials)
    assert request["accountType"] == "2"
    assert request["type"] == "17"
    assert "verifyCode" not in request
    checked = verification_body(credentials, "123456")
    assert checked["verifyCode"] == "123456"
    assert "captchaId" not in checked


def test_invalid_device_is_rejected_without_disclosing_it() -> None:
    with pytest.raises(ValueError, match="^pakistan_credentials_invalid$"):
        PakistanCredentials("person@example.invalid", "synthetic-password", "invalid-device")
