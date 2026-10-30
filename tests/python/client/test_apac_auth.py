"""APAC authentication payloads use only synthetic inputs."""

import pytest

from custom_components.gwm_ora.gwm_client.apac_auth import ApacCredentials, login_body, verification_body


def test_synthetic_login_preserves_account_and_device() -> None:
    credentials = ApacCredentials("0123456789", "synthetic-password", "a" * 32, country="PK")
    assert "synthetic-password" not in repr(credentials)
    body = login_body(credentials, "123456")
    assert body["account"] == "0123456789"
    assert body["country"] == "PK"
    assert body["countryCode"] == "+92"
    assert body["accountType"] == "1"
    assert body["deviceId"] == "a" * 32
    assert body["validCodeMode"] == "1"


def test_email_verification_request_and_check() -> None:
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "b" * 32, country="PK")
    request = verification_body(credentials)
    assert request["accountType"] == "2"
    assert request["type"] == "17"
    assert "verifyCode" not in request
    checked = verification_body(credentials, "123456")
    assert checked["verifyCode"] == "123456"
    assert "captchaId" not in checked


def test_invalid_device_is_rejected_without_disclosing_it() -> None:
    with pytest.raises(ValueError, match="^apac_credentials_invalid$"):
        ApacCredentials("person@example.invalid", "synthetic-password", "invalid-device", country="PK")


@pytest.mark.parametrize("country,calling_code", [("TH", "+66"), ("MY", "+60"), ("ID", "+62"), ("PK", "+92")])
def test_selected_country_reaches_login_and_verification(country: str, calling_code: str) -> None:
    """Keep the country and calling code together for every APAC auth request."""
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, country=country)
    assert login_body(credentials)["country"] == country
    for body in (login_body(credentials), verification_body(credentials), verification_body(credentials, "123456")):
        assert body["countryCode"] == calling_code


@pytest.mark.parametrize("code", ["", "123\n456", "123\x00456", " 123456", "123456 ", "é", "x" * 65, 123456, False])
def test_invalid_verification_codes_fail_without_disclosure(code: object) -> None:
    """Apply the same bounded input contract to login and verification bodies."""
    credentials = ApacCredentials("person@example.invalid", "synthetic-password", "a" * 32, country="PK")
    for builder in (login_body, verification_body):
        with pytest.raises(ValueError, match="^apac_verification_invalid$"):
            builder(credentials, code)  # type: ignore[arg-type]
