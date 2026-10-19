"""Offline byte-level contract tests for mainland-China protocol cryptography."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta, timezone

import pytest

from custom_components.gwm_ora.gwm_client.china_crypto import (
    AUTO_AI_CKEY,
    BEAN_TECH_APP_KEY,
    DEFAULT_NOTE_ID,
    ChinaCryptoError,
    auto_ai_sign,
    bean_tech_sign,
    decrypt_g_app,
    default_sign,
    encrypt_g_app,
    format_china_timestamp,
    md5_hex,
    sha256_hex,
    to_china_time,
)

_LOGICAL_JSON = '{"phone":"13800138000","flag":"LOGIN"}'
_FIXED_SALT = bytes(range(8))


def test_csharp_signing_vectors_match_exactly() -> None:
    headers = {
        "Authorization": "token-abcdef123456",
        "SourceApp": "GWM",
        "SourceType": "ANDROID",
        "SourceAppVer": "2.1.5",
        "Timestamp": "1723456789000",
        "DeviceId": "0123456789abcdef0123456789abcdef",
        "AppId": "GWM-APP-ANDROID-1100018",
        "NoteId": DEFAULT_NOTE_ID,
    }

    assert default_sign(
        "POST",
        "https://gapp-api.gwmapp-h.com/api-guser/v5/token/refresh",
        '{"token":"abc","refreshToken":"def"}',
        headers,
    ) == "ef8be13f75ea09d4f0c009b6cf870b21a4f1a91b2269ba15fff9e852f2051bad"
    assert bean_tech_sign(
        "POST",
        "/app-api/api/v1.0/userAuth/loginSSOAccount",
        "0123456789abcdef",
        "1723456789123",
        'json={"appType":0,"deviceId":"abc"}',
    ) == "70b1d45225c49dfa9086528eaf7df04e578df1b2df46dfce5135ebec77641b3b"
    assert auto_ai_sign("1723456789123") == "bI5QLYve+aQBeu2pyb0yLUf3GuU="


@pytest.mark.parametrize(
    ("key_id", "expected"),
    [
        (
            1,
            "G_A(U2FsdGVkX18AAQIDBAUGB84kYI08waPbOtl1yrYKHmW52HxpOxE/9dmTl8NMzsil"
            "Iisb9iJWuKv92AIIZJruqA==,1)",
        ),
        (
            2,
            "G_A(U2FsdGVkX18AAQIDBAUGBxT90esG0BQgaKEUMVmZGc8NWZusJtiMRxkXmfK0oiwx"
            "yI/qKbwiOuDmbtjKlhdi2Q==,2)",
        ),
    ],
)
def test_g_app_fixed_salt_ciphertext_matches_openssl_envelope(
    key_id: int,
    expected: str,
) -> None:
    encrypted = encrypt_g_app(_LOGICAL_JSON, key_id, salt=_FIXED_SALT)

    assert encrypted == expected
    assert decrypt_g_app(encrypted) == _LOGICAL_JSON


@pytest.mark.parametrize(
    "plaintext",
    ["", "a" * 15, "b" * 16, "c" * 17, "长城汽车 🚙"],
)
@pytest.mark.parametrize("key_id", [1, 2])
def test_g_app_round_trip_covers_padding_and_utf8_boundaries(
    plaintext: str,
    key_id: int,
) -> None:
    assert decrypt_g_app(encrypt_g_app(plaintext, key_id, salt=b"12345678")) == plaintext


def test_g_app_random_salt_is_fresh_and_embedded() -> None:
    first = encrypt_g_app("same plaintext")
    second = encrypt_g_app("same plaintext")

    assert first != second
    assert decrypt_g_app(first) == "same plaintext"
    assert decrypt_g_app(second) == "same plaintext"


@pytest.mark.parametrize("salt", [b"1234567", b"123456789", bytearray(b"12345678"), "12345678"])
def test_g_app_rejects_non_eight_byte_salts_without_echoing_them(salt: object) -> None:
    with pytest.raises(ChinaCryptoError, match="^g_app_salt_invalid$") as raised:
        encrypt_g_app("private plaintext", salt=salt)  # type: ignore[arg-type]

    assert "private plaintext" not in str(raised.value)
    assert str(salt) not in str(raised.value)


@pytest.mark.parametrize("key_id", [0, 3, -1, True, "1", None])
def test_g_app_rejects_unsupported_key_ids_without_echoing_them(key_id: object) -> None:
    with pytest.raises(ChinaCryptoError, match="^g_app_key_id_unsupported$") as raised:
        encrypt_g_app("private plaintext", key_id)  # type: ignore[arg-type]

    assert "private plaintext" not in str(raised.value)
    assert str(key_id) not in str(raised.value)


@pytest.mark.parametrize("ordinary", ["", "{}", "G_A(not-closed,1", "prefix G_A(data,1)"])
def test_g_app_non_envelopes_are_returned_unchanged(ordinary: str) -> None:
    assert decrypt_g_app(ordinary) == ordinary


@pytest.mark.parametrize(
    ("wrapped", "category"),
    [
        ("G_A(,1)", "g_app_wrapper_invalid"),
        ("G_A(not-base64,1)", "g_app_payload_invalid"),
        ("G_A(U2FsdGVkX18=,1)", "g_app_payload_invalid"),
        ("G_A(U2FsdGVkX18xMjM0NTY3ODAxMjM0NTY3OA==,1)", "g_app_payload_invalid"),
        ("G_A(U2FsdGVkX18xMjM0NTY3OAECAwQFBgcICQoLDA0ODxA=,1)", "g_app_decryption_failed"),
        ("G_A(U2FsdGVkX18xMjM0NTY3OFXJqKGnNol8F3doCZP2PiI=,0)", "g_app_key_id_unsupported"),
        ("G_A(U2FsdGVkX18xMjM0NTY3OFXJqKGnNol8F3doCZP2PiI=,2147483648)", "g_app_wrapper_invalid"),
    ],
)
def test_g_app_malformed_envelopes_fail_with_safe_categories(
    wrapped: str,
    category: str,
) -> None:
    with pytest.raises(ChinaCryptoError, match=f"^{category}$") as raised:
        decrypt_g_app(wrapped)

    assert wrapped not in str(raised.value)


def test_g_app_base64_accepts_whitespace_like_dotnet() -> None:
    wrapped = encrypt_g_app(_LOGICAL_JSON, salt=_FIXED_SALT)
    split = wrapped.index(",")
    with_whitespace = wrapped[:12] + " \r\n\t" + wrapped[12:split] + " " + wrapped[split:]

    assert decrypt_g_app(with_whitespace) == _LOGICAL_JSON


def test_g_app_rejects_corrupted_padding_without_exposing_ciphertext() -> None:
    wrapped = encrypt_g_app("a" * 17, salt=_FIXED_SALT)
    corrupted = _flip_encrypted_byte(wrapped, 31, 0x01)

    with pytest.raises(ChinaCryptoError, match="^g_app_decryption_failed$") as raised:
        decrypt_g_app(corrupted)

    assert corrupted not in str(raised.value)


def test_g_app_rejects_malformed_utf8_without_exposing_ciphertext() -> None:
    wrapped = encrypt_g_app("a" * 17, salt=_FIXED_SALT)
    corrupted = _flip_encrypted_byte(wrapped, 16, 0x9E)

    with pytest.raises(ChinaCryptoError, match="^g_app_plaintext_invalid$") as raised:
        decrypt_g_app(corrupted)

    assert corrupted not in str(raised.value)


def test_default_get_signature_uses_odd_timestamp_transposition_and_ignores_body() -> None:
    headers = {
        "Authorization": " token-abcdef123456 ",
        "SourceApp": "GWM",
        "SourceType": "ANDROID",
        "SourceAppVer": "2.1.5",
        "Timestamp": "1723456789001",
        "DeviceId": "0123456789abcdef0123456789abcdef",
        "AppId": "GWM-APP-ANDROID-1100018",
        "NoteId": DEFAULT_NOTE_ID,
    }

    expected = "4d5eb1824ecb358c08fe1e5a83d2fa4f55d62bc4664a2c1087751b0b65f05639"
    assert default_sign("GET", "https://example.invalid/a?x=1", "ignored", headers) == expected
    assert default_sign("get", "https://example.invalid/a?x=1", "different", headers) == expected


def test_default_signature_header_lookup_is_case_sensitive_like_csharp() -> None:
    lowercase_headers = {
        "authorization": "token-abcdef123456",
        "timestamp": "1723456789000",
        "deviceid": "0123456789abcdef0123456789abcdef",
    }

    assert default_sign("GET", "https://example.invalid", None, lowercase_headers) == default_sign(
        "GET",
        "https://example.invalid",
        None,
        {},
    )


def test_bean_tech_decodes_path_before_java_encoding_and_removes_whitespace() -> None:
    assert bean_tech_sign(
        "get",
        "/app-api/%E8%BD%A6%20state",
        "non ce",
        "1723456789123",
        "b=two words\na=1",
    ) == "25416a31c8702e02b01998de038c5ce4e10cb64f354402014edf999622b6f5b9"


def test_digest_helpers_match_app_lowercase_utf8_contract() -> None:
    assert sha256_hex("长城") == "c9917b939d6974deb36c64f782d0a8106546a889495d7847ab49d4af58ab53c0"
    assert md5_hex("LGWTEST0000000001auto-token") == "a2367cbc4c4dc97a97917339d5e89fe7"


def test_china_clock_uses_fixed_utc_plus_eight_and_millisecond_precision() -> None:
    instant = datetime(2026, 8, 26, 16, 30, 0, 123999, tzinfo=UTC)

    china = to_china_time(instant)

    assert china.utcoffset() == timedelta(hours=8)
    assert china == datetime(2026, 8, 27, 0, 30, 0, 123999, tzinfo=timezone(timedelta(hours=8)))
    assert china.timestamp() == instant.timestamp()
    assert format_china_timestamp(instant) == "20260827003000123"


def test_china_clock_converts_non_utc_aware_inputs_by_instant() -> None:
    source = datetime(2026, 1, 1, 12, 0, 0, 999, tzinfo=timezone(timedelta(hours=-5)))

    assert format_china_timestamp(source) == "20260102010000000"


@pytest.mark.parametrize("instant", [datetime(2026, 1, 1), None, "2026-01-01"])
def test_china_clock_rejects_values_without_an_instant(instant: object) -> None:
    with pytest.raises(ValueError, match="^china_time_invalid$"):
        to_china_time(instant)  # type: ignore[arg-type]


def test_only_protocol_header_constants_are_public_app_derived_constants() -> None:
    assert DEFAULT_NOTE_ID == "145765423214576567716671"
    assert BEAN_TECH_APP_KEY == "7863128529"
    assert AUTO_AI_CKEY == "ea49a50f914b8d38af1c84809d302683"


def _flip_encrypted_byte(wrapped: str, index: int, mask: int) -> str:
    separator = wrapped.rfind(",")
    encrypted = bytearray(base64.b64decode(wrapped[4:separator], validate=True))
    encrypted[index] ^= mask
    return f"G_A({base64.b64encode(encrypted).decode('ascii')}{wrapped[separator:]}"
