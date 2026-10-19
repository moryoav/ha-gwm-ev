"""Deterministic mainland-China protocol cryptography and clock helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = [
    "AUTO_AI_CKEY",
    "BEAN_TECH_APP_KEY",
    "DEFAULT_NOTE_ID",
    "ChinaCryptoError",
    "auto_ai_sign",
    "bean_tech_sign",
    "decrypt_g_app",
    "default_sign",
    "encrypt_g_app",
    "format_china_timestamp",
    "md5_hex",
    "sha256_hex",
    "to_china_time",
]

DEFAULT_NOTE_ID = "145765423214576567716671"
BEAN_TECH_APP_KEY = "7863128529"
AUTO_AI_CKEY = "ea49a50f914b8d38af1c84809d302683"

_DEFAULT_SECRET_32 = "E3*138%pb=GcflmhmsaA4WU^J-f&0Ofe"
_DEFAULT_SECRET_36 = "t8X_MybKFjp-Kg^mt99ALe-ArGzJE5mpCOra"
_BEAN_TECH_SECRET = "21382b32fea1d5fa03813d806d2dd64f"
_AUTO_AI_PRIVATE_KEY = "dad377585f566b548c961a418dcec41a"
_G_APP_PASSWORDS = {
    1: "Qin.1^0123456789abcdef0123456789abcdef0123456789abcdef012345cdef",
    2: "Gwn*9$0123456789abcdef0123456789abcdef0189abcdef0123456789abcdef",
}
_G_APP_PREFIX = b"Salted__"
_AES_BLOCK_BYTES = algorithms.AES.block_size // 8
_CHINA_TIME_ZONE = timezone(timedelta(hours=8))
_INT32_MIN = -(2**31)
_INT32_MAX = (2**31) - 1
_INT64_MIN = -(2**63)
_INT64_MAX = (2**63) - 1


class ChinaCryptoError(ValueError):
    """A safe, non-secret-bearing China protocol cryptography failure."""


def encrypt_g_app(plaintext: str, key_id: int = 1, *, salt: bytes | None = None) -> str:
    """Wrap UTF-8 text in the G-App OpenSSL-compatible ``G_A`` envelope.

    ``salt`` exists solely to make offline contract tests deterministic. Normal
    callers omit it and receive a fresh cryptographically random eight-byte salt.
    """

    if not isinstance(plaintext, str):
        raise TypeError("g_app_plaintext_invalid")
    password = _g_app_password(key_id)
    selected_salt = secrets.token_bytes(8) if salt is None else salt
    if not isinstance(selected_salt, bytes) or len(selected_salt) != 8:
        raise ChinaCryptoError("g_app_salt_invalid")

    key, initialization_vector = _derive_openssl_key(password, selected_salt)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    encoded = plaintext.encode("utf-8")
    padded = padder.update(encoded) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(initialization_vector)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    payload = base64.b64encode(_G_APP_PREFIX + selected_salt + ciphertext).decode("ascii")
    return f"G_A({payload},{key_id})"


def decrypt_g_app(wrapped: str) -> str:
    """Decrypt a G-App envelope, returning ordinary non-envelope text unchanged."""

    if not isinstance(wrapped, str):
        raise TypeError("g_app_wrapper_invalid")
    if not wrapped.startswith("G_A(") or not wrapped.endswith(")"):
        return wrapped

    separator = wrapped.rfind(",")
    if separator <= 4:
        raise ChinaCryptoError("g_app_wrapper_invalid")
    key_id = _parse_int32(wrapped[separator + 1 : -1])
    if key_id is None:
        raise ChinaCryptoError("g_app_wrapper_invalid")
    password = _g_app_password(key_id)

    encoded_payload = wrapped[4:separator]
    try:
        compact_payload = "".join(encoded_payload.split()).encode("ascii")
        encrypted = base64.b64decode(compact_payload, validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise ChinaCryptoError("g_app_payload_invalid") from error
    if (
        len(encrypted) < 32
        or len(encrypted) % _AES_BLOCK_BYTES != 0
        or encrypted[:8] != _G_APP_PREFIX
    ):
        raise ChinaCryptoError("g_app_payload_invalid")

    salt = encrypted[8:16]
    ciphertext = encrypted[16:]
    key, initialization_vector = _derive_openssl_key(password, salt)
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(initialization_vector)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as error:
        raise ChinaCryptoError("g_app_decryption_failed") from error
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ChinaCryptoError("g_app_plaintext_invalid") from error


def default_sign(
    method: str,
    signing_url: str,
    raw_body: str | None,
    headers: Mapping[str, str],
) -> str:
    """Create the SHA-256 signature used by the China G-App service."""

    timestamp = _header(headers, "Timestamp")
    authorization = _header(headers, "Authorization")
    device_id = _header(headers, "DeviceId")
    canonical = method.upper() + signing_url
    for name in (
        "AppId",
        "Authorization",
        "DeviceId",
        "NoteId",
        "SourceApp",
        "SourceAppVer",
        "SourceType",
        "Timestamp",
    ):
        canonical += f"{name.lower()}:{_header(headers, name)}"
    if method.casefold() != "get":
        canonical += "json=" + (raw_body or "")
    canonical += _default_derived_secret(timestamp, device_id, authorization)
    return sha256_hex(canonical)


def bean_tech_sign(
    method: str,
    path: str,
    nonce: str,
    timestamp: str,
    parameter: str,
) -> str:
    """Create the BeanTech SHA-256 signature using Java URL encoding rules."""

    decoded_path = "/" + "/".join(unquote(part) for part in path.split("/") if part)
    authorization = (
        f"bt-auth-appkey:{BEAN_TECH_APP_KEY}"
        f"bt-auth-nonce:{nonce}"
        f"bt-auth-timestamp:{timestamp}"
    )
    encoded = _java_url_encode(
        method.upper() + decoded_path + authorization + parameter + _BEAN_TECH_SECRET
    )
    for whitespace in ("+", "%20", "%0A", "%09", "%0D"):
        encoded = encoded.replace(whitespace, "")
    return sha256_hex(encoded)


def auto_ai_sign(timestamp: str) -> str:
    """Create the AutoAI HMAC-SHA1 signature."""

    key = f"C_KEY={AUTO_AI_CKEY}&API_KEY={_AUTO_AI_PRIVATE_KEY}".encode()
    message = f"SIGN_BODY=[]&SIGN_TIME={timestamp}".encode()
    return base64.b64encode(hmac.digest(key, message, "sha1")).decode("ascii")


def sha256_hex(value: str) -> str:
    """Return a lowercase SHA-256 digest for UTF-8 text."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def md5_hex(value: str) -> str:
    """Return the app-compatible lowercase MD5 digest for UTF-8 text."""

    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def to_china_time(instant: datetime) -> datetime:
    """Convert an aware instant to fixed UTC+08:00 without a time-zone database."""

    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("china_time_invalid")
    return instant.astimezone(_CHINA_TIME_ZONE)


def format_china_timestamp(instant: datetime) -> str:
    """Format the AutoAI local timestamp as ``yyyyMMddHHmmssfff``."""

    local = to_china_time(instant)
    return (
        f"{local.year:04d}{local.month:02d}{local.day:02d}"
        f"{local.hour:02d}{local.minute:02d}{local.second:02d}"
        f"{local.microsecond // 1000:03d}"
    )


def _g_app_password(key_id: int) -> str:
    if isinstance(key_id, bool) or not isinstance(key_id, int):
        raise ChinaCryptoError("g_app_key_id_unsupported")
    try:
        return _G_APP_PASSWORDS[key_id]
    except KeyError as error:
        raise ChinaCryptoError("g_app_key_id_unsupported") from error


def _derive_openssl_key(password: str, salt: bytes) -> tuple[bytes, bytes]:
    password_bytes = password.encode("utf-8")
    derived = b""
    previous = b""
    while len(derived) < 48:
        previous = hashlib.md5(
            previous + password_bytes + salt,
            usedforsecurity=False,
        ).digest()
        derived += previous
    return derived[:32], derived[32:48]


def _header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name, "")
    return value if isinstance(value, str) else ""


def _default_derived_secret(timestamp_text: str, device_id: str, authorization: str) -> str:
    timestamp = _parse_int64(timestamp_text)
    if timestamp is None:
        timestamp = 0
    index = _dotnet_remainder(_dotnet_remainder(timestamp, 100_000), 32)
    if index < 0:
        raise ChinaCryptoError("timestamp_invalid")

    source = _DEFAULT_SECRET_36
    if timestamp & 1 == 1:
        source = "".join(
            _DEFAULT_SECRET_36[(row * 6) + column]
            for column in range(6)
            for row in range(6)
        )
    repeated = source + source
    secret_selection = repeated[index : index + 6]
    device_offset = _dotnet_remainder(timestamp, 8)
    if device_offset < 0:
        raise ChinaCryptoError("timestamp_invalid")
    device_selection = (
        device_id[device_offset : device_offset + 6]
        if len(device_id) >= device_offset + 6
        else ""
    )
    trimmed_authorization = authorization.strip()
    auth_selection = (
        trimmed_authorization[3:9] if len(trimmed_authorization) > 9 else ""
    )
    return _DEFAULT_SECRET_32 + secret_selection + device_selection + auth_selection


def _parse_int32(value: str) -> int | None:
    parsed = _parse_integer(value)
    if parsed is None or not _INT32_MIN <= parsed <= _INT32_MAX:
        return None
    return parsed


def _parse_int64(value: str) -> int | None:
    parsed = _parse_integer(value)
    if parsed is None or not _INT64_MIN <= parsed <= _INT64_MAX:
        return None
    return parsed


def _parse_integer(value: str) -> int | None:
    try:
        normalized = value.strip()
        if not normalized or normalized.lstrip("+-").isdigit() is False:
            return None
        return int(normalized, 10)
    except (AttributeError, ValueError):
        return None


def _dotnet_remainder(dividend: int, divisor: int) -> int:
    quotient = abs(dividend) // divisor
    if dividend < 0:
        quotient = -quotient
    return dividend - (quotient * divisor)


def _java_url_encode(value: str) -> str:
    result: list[str] = []
    for octet in value.encode("utf-8"):
        character = chr(octet)
        if character.isascii() and (character.isalnum() or character in "-_.*"):
            result.append(character)
        elif character == " ":
            result.append("+")
        else:
            result.append(f"%{octet:02X}")
    return "".join(result)
