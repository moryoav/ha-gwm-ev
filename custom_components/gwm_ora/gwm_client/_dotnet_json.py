"""Exact compact JSON encoding used by the legacy .NET GWM client."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

_HTML_SENSITIVE = frozenset({'"', "&", "'", "+", "<", ">", "`"})
_SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}
_MAX_DEPTH = 32


def encode_dotnet_json(value: object) -> str:
    """Serialize the finite auth payload types like System.Text.Json defaults."""

    return _encode_value(value, depth=0)


def _encode_value(value: object, *, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise ValueError("json_depth_invalid")
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return _encode_string(value)
    if type(value) is dict:
        mapping = value
        parts: list[str] = []
        for key, child in mapping.items():
            if type(key) is not str:
                raise ValueError("json_key_invalid")
            parts.append(
                _encode_string(key) + ":" + _encode_value(child, depth=depth + 1)
            )
        return "{" + ",".join(parts) + "}"
    if type(value) is list:
        sequence = cast(list[object], value)
        return "[" + ",".join(
            _encode_value(child, depth=depth + 1) for child in sequence
        ) + "]"
    if type(value) is tuple:
        tuple_sequence = cast(tuple[object, ...], value)
        return "[" + ",".join(
            _encode_value(child, depth=depth + 1) for child in tuple_sequence
        ) + "]"
    if isinstance(value, Mapping | Sequence):
        raise ValueError("json_container_invalid")
    raise ValueError("json_value_invalid")


def _encode_string(value: str) -> str:
    encoded: list[str] = ['"']
    for character in value:
        short = _SHORT_ESCAPES.get(character)
        if short is not None:
            encoded.append(short)
            continue
        codepoint = ord(character)
        if character == "\\":
            encoded.append("\\\\")
        elif 0x20 <= codepoint <= 0x7E and character not in _HTML_SENSITIVE:
            encoded.append(character)
        elif codepoint <= 0xFFFF:
            encoded.append(f"\\u{codepoint:04X}")
        else:
            scalar = codepoint - 0x10000
            high = 0xD800 + (scalar >> 10)
            low = 0xDC00 + (scalar & 0x3FF)
            encoded.append(f"\\u{high:04X}\\u{low:04X}")
    encoded.append('"')
    return "".join(encoded)


__all__ = ["encode_dotnet_json"]
