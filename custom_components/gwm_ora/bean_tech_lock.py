"""Prepare BeanTech lock credentials from the bundled GWM encoder."""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from pathlib import Path

from homeassistant.core import HomeAssistant
from homeassistant.requirements import RequirementsNotFound, async_process_requirements

from .const import DOMAIN
from .gwm_client.china_crypto import md5_hex

_ENCODER = Path(__file__).resolve().parent / "resources" / "beantech_lock_encoder.bin"
_ENCODER_SHA256 = "741c5d031404643b18b8d3efb8e42715a58e4875bcf9071a213313a9c678f687"
_ENCODER_REQUIREMENT = "unicorn==2.1.4"
_IMAGE = 0x100000
_WORK = 0x200000
_RETURN = 0x300000
_CIPHER_SIZE = 48
_IMPORTS = {
    0xA30: "memcpy",
    0xA50: "malloc",
    0xA80: "calloc",
    0xAC0: "memset",
    0xAF0: "strlen",
    0xB10: "free",
}


class BeanTechLockPreparationError(Exception):
    """The local encoder could not prepare a credential."""


async def async_prepare_bean_tech_lock_credential(hass: HomeAssistant, pin: str) -> str:
    """Encode the PIN off the event loop, loading the optional emulator on demand."""
    if re.fullmatch(r"[0-9]{6}", pin) is None:
        raise ValueError("bean_tech_lock_pin_invalid")
    try:
        if not hass.config.skip_pip:
            await async_process_requirements(hass, DOMAIN, [_ENCODER_REQUIREMENT], is_built_in=False)
        return await hass.async_add_executor_job(_prepare_credential, pin)
    except RequirementsNotFound:
        raise BeanTechLockPreparationError("bean_tech_lock_encoder_unavailable") from None


def _prepare_credential(pin: str) -> str:
    """Check the bundled bytes before passing them to the emulator."""
    try:
        bundle = _ENCODER.read_bytes()
    except OSError:
        raise BeanTechLockPreparationError("bean_tech_lock_encoder_unavailable") from None
    if hashlib.sha256(bundle).hexdigest() != _ENCODER_SHA256:
        raise BeanTechLockPreparationError("bean_tech_lock_encoder_invalid")
    # The first 16 bytes are the CBC IV passed by the app. The rest is the
    # original ARM64 encoder from the verified GWM Android package.
    try:
        from unicorn import UcError
    except (ImportError, OSError):
        raise BeanTechLockPreparationError("bean_tech_lock_encoder_unavailable") from None
    try:
        return _encode_pin(pin, iv=bundle[:16], library=bundle[16:])
    except UcError:
        raise BeanTechLockPreparationError("bean_tech_lock_encoding_failed") from None


def _encode_pin(pin: str, *, iv: bytes, library: bytes) -> str:
    """Run the pinned encoder routine with bounded memory and no system calls."""
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
    )

    arguments = (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
    )
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(_IMAGE, 0x60000)
    cpu.mem_map(_WORK, 0x100000)
    ph_offset, = struct.unpack_from("<Q", library, 0x20)
    ph_size, ph_count = struct.unpack_from("<HH", library, 0x36)
    for index in range(ph_count):
        kind, _, offset, address, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", library, ph_offset + index * ph_size,
        )
        if kind == 1:  # PT_LOAD
            cpu.mem_write(_IMAGE + address, library[offset:offset + size])
    for address, info, addend in struct.iter_unpack("<QQq", library[0x780:0x858]):
        if info == 1027:  # R_AARCH64_RELATIVE
            cpu.mem_write(_IMAGE + address, struct.pack("<Q", _IMAGE + addend))

    # Set up the stack guard and the encoder's initialized state.
    cpu.mem_write(_IMAGE + 0x48FC8, struct.pack("<Q", _WORK))
    cpu.mem_write(_IMAGE + 0x49280, struct.pack("<II", 1, 1))
    source, output, length, iv_addr = (_WORK + n for n in (0x100, 0x200, 0x300, 0x400))
    # The vendor format requires the lowercase MD5 digest as the encoder input.
    digest = md5_hex(pin).encode("ascii")
    cpu.mem_write(source, digest + b"\0")
    cpu.mem_write(length, struct.pack("<I", _CIPHER_SIZE))
    cpu.mem_write(iv_addr, iv)
    for register, value in zip(arguments, (source, len(digest), output, length, iv_addr, len(iv)), strict=True):
        cpu.reg_write(register, value)
    cpu.reg_write(UC_ARM64_REG_SP, _WORK + 0xF0000)
    cpu.reg_write(UC_ARM64_REG_LR, _RETURN)

    heap = _WORK + 0x4000

    def libc(machine: Uc, _address: int, _size: int, function: str) -> None:
        """Handle only the memory operations used by the encoder."""
        nonlocal heap
        a, b, c = (machine.reg_read(register) for register in arguments[:3])
        result = 0
        if function in {"malloc", "calloc"}:
            size = a if function == "malloc" else a * b
            result = heap
            heap += (size + 63) & ~63
            if heap >= _WORK + 0xE0000:
                raise BeanTechLockPreparationError("bean_tech_lock_encoding_failed")
        elif function == "memcpy":
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
        elif function == "memset":
            machine.mem_write(a, bytes([b & 255]) * c)
            result = a
        elif function == "strlen":
            result = len(machine.mem_read(a, 512).split(b"\0", 1)[0])
        machine.reg_write(UC_ARM64_REG_X0, result)
        machine.reg_write(UC_ARM64_REG_PC, machine.reg_read(UC_ARM64_REG_LR))

    for address, function in _IMPORTS.items():
        cpu.hook_add(UC_HOOK_CODE, libc, function, _IMAGE + address, _IMAGE + address)
    cpu.emu_start(_IMAGE + 0x1824, _RETURN, count=1_000_000)
    if (
        cpu.reg_read(UC_ARM64_REG_PC) != _RETURN
        or cpu.reg_read(UC_ARM64_REG_X0) != 0
        or bytes(cpu.mem_read(length, 4)) != struct.pack("<I", _CIPHER_SIZE)
    ):
        raise BeanTechLockPreparationError("bean_tech_lock_encoding_failed")
    return base64.b64encode(cpu.mem_read(output, _CIPHER_SIZE)).decode("ascii")
