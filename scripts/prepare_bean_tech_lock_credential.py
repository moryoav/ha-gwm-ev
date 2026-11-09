"""Prepare a BeanTech lock credential offline using a supported GWM APK."""

import argparse
import base64
import getpass
import hashlib
import re
import struct
import warnings
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc, UcError
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

# Whole-file hashes of verified GWM-signed APKs, with their DEX array offsets.
_APK_KEY_OFFSETS = {
    # 2.2.0 (2200), downloaded from the official TANK site.
    "d227dac6c8507d5d96498c1e475cb0431e4437667ca0834c1e83062e74c1b9ca": 0x1FA5DE0,
    # 2.2.2 (2220), with the same signer and encoder as 2200.
    "6c0fb705850d96399efaf8bcd5725e3e93fc74656fcd0090c8387bfcd5dc3fd0": 0x2EFC098,
}
_IMAGE = 0x100000
_WORK = 0x200000
_RETURN = 0x300000
_ARGUMENTS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
              UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)
_CIPHER_SIZE = 48
_IMPORTS = {
    0xA30: "memcpy",
    0xA50: "malloc",
    0xA80: "calloc",
    0xAC0: "memset",
    0xAF0: "strlen",
    0xB10: "free",
}


def _read_app(apk_path: Path) -> tuple[bytes, bytes]:
    """Read the encoder inputs from the same APK file that passed the hash check."""
    # Read from the same open file that was hashed. The tool never installs or launches the app.
    with apk_path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest not in _APK_KEY_OFFSETS:
            raise ValueError("Use the supported GWM Android APK linked in the README.")
        with ZipFile(stream) as apk, apk.open("classes.dex") as dex:
            dex.seek(_APK_KEY_OFFSETS[digest])
            return dex.read(16), apk.read("lib/arm64-v8a/libsapp_crypto_tool.so")


def _encode_pin(pin: str, *, key: bytes, library: bytes) -> str:
    """Run the supported app's encoder in bounded, local emulated memory."""
    # Both supported APKs contain the same ARM64 encoder. Run just that routine in
    # emulated memory, with a small set of memory-only libc shims and no OS access.
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
    source, output, length, key_addr = (_WORK + n for n in (0x100, 0x200, 0x300, 0x400))
    # The vendor format requires a lowercase MD5 digest as the native encoder's
    # input. Keep that intermediate in memory and output only the encoded value.
    digest = hashlib.md5(pin.encode("ascii"), usedforsecurity=False).hexdigest().encode("ascii")
    cpu.mem_write(source, digest + b"\0")
    cpu.mem_write(length, struct.pack("<I", _CIPHER_SIZE))
    cpu.mem_write(key_addr, key)
    for register, value in zip(_ARGUMENTS, (source, len(digest), output, length, key_addr, len(key)), strict=True):
        cpu.reg_write(register, value)
    cpu.reg_write(UC_ARM64_REG_SP, _WORK + 0xF0000)
    cpu.reg_write(UC_ARM64_REG_LR, _RETURN)

    heap = _WORK + 0x4000

    def libc(machine: Uc, address: int, _size: int, function: str) -> None:
        """Handle only the memory operations imported by this encoder routine."""
        nonlocal heap
        a, b, c = (machine.reg_read(register) for register in _ARGUMENTS[:3])
        result = 0
        if function in {"malloc", "calloc"}:
            size = a if function == "malloc" else a * b
            result = heap
            heap += (size + 63) & ~63
            if heap >= _WORK + 0xE0000:
                raise ValueError("The app encoder ran out of working memory.")
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
        raise ValueError("The app encoder did not produce a lock credential.")
    return base64.b64encode(cpu.mem_read(output, _CIPHER_SIZE)).decode("ascii")


def main() -> None:
    """Read the PIN from a hidden terminal prompt and print the credential."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="Supported mainland-China GWM Android APK")
    args = parser.parse_args()
    try:
        key, library = _read_app(args.apk)
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            pin = getpass.getpass("GWM vehicle security PIN: ")
        if re.fullmatch(r"[0-9]{6}", pin) is None:
            raise ValueError("Enter the six digits you use in the GWM app.")
        credential = _encode_pin(pin, key=key, library=library)
    except ValueError as err:
        parser.error(str(err))
    except (BadZipFile, EOFError, getpass.GetPassWarning, OSError, UcError):
        parser.error("Could not prepare the credential. Run this in a terminal with a supported APK.")
    print(credential)


if __name__ == "__main__":
    main()
