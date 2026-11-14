"""
LUKS2 binary header parsing and checksum verification.

Reference: struct luks2_hdr_disk in cryptsetup lib/luks2/luks2.h and
hdr_checksum_calculate() / hdr_checksum_check() in
lib/luks2/luks2_disk_metadata.c.

The checksum is hash(csum_alg) over the 4096-byte binary header with its
own 64-byte csum field zeroed, immediately followed by the ENTIRE JSON
area (hdr_size - 4096 bytes, NUL padding included).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from . import constants as C


@dataclass
class BinaryHeader:
    """One parsed copy of the 4096-byte binary header."""

    disk_offset: int
    raw: bytes
    truncated: bool = False
    fields: dict[str, Any] = field(default_factory=dict)
    magic_ok: bool = False
    is_secondary: bool = False
    is_luks1: bool = False

    @property
    def hdr_size(self) -> Optional[int]:
        return self.fields.get("hdr_size")

    @property
    def seqid(self) -> Optional[int]:
        return self.fields.get("seqid")


def _nul_terminated(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def parse_binary_header(data: bytes, disk_offset: int,
                        expect_secondary: bool = False) -> BinaryHeader:
    """Parse as many header fields as the available bytes allow.

    Never raises on malformed input; the audit layer decides severity.
    """
    hdr = BinaryHeader(disk_offset=disk_offset, raw=bytes(data[:C.LUKS2_HDR_BIN_LEN]))
    if len(data) < C.LUKS2_HDR_BIN_LEN:
        hdr.truncated = True

    def have(off: int, length: int) -> bool:
        return len(data) >= off + length

    parsed: dict[str, Any] = {}
    for name, (off, length, fmt) in C.HDR_FIELDS.items():
        if not have(off, length):
            parsed[name] = None
            continue
        chunk = data[off:off + length]
        if fmt is None:
            if name in ("label", "csum_alg", "uuid", "subsystem"):
                parsed[name] = _nul_terminated(chunk)
            else:
                parsed[name] = bytes(chunk)
        else:
            parsed[name] = struct.unpack(fmt, chunk)[0]
    hdr.fields = parsed

    magic = parsed.get("magic") or b""
    if magic == C.MAGIC_LUKS2_SECONDARY:
        hdr.magic_ok = True
        hdr.is_secondary = True
    elif magic == C.MAGIC_LUKS:
        hdr.magic_ok = True
        hdr.is_secondary = False
        if parsed.get("version") == C.LUKS1_VERSION:
            hdr.is_luks1 = True
    return hdr


def checksum_alg_supported(alg: str) -> bool:
    if not alg:
        return False
    try:
        hashlib.new(alg)
    except (ValueError, TypeError):
        return False
    return True


def compute_checksum(csum_alg: str, binary_hdr: bytes, json_area: bytes) -> bytes:
    """Recompute the on-disk checksum. Caller passes the raw stored header;
    this function zeroes the csum field itself, mirroring cryptsetup."""
    off, length, _ = C.HDR_FIELDS["csum"]
    zeroed = bytearray(binary_hdr[:C.LUKS2_HDR_BIN_LEN])
    zeroed[off:off + length] = b"\x00" * length
    h = hashlib.new(csum_alg)
    h.update(bytes(zeroed))
    h.update(json_area)
    return h.digest()


def verify_checksum(hdr: BinaryHeader, json_area: bytes) -> tuple[bool, str]:
    """Return (ok, reason). reason is empty on success."""
    alg = hdr.fields.get("csum_alg") or ""
    if not checksum_alg_supported(alg):
        return False, f"unsupported checksum algorithm {alg!r}"
    if hdr.truncated or len(hdr.raw) < C.LUKS2_HDR_BIN_LEN:
        return False, "binary header truncated, cannot verify checksum"
    if hdr.hdr_size is None:
        return False, "hdr_size unreadable"
    expected_json_len = hdr.hdr_size - C.LUKS2_HDR_BIN_LEN
    if len(json_area) < expected_json_len:
        return False, (f"JSON area truncated: have {len(json_area)} bytes, "
                       f"need {expected_json_len}")
    digest = compute_checksum(alg, hdr.raw, json_area[:expected_json_len])
    stored = hdr.fields.get("csum") or b""
    if stored[:len(digest)] != digest:
        return False, (f"{alg} digest mismatch over 4096-byte header + "
                       f"{expected_json_len}-byte JSON area")
    return True, ""


def check_zero_regions(hdr: BinaryHeader) -> list[tuple[str, int, int]]:
    """Return (region_name, first_bad_offset, length) for non-zero reserved
    regions. Offsets are relative to the start of the binary header."""
    problems = []
    if hdr.truncated:
        return problems
    for name, off, length in C.HDR_ZERO_REGIONS:
        region = hdr.raw[off:off + length]
        if region and any(region):
            first = off + next(i for i, b in enumerate(region) if b)
            problems.append((name, first, length))
    return problems


def diff_ranges(a: bytes, b: bytes, base: int = 0,
                span: Optional[int] = None) -> list[tuple[int, int, bytes, bytes]]:
    """Locate every contiguous differing byte range.

    Returns (start_abs, end_exclusive_abs, bytes_from_a, bytes_from_b).
    Ranges are capped per contiguous run, so a single flipped bit reports a
    one-byte range; a wiped sector reports one 4096-byte range.
    """
    n = min(len(a), len(b)) if span is None else min(span, len(a), len(b))
    out: list[tuple[int, int, bytes, bytes]] = []
    i = 0
    while i < n:
        if a[i] == b[i]:
            i += 1
            continue
        start = i
        while i < n and a[i] != b[i]:
            i += 1
        out.append((base + start, base + i, a[start:i], b[start:i]))
    return out


def describe_field(name: str, value: Any) -> str:
    if isinstance(value, bytes):
        if name == "csum":
            return value.hex() or "(absent)"
        if name in ("magic", "salt"):
            return value.hex()
        return _nul_terminated(value)
    return repr(value)
