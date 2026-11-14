"""
LUKS2 JSON metadata area handling.

The JSON area occupies (hdr_size - 4096) bytes immediately after the binary
header: one UTF-8 JSON object followed by NUL padding and nothing else
(validate_json_area() in cryptsetup requires a leading '{' and a purely
NUL tail). Large integers (sizes, offsets, iterations, memory, time ...) are
serialized as STRINGS per the LUKS2 on-disk format; key_size is a JSON number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from . import constants as C


@dataclass
class JsonArea:
    disk_offset: int                      # absolute offset of the area
    raw: bytes                            # full area incl. padding
    text: bytes = b""
    parsed: Optional[dict[str, Any]] = None
    parse_error: Optional[str] = None
    error_pos: Optional[int] = None       # byte offset inside the area
    padding_issue: Optional[str] = None
    text_len: int = 0                     # bytes before first NUL


def extract_json(area: bytes, disk_offset: int) -> JsonArea:
    ja = JsonArea(disk_offset=disk_offset, raw=bytes(area))
    if not area:
        ja.parse_error = "empty JSON area"
        return ja
    if area[0:1] != b"{":
        ja.parse_error = "JSON area does not start with '{'"
        ja.error_pos = 0
        return ja

    nul = area.find(b"\x00")
    if nul == -1:
        # cryptsetup requires room for a trailing NUL; treat as malformed.
        ja.parse_error = "JSON area has no NUL terminator"
        ja.text = bytes(area)
        ja.text_len = len(area)
    else:
        ja.text = bytes(area[:nul])
        ja.text_len = nul
        tail = area[nul:]
        if any(tail):
            first = nul + next(i for i, b in enumerate(tail) if b)
            ja.padding_issue = (f"non-zero byte in JSON padding at area+0x{first:x} "
                                f"(disk offset 0x{disk_offset + first:x})")
    try:
        ja.parsed = json.loads(ja.text.decode("utf-8"))
    except UnicodeDecodeError as exc:
        ja.parse_error = f"JSON text is not valid UTF-8: {exc}"
        ja.error_pos = getattr(exc, "start", None)
    except json.JSONDecodeError as exc:
        ja.parse_error = f"invalid JSON: {exc.msg}"
        ja.error_pos = exc.pos
    return ja


def as_uint64(value: Any) -> Optional[int]:
    """LUKS2 large integers arrive as decimal strings; tolerate plain ints
    too, flagging the latter at the schema layer."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        s = value.strip()
        if not s or not s.isdigit():
            return None
        try:
            return int(s)
        except ValueError:
            return None
    return None


@dataclass
class SchemaFinding:
    code: str
    severity: str
    message: str
    path: str = ""


def _require_object(findings: list[SchemaFinding], parent: Any, key: str,
                    path: str) -> Optional[dict[str, Any]]:
    if not isinstance(parent, dict) or key not in parent:
        findings.append(SchemaFinding("JSON_MISSING_SECTION", C.SEV_ERROR,
                                      f"missing top-level section {key!r}", path))
        return None
    if not isinstance(parent[key], dict):
        findings.append(SchemaFinding("JSON_BAD_TYPE", C.SEV_ERROR,
                                      f"section {key!r} must be a JSON object", path))
        return None
    return parent[key]


def _numbered_name_ok(name: str) -> bool:
    return bool(name) and all(ch.isdigit() for ch in name)


def _check_keyslot(name: str, slot: Any,
                   findings: list[SchemaFinding]) -> None:
    p = f"keyslots.{name}"
    if not _numbered_name_ok(name):
        findings.append(SchemaFinding("JSON_BAD_NAME", C.SEV_ERROR,
                                      f"keyslot name {name!r} is not a numbered id", p))
    if not isinstance(slot, dict):
        findings.append(SchemaFinding("JSON_BAD_TYPE", C.SEV_ERROR,
                                      "keyslot entry must be an object", p))
        return

    if not isinstance(slot.get("type"), str) or not slot["type"]:
        findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                      "keyslot missing string 'type'", p))

    key_size = slot.get("key_size")
    if isinstance(key_size, bool) or not isinstance(key_size, int) or key_size <= 0:
        findings.append(SchemaFinding("JSON_BAD_TYPE", C.SEV_ERROR,
                                      "keyslot 'key_size' must be a positive integer", p))
    elif key_size > 0xFFFFFFFF:
        findings.append(SchemaFinding("JSON_BAD_RANGE", C.SEV_ERROR,
                                      "keyslot 'key_size' exceeds uint32", p))

    area = slot.get("area")
    if not isinstance(area, dict):
        findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                      "keyslot missing 'area' object", p))
    else:
        for field_name in ("type", "offset", "size", "encryption"):
            if field_name not in area:
                findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                              f"area missing {field_name!r}",
                                              f"{p}.area"))
        for field_name in ("offset", "size"):
            if field_name in area and as_uint64(area[field_name]) is None:
                findings.append(SchemaFinding("JSON_BAD_NUMBER", C.SEV_ERROR,
                                              f"area.{field_name} is not a uint64 string",
                                              f"{p}.area"))
            elif isinstance(area[field_name], int):
                findings.append(SchemaFinding("JSON_NUMBER_AS_INT", C.SEV_WARNING,
                                              f"area.{field_name} should be a quoted string",
                                              f"{p}.area"))

    kdf = slot.get("kdf")
    if not isinstance(kdf, dict):
        findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                      "keyslot missing 'kdf' object", p))
    else:
        kdf_type = kdf.get("type")
        if not isinstance(kdf_type, str) or not kdf_type:
            findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                          "kdf missing string 'type'", f"{p}.kdf"))
        salt = kdf.get("salt")
        if not isinstance(salt, str) or not salt:
            findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                          "kdf missing base64 'salt'", f"{p}.kdf"))
        if kdf_type in C.ARGON2_KDFS:
            for field_name in ("time", "memory", "cpus"):
                if field_name not in kdf:
                    findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                                  f"argon2 kdf missing {field_name!r}",
                                                  f"{p}.kdf"))
                elif as_uint64(kdf[field_name]) is None:
                    findings.append(SchemaFinding("JSON_BAD_NUMBER", C.SEV_ERROR,
                                                  f"kdf.{field_name} not a uint64 string",
                                                  f"{p}.kdf"))
        elif kdf_type == C.KDF_PBKDF2:
            for field_name in ("iterations", "hash"):
                if field_name not in kdf:
                    findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                                  f"pbkdf2 kdf missing {field_name!r}",
                                                  f"{p}.kdf"))
            if "iterations" in kdf and as_uint64(kdf["iterations"]) is None:
                findings.append(SchemaFinding("JSON_BAD_NUMBER", C.SEV_ERROR,
                                              "kdf.iterations not a uint64 string",
                                              f"{p}.kdf"))

    af = slot.get("af")
    if not isinstance(af, dict):
        findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                      "keyslot missing 'af' object", p))
    elif not isinstance(af.get("type"), str) or not af["type"]:
        findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                      "af missing string 'type'", f"{p}.af"))


def validate_metadata(doc: dict[str, Any]) -> list[SchemaFinding]:
    """Structural / semantic validation independent of the binary header."""
    findings: list[SchemaFinding] = []
    if not isinstance(doc, dict):
        return [SchemaFinding("JSON_BAD_TYPE", C.SEV_ERROR,
                              "top-level JSON value must be an object", "")]

    sections: dict[str, dict[str, Any]] = {}
    for key in C.JSON_REQUIRED_TOP_KEYS:
        obj = _require_object(findings, doc, key, "")
        if obj is not None:
            sections[key] = obj
    if len(sections) < len(C.JSON_REQUIRED_TOP_KEYS):
        return findings

    keyslots, digests = sections["keyslots"], sections["digests"]
    segments, tokens, config = (sections["segments"], sections["tokens"],
                                sections["config"])

    if len(keyslots) > C.LUKS2_OBJECTS_MAX:
        findings.append(SchemaFinding("JSON_TOO_MANY", C.SEV_ERROR,
                                      f"more than {C.LUKS2_OBJECTS_MAX} keyslots",
                                      "keyslots"))
    for name, slot in keyslots.items():
        _check_keyslot(name, slot, findings)

    if not segments:
        findings.append(SchemaFinding("JSON_EMPTY", C.SEV_ERROR,
                                      "segments section must not be empty",
                                      "segments"))
    for name, seg in segments.items():
        if not _numbered_name_ok(name):
            findings.append(SchemaFinding("JSON_BAD_NAME", C.SEV_ERROR,
                                          f"segment name {name!r} not numbered",
                                          f"segments.{name}"))
        if not isinstance(seg, dict):
            continue
        for field_name in ("type", "offset", "size"):
            if field_name not in seg:
                findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                              f"segment missing {field_name!r}",
                                              f"segments.{name}"))
        if seg.get("type") == "crypt":
            for field_name in ("iv_tweak", "encryption"):
                if not isinstance(seg.get(field_name), str):
                    findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                                  f"crypt segment missing string {field_name!r}",
                                                  f"segments.{name}"))
            sector = seg.get("sector_size")
            if isinstance(sector, bool) or not isinstance(sector, int) or sector <= 0:
                findings.append(SchemaFinding("JSON_BAD_TYPE", C.SEV_ERROR,
                                              "sector_size must be a positive integer",
                                              f"segments.{name}"))
            elif sector % 512:
                findings.append(SchemaFinding("JSON_BAD_ALIGN", C.SEV_ERROR,
                                              "sector_size must be 512-byte aligned",
                                              f"segments.{name}"))

    for name, digest in digests.items():
        if not _numbered_name_ok(name):
            findings.append(SchemaFinding("JSON_BAD_NAME", C.SEV_ERROR,
                                          f"digest name {name!r} not numbered",
                                          f"digests.{name}"))
        if not isinstance(digest, dict):
            continue
        if not isinstance(digest.get("type"), str):
            findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                          "digest missing string 'type'",
                                          f"digests.{name}"))
        for ref_key, known in (("keyslots", keyslots), ("segments", segments)):
            refs = digest.get(ref_key)
            if not isinstance(refs, list) or not refs:
                findings.append(SchemaFinding("JSON_MISSING_FIELD", C.SEV_ERROR,
                                              f"digest missing non-empty {ref_key} array",
                                              f"digests.{name}"))
                continue
            for ref in refs:
                if str(ref) not in known:
                    findings.append(SchemaFinding("JSON_DANGLING_REF", C.SEV_ERROR,
                                                  f"digest references unknown {ref_key[:-1]} {ref!r}",
                                                  f"digests.{name}"))

    for name, token in tokens.items():
        if not _numbered_name_ok(name):
            findings.append(SchemaFinding("JSON_BAD_NAME", C.SEV_WARNING,
                                          f"token name {name!r} not numbered (allowed for user tokens)",
                                          f"tokens.{name}"))
        if isinstance(token, dict):
            for ref in token.get("keyslots", []) or []:
                if str(ref) not in keyslots:
                    findings.append(SchemaFinding("JSON_DANGLING_REF", C.SEV_ERROR,
                                                  f"token references unknown keyslot {ref!r}",
                                                  f"tokens.{name}"))

    cfg_json_size = as_uint64(config.get("json_size"))
    cfg_keyslots_size = as_uint64(config.get("keyslots_size"))
    if "json_size" in config and cfg_json_size is None:
        findings.append(SchemaFinding("JSON_BAD_NUMBER", C.SEV_ERROR,
                                      "config.json_size not a uint64 string", "config"))
    if "keyslots_size" in config and cfg_keyslots_size is None:
        findings.append(SchemaFinding("JSON_BAD_NUMBER", C.SEV_ERROR,
                                      "config.keyslots_size not a uint64 string", "config"))

    findings.extend(_check_area_intervals(keyslots, config))
    return findings


def _check_area_intervals(keyslots: dict[str, Any],
                          config: dict[str, Any]) -> list[SchemaFinding]:
    """Mirror cryptsetup validate_intervals(): areas must be outside both
    metadata regions, non-empty, in bounds, and pairwise non-overlapping."""
    out: list[SchemaFinding] = []
    intervals: list[tuple[int, int, str]] = []
    keyslots_size = as_uint64(config.get("keyslots_size"))
    metadata_size = as_uint64(config.get("json_size"))
    if metadata_size is not None:
        metadata_size += C.LUKS2_HDR_BIN_LEN

    for name, slot in keyslots.items():
        if not isinstance(slot, dict) or not isinstance(slot.get("area"), dict):
            continue
        area = slot["area"]
        off = as_uint64(area.get("offset"))
        size = as_uint64(area.get("size"))
        if off is None or size is None:
            continue
        p = f"keyslots.{name}.area"
        if size == 0:
            out.append(SchemaFinding("JSON_BAD_RANGE", C.SEV_ERROR,
                                     "keyslot area has zero length", p))
        if metadata_size is not None and off < 2 * metadata_size:
            out.append(SchemaFinding("JSON_BAD_RANGE", C.SEV_ERROR,
                                     f"area offset 0x{off:x} overlaps metadata region "
                                     f"(must be >= 0x{2 * metadata_size:x})", p))
        if keyslots_size is not None and metadata_size is not None:
            end_bound = 2 * metadata_size + keyslots_size
            if off + size > end_bound:
                out.append(SchemaFinding("JSON_BAD_RANGE", C.SEV_ERROR,
                                         f"area [0x{off:x}, 0x{off + size:x}) exceeds "
                                         f"keyslots area end 0x{end_bound:x}", p))
        intervals.append((off, size, name))

    for i in range(len(intervals)):
        off_a, size_a, name_a = intervals[i]
        for j in range(i + 1, len(intervals)):
            off_b, size_b, name_b = intervals[j]
            if off_a < off_b + size_b and off_b < off_a + size_a:
                out.append(SchemaFinding("JSON_AREA_OVERLAP", C.SEV_ERROR,
                                         f"keyslot areas {name_a} and {name_b} overlap",
                                         "keyslots"))
    return out
