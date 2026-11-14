"""Rendering of AuditReport: human-readable text and machine JSON."""

from __future__ import annotations

import json as _json
from dataclasses import asdict, is_dataclass
from typing import Any

from . import constants as C
from .engine import AuditReport
from .jsonmeta import as_uint64


_SEV_ORDER = {s: i for i, s in enumerate(
    (C.SEV_OK, C.SEV_INFO, C.SEV_WARNING, C.SEV_ERROR, C.SEV_CRITICAL))}


def exit_code(report: AuditReport) -> int:
    """Structural problems (on-disk format, checksums, JSON validity, cross
    copy consistency) -> 2. Cryptographic policy findings, including a
    CRITICAL-strength KDF parameterset, are still a *valid but weak* header
    and therefore -> 1."""
    structural_severity = {C.SEV_CRITICAL, C.SEV_ERROR}
    policy_actionable = {C.SEV_WARNING, C.SEV_ERROR, C.SEV_CRITICAL}
    has_structural = any(f.severity in structural_severity
                         for f in report.findings)
    has_weak_policy = any(
        v.severity in policy_actionable
        for verdicts in report.keyslot_verdicts.values() for v in verdicts)
    has_warning_finding = any(f.severity == C.SEV_WARNING
                              for f in report.findings)
    if has_structural:
        return C.EXIT_CORRUPT
    if has_weak_policy or has_warning_finding:
        return C.EXIT_WEAK
    return C.EXIT_CLEAN


def _sorted_findings(report: AuditReport):
    return sorted(report.findings,
                  key=lambda f: (-_SEV_ORDER[f.severity], f.where, f.code))


def _kdf_summary(slot_id: str, slot: dict[str, Any]) -> list[str]:
    kdf = slot.get("kdf", {})
    area = slot.get("area", {})
    lines = [f"  keyslot {slot_id}: type={slot.get('type')} "
             f"key_size={slot.get('key_size')}B "
             f"area={area.get('encryption', '?')} "
             f"@0x{str(area.get('offset', '0'))}"]
    kdf_type = kdf.get("type")
    if kdf_type in C.ARGON2_KDFS:
        mem = as_uint64(kdf.get("memory")) or 0
        lines.append(
            f"    KDF {kdf_type}: memory={mem} KiB ({mem / 1024:g} MiB) "
            f"time={kdf.get('time')} parallel={kdf.get('cpus')}")
    elif kdf_type == C.KDF_PBKDF2:
        lines.append(f"    KDF pbkdf2: hash={kdf.get('hash')} "
                     f"iterations={kdf.get('iterations')}")
    else:
        lines.append(f"    KDF {kdf_type!r}")
    return lines


def render_text(report: AuditReport) -> str:
    out: list[str] = []
    out.append("=" * 78)
    out.append(f"LUKS2 header audit: {report.path}")
    out.append("=" * 78)
    out.append(f"file size: {report.file_size} bytes "
               f"({report.file_size:#x})  LUKS version: "
               f"{report.luks_version or 'unknown'}")

    for role in ("primary", "secondary"):
        cr = report.copies.get(role)
        if cr is None or not cr.present:
            out.append(f"\n[{role}] not present")
            continue
        h = cr.hdr
        out.append(f"\n[{role}] disk offset 0x{cr.disk_offset:x}")
        if h and h.fields:
            f = h.fields
            out.append(f"  magic={f.get('magic').hex() if f.get('magic') else '?'} "
                       f"version={f.get('version')} hdr_size={f.get('hdr_size')} "
                       f"seqid={f.get('seqid')}")
            out.append(f"  label={f.get('label')!r} uuid={f.get('uuid')!r} "
                       f"subsystem={f.get('subsystem')!r}")
            out.append(f"  checksum_alg={f.get('csum_alg')!r} "
                       f"hdr_offset={f.get('hdr_offset')} "
                       f"salt={(f.get('salt') or b'').hex()[:32]}...")
        if cr.checksum_ok is True:
            out.append("  checksum: VERIFIED")
        elif cr.checksum_ok is False:
            out.append(f"  checksum: FAILED ({cr.checksum_reason})")
        else:
            out.append("  checksum: not evaluated")
        if cr.json_area:
            ja = cr.json_area
            out.append(f"  JSON area @0x{ja.disk_offset:x}, "
                       f"{ja.text_len} bytes used of {len(ja.raw)}")
            if ja.parse_error:
                out.append(f"  JSON parse: ERROR {ja.parse_error}")
            elif ja.parsed is not None:
                out.append("  JSON parse: OK")

    # keyslot KDF detail from the authoritative copy
    source = None
    for role in ("primary", "secondary"):
        cr = report.copies.get(role)
        if cr and cr.json_area and isinstance(cr.json_area.parsed, dict):
            source = cr
            break
    if source:
        slots = source.json_area.parsed.get("keyslots", {})
        out.append("\n-- keyslot KDF parameters (authoritative copy: "
                   f"{source.role}) --")
        for slot_id in sorted(slots, key=lambda x: (len(str(x)), str(x))):
            out.extend(_kdf_summary(str(slot_id), slots[slot_id]))

    verdicts_flat = [(sid, v) for sid, vs in report.keyslot_verdicts.items()
                     for v in vs]
    if verdicts_flat:
        out.append("\n-- KDF / key material verdicts --")
        for slot_id, v in sorted(verdicts_flat,
                                 key=lambda kv: (-_SEV_ORDER[kv[1].severity],
                                                 kv[0], kv[1].code)):
            out.append(f"  [{v.severity:8s}] {v.message}")
            if v.repair:
                out.append(f"             fix: {v.repair}")

    if report.findings:
        out.append("\n-- structural / consistency findings --")
        for f in _sorted_findings(report):
            loc = f" ({f.where})" if f.where else ""
            out.append(f"  [{f.severity:8s}] {f.code}{loc}: {f.message}")
            if f.repair:
                out.append(f"             fix: {f.repair}")
    else:
        out.append("\n-- no structural findings --")

    if report.repair_hints:
        out.append("\n-- repair guidance --")
        for hint in report.repair_hints:
            for i, line in enumerate(_wrap(hint, 74)):
                out.append(("   " if i else "  * ") + line)

    worst = report.worst_severity()
    out.append("\n" + "-" * 78)
    out.append(f"overall: {worst}   exit code: {exit_code(report)} "
               f"(0 clean / 1 weak crypto / 2 structural damage / 3 usage)")
    return "\n".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    if cur:
        lines.append(cur)
    return lines


def _default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    raise TypeError(f"not JSON serializable: {type(obj)!r}")


def render_json(report: AuditReport) -> str:
    payload = {
        "path": report.path,
        "file_size": report.file_size,
        "luks_version": report.luks_version,
        "worst_severity": report.worst_severity(),
        "exit_code": exit_code(report),
        "copies": {
            role: {
                "present": cr.present,
                "disk_offset": cr.disk_offset,
                "truncated": cr.truncated,
                "checksum_ok": cr.checksum_ok,
                "checksum_reason": cr.checksum_reason,
                "zero_region_issues": cr.zero_region_issues,
                "binary_fields": _safe_fields(cr),
                "json": None if cr.json_area is None else {
                    "disk_offset": cr.json_area.disk_offset,
                    "text_len": cr.json_area.text_len,
                    "area_len": len(cr.json_area.raw),
                    "parse_error": cr.json_area.parse_error,
                    "error_pos": cr.json_area.error_pos,
                    "padding_issue": cr.json_area.padding_issue,
                    "parsed": cr.json_area.parsed,
                    "schema_findings": [asdict(s) for s in cr.schema_findings],
                },
            }
            for role, cr in report.copies.items()
        },
        "keyslot_verdicts": {
            sid: [asdict(v) for v in vs]
            for sid, vs in report.keyslot_verdicts.items()
        },
        "findings": [asdict(f) for f in report.findings],
        "repair_hints": report.repair_hints,
    }
    return _json.dumps(payload, indent=2, default=_default, sort_keys=False)


def _safe_fields(cr) -> dict[str, Any]:
    if not cr.hdr:
        return {}
    out = {}
    for name, value in cr.hdr.fields.items():
        if isinstance(value, (bytes, bytearray)):
            out[name] = bytes(value).hex()
        else:
            out[name] = value
    return out
