"""
Audit engine: ties binary parsing, JSON metadata and KDF policy together.

The target is opened read-only with O_RDONLY (no O_RDWR anywhere in the
project) and read with pread-style seeks, so block devices and regular disk
images are handled identically. Nothing here ever writes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from . import constants as C
from . import binary as B
from . import jsonmeta as J
from . import kdfpolicy as K


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    where: str = ""          # "primary" | "secondary" | "both" | "cross"
    repair: Optional[str] = None


@dataclass
class CopyReport:
    role: str                # "primary" | "secondary"
    disk_offset: int
    present: bool = False
    truncated: bool = False
    hdr: Optional[B.BinaryHeader] = None
    json_area: Optional[J.JsonArea] = None
    checksum_ok: Optional[bool] = None
    checksum_reason: str = ""
    zero_region_issues: list[str] = field(default_factory=list)
    schema_findings: list[J.SchemaFinding] = field(default_factory=list)


@dataclass
class AuditReport:
    path: str
    file_size: int = 0
    luks_version: Optional[int] = None
    readable: bool = False
    findings: list[Finding] = field(default_factory=list)
    copies: dict[str, CopyReport] = field(default_factory=dict)
    keyslot_verdicts: dict[str, list[K.KdfVerdict]] = field(default_factory=dict)
    repair_hints: list[str] = field(default_factory=list)

    def add(self, code: str, severity: str, message: str,
            where: str = "", repair: Optional[str] = None) -> None:
        self.findings.append(Finding(code, severity, message, where, repair))

    def worst_severity(self) -> str:
        order = {s: i for i, s in enumerate(
            (C.SEV_OK, C.SEV_INFO, C.SEV_WARNING, C.SEV_ERROR, C.SEV_CRITICAL))}
        worst = C.SEV_OK
        for f in self.findings:
            if order[f.severity] > order[worst]:
                worst = f.severity
        for verdicts in self.keyslot_verdicts.values():
            for v in verdicts:
                if order[v.severity] > order[worst]:
                    worst = v.severity
        return worst


# ---------------------------------------------------------------------------
# Read-only IO
# ---------------------------------------------------------------------------

def _read_at(fd: int, offset: int, length: int) -> bytes:
    """Bounded pread; returns short reads without raising."""
    chunks = []
    remaining = length
    cur = offset
    while remaining:
        try:
            chunk = os.pread(fd, min(remaining, 4 * 1024 * 1024), cur)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        cur += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _peek_magic(fd: int, offset: int) -> bytes:
    return _read_at(fd, offset, C.LUKS2_MAGIC_L)


def _locate_secondary(fd: int, primary_hdr_size: Optional[int],
                      file_size: int) -> Optional[int]:
    candidates = []
    if primary_hdr_size:
        candidates.append(primary_hdr_size)
    for off in C.LUKS2_HDR2_FALLBACK_OFFSETS:
        if off not in candidates:
            candidates.append(off)
    for off in candidates:
        # A full binary header page must fit; a partial image must not be
        # mistaken for a damaged secondary copy.
        if off + C.LUKS2_HDR_BIN_LEN > file_size:
            continue
        magic = _peek_magic(fd, off)
        if len(magic) == C.LUKS2_MAGIC_L and magic in (
                C.MAGIC_LUKS2_SECONDARY, C.MAGIC_LUKS):
            return off
    return None


# ---------------------------------------------------------------------------
# Per-copy work
# ---------------------------------------------------------------------------

def _audit_copy(fd: int, role: str, offset: int,
                report: AuditReport) -> CopyReport:
    cr = CopyReport(role=role, disk_offset=offset)
    head = _read_at(fd, offset, C.LUKS2_HDR_BIN_LEN)
    if not head:
        report.add("COPY_UNREADABLE", C.SEV_CRITICAL,
                   f"{role} header at disk offset 0x{offset:x} could not be read",
                   role)
        return cr

    cr.present = True
    expect_secondary = role == "secondary"
    cr.hdr = B.parse_binary_header(head, offset, expect_secondary)
    cr.truncated = cr.hdr.truncated

    if not cr.hdr.magic_ok:
        report.add("MAGIC_BAD", C.SEV_CRITICAL,
                   f"{role} magic {head[:6].hex()} is neither LUKS nor SKUL "
                   "at expected offset", role)
        return cr

    h = cr.hdr
    if h.is_luks1:
        return cr  # caller handles LUKS1 short circuit

    # binary structural rules from hdr_disk_sanity_check_pre()
    if h.fields.get("version") != C.LUKS2_VERSION:
        report.add("VERSION_BAD", C.SEV_ERROR,
                   f"{role} version field is {h.fields.get('version')}, expected 2",
                   role)
    if h.hdr_size is not None:
        if not (C.LUKS2_HDR_16K_LEN <= h.hdr_size <= C.LUKS2_HDR_SIZE_MAX):
            report.add("HDR_SIZE_RANGE", C.SEV_CRITICAL,
                       f"{role} hdr_size={h.hdr_size} outside permitted "
                       f"0x{C.LUKS2_HDR_16K_LEN:x}..0x{C.LUKS2_HDR_SIZE_MAX:x}",
                       role)
    expected_offset = 0 if role == "primary" else (h.hdr_size or 0)
    if h.fields.get("hdr_offset") is not None and h.fields.get("hdr_offset") != offset:
        report.add("HDR_OFFSET_MISMATCH", C.SEV_CRITICAL,
                   f"{role} hdr_offset field says 0x{h.fields['hdr_offset']:x} but "
                   f"the copy sits at 0x{offset:x}", role)
    elif role == "secondary" and h.hdr_size and offset != h.hdr_size:
        report.add("HDR_OFFSET_MISMATCH", C.SEV_CRITICAL,
                   f"secondary copy offset 0x{offset:x} != primary hdr_size "
                   f"0x{h.hdr_size:x}", role)

    for name, bad_off, length in B.check_zero_regions(h):
        msg = (f"{role} reserved region {name} contains non-zero bytes "
               f"(first at header+0x{bad_off:x})")
        cr.zero_region_issues.append(msg)
        report.add("PADDING_NONZERO", C.SEV_WARNING, msg, role)

    json_len = max((h.hdr_size or 0) - C.LUKS2_HDR_BIN_LEN, 0)
    if json_len:
        raw_json = _read_at(fd, offset + C.LUKS2_HDR_BIN_LEN, json_len)
        cr.json_area = J.extract_json(raw_json,
                                      offset + C.LUKS2_HDR_BIN_LEN)
        if cr.json_area.padding_issue:
            report.add("JSON_PADDING_BAD", C.SEV_WARNING,
                       f"{role}: {cr.json_area.padding_issue}", role)
        if cr.json_area.parse_error:
            report.add("JSON_PARSE", C.SEV_CRITICAL,
                       f"{role}: {cr.json_area.parse_error}"
                       + (f" at area+0x{cr.json_area.error_pos:x}"
                          if cr.json_area.error_pos is not None else ""),
                       role)
        elif isinstance(cr.json_area.parsed, dict):
            cr.schema_findings = J.validate_metadata(cr.json_area.parsed)
            for sf in cr.schema_findings:
                report.add(sf.code, sf.severity,
                           f"{role}: {sf.message}"
                           + (f" [{sf.path}]" if sf.path else ""), role)

    ok, reason = B.verify_checksum(h, raw_json if json_len else b"")
    cr.checksum_ok, cr.checksum_reason = ok, reason
    if not ok:
        report.add("CHECKSUM_BAD", C.SEV_CRITICAL,
                   f"{role}: {reason}", role)
    return cr


# ---------------------------------------------------------------------------
# Cross-copy analysis
# ---------------------------------------------------------------------------

# Fields cryptsetup intentionally allows to differ between the two copies:
# magic (LUKS vs SKUL), hdr_offset (0 vs hdr_size), salt (unique per copy),
# csum (derived from the unique salt, therefore necessarily different),
# seqid (adjucated separately by _seqid_verdict: mismatch is expected after
# a crash mid-update, not a structural defect).
_FIELD_ALLOWED_DIFF = {"magic", "hdr_offset", "salt", "csum", "seqid"}


def _compare_binary(primary: CopyReport, secondary: CopyReport,
                    report: AuditReport) -> None:
    if not primary.hdr or not secondary.hdr:
        return
    for name, (off, length, _fmt) in C.HDR_FIELDS.items():
        a = primary.hdr.fields.get(name)
        b = secondary.hdr.fields.get(name)
        if a is None or b is None:
            continue
        if name in _FIELD_ALLOWED_DIFF or a == b:
            continue
        report.add("BIN_FIELD_MISMATCH", C.SEV_ERROR,
                   f"binary field {name} differs between copies: "
                   f"primary={B.describe_field(name, a)} vs "
                   f"secondary={B.describe_field(name, b)} "
                   f"(header offset 0x{off:x}, {length} bytes)", "cross")


def _byte_ranges(a: bytes, b: bytes, base: int, label: str,
                 report: AuditReport, code: str,
                 severity: str = C.SEV_CRITICAL) -> None:
    for start, end, av, bv in B.diff_ranges(a, b, base=base):
        length = end - start
        report.add(code, severity,
                   f"{label} differs at disk offsets 0x{start:x}..0x{end:x} "
                   f"({length} byte{'s' if length != 1 else ''}); "
                   f"primary bytes {av[:16].hex()}{'...' if length > 16 else ''} vs "
                   f"secondary {bv[:16].hex()}{'...' if length > 16 else ''}", "cross")


def _mask_allowed_binary_diffs(raw: bytes) -> bytearray:
    """Zero the fields that legitimately differ between the two copies
    (magic, hdr_offset, salt, csum) so a raw diff reveals only corruption."""
    out = bytearray(raw)
    for name in _FIELD_ALLOWED_DIFF:
        off, length, _ = C.HDR_FIELDS[name]
        out[off:off + length] = b"\x00" * length
    return out


def _localize_corruption(primary: CopyReport, secondary: CopyReport,
                         report: AuditReport) -> None:
    """When a checksum fails but the other copy checks out, diff the raw
    regions to name the exact damaged byte range(s)."""
    pairs = ((primary, secondary), (secondary, primary))
    for bad, good in pairs:
        if bad.checksum_ok is not False or good.checksum_ok is not True:
            continue
        bad_role, good_role = bad.role, good.role
        if bad.hdr and good.hdr and not bad.hdr.truncated:
            _byte_ranges(_mask_allowed_binary_diffs(good.hdr.raw),
                         _mask_allowed_binary_diffs(bad.hdr.raw),
                         bad.disk_offset,
                         f"binary header ({bad_role} damaged, {good_role} good)",
                         report, "CORRUPT_BIN_RANGE")
        if (bad.json_area and good.json_area and bad.json_area.raw
                and good.json_area.raw):
            _byte_ranges(good.json_area.raw, bad.json_area.raw,
                         bad.json_area.disk_offset,
                         f"JSON area ({bad_role} damaged, {good_role} good)",
                         report, "CORRUPT_JSON_RANGE")
        if bad.json_area and bad.json_area.parse_error and good.json_area \
                and good.json_area.parsed is not None:
            pos = bad.json_area.error_pos
            loc = (f"near area+0x{pos:x} (disk offset "
                   f"0x{bad.json_area.disk_offset + (pos or 0):x})"
                   if pos is not None else "at unknown offset")
            report.add("CORRUPT_JSON_LOCATION", C.SEV_CRITICAL,
                       f"{bad_role} JSON is unparseable {loc}; the "
                       f"{good_role} JSON parses cleanly and is the repair source",
                       "cross")


def _compare_json(primary: CopyReport, secondary: CopyReport,
                  report: AuditReport) -> None:
    pa, sa = primary.json_area, secondary.json_area
    if pa is None or sa is None:
        return
    if pa.raw and sa.raw and pa.raw != sa.raw:
        # Byte-level differences matter even when both parse (e.g. key
        # ordering drift, padding tampering).
        diffs = B.diff_ranges(pa.raw, sa.raw, base=0)
        if pa.parsed is not None and sa.parsed is not None \
                and pa.parsed == sa.parsed:
            for start, end, _a, _b in diffs:
                report.add("JSON_BYTES_DIFF", C.SEV_INFO,
                           f"JSON semantically identical but bytes differ at "
                           f"area+0x{start:x}..0x{end:x} (re-serialization or "
                           "padding drift); cryptsetup repair normalizes this",
                           "cross")
        else:
            _byte_ranges(pa.raw, sa.raw, 0,
                         "JSON area byte content", report,
                         "JSON_CONTENT_DIFF")
    if pa.parsed is not None and sa.parsed is not None \
            and pa.parsed != sa.parsed:
        p_keys = set(pa.parsed.get("keyslots", {}))
        s_keys = set(sa.parsed.get("keyslots", {}))
        if p_keys != s_keys:
            report.add("JSON_KEYSLOT_SET_DIFF", C.SEV_ERROR,
                       f"keyslot sets diverge: primary={sorted(p_keys)} "
                       f"secondary={sorted(s_keys)}", "cross")
        else:
            report.add("JSON_CONTENT_DIFF", C.SEV_ERROR,
                       "parsed JSON metadata differs between copies", "cross")


def _seqid_verdict(primary: CopyReport, secondary: CopyReport,
                   report: AuditReport) -> None:
    s1 = primary.hdr.seqid if primary.hdr else None
    s2 = secondary.hdr.seqid if secondary.hdr else None
    if s1 is None or s2 is None:
        return
    if s1 != s2:
        newer = "primary" if s1 > s2 else "secondary"
        report.add("SEQID_MISMATCH", C.SEV_WARNING,
                   f"sequence ids differ (primary={s1}, secondary={s2}); "
                   f"the {newer} copy is authoritative. This is normal after a "
                   "crash mid-update, but a healthy disk carries equal seqids",
                   "cross",
                   "run 'cryptsetup repair <device>' after taking a header "
                   "backup; it rewrites the stale copy from the authoritative one")
    elif primary.checksum_ok and secondary.checksum_ok:
        report.add("SEQID_SYNCED", C.SEV_OK,
                   f"both copies share seqid={s1} and verify cleanly")


# ---------------------------------------------------------------------------
# Repair suggestions
# ---------------------------------------------------------------------------

def _repair_guidance(report: AuditReport, primary: CopyReport,
                     secondary: CopyReport) -> None:
    p_ok = primary.checksum_ok is True
    s_ok = secondary.checksum_ok is True
    hints = report.repair_hints

    if not secondary.present:
        if p_ok:
            hints.append(
                "Only the primary header copy is present (typical for a "
                "luksHeaderBackup file or a truncated image). If this is a "
                "whole-disk image rather than an intentional backup, the "
                "redundant secondary copy is missing: extend the image from "
                "the source disk or run 'cryptsetup repair <device>' on the "
                "real device to rebuild it, then take a fresh "
                "luksHeaderBackup.")
        else:
            hints.append(
                "The only available header copy fails verification and no "
                "secondary copy exists. Restore from an offline "
                "luksHeaderBackup; do not attempt in-place repair without a "
                "full disk image first.")
        return
    if p_ok and s_ok:
        if not any(f.code == "SEQID_MISMATCH" for f in report.findings):
            hints.append("Both header copies verify; no repair needed. "
                         "Refresh an offline backup: "
                         "cryptsetup luksHeaderBackup <device> --header-backup-file <file>")
        return
    if not p_ok and not s_ok:
        hints.append("BOTH copies fail verification: do NOT run cryptsetup "
                     "repair blindly. Restore from an offline "
                     "luksHeaderBackup file onto a cloned disk first "
                     "(luksHeaderRestore), and preserve the failing disk for "
                     "forensics. If no backup exists, keyslot recovery may "
                     "still be possible with 'cryptsetup repair' experimental "
                     "mode; engage your storage vendor/support.")
        return
    good_role = "secondary" if s_ok else "primary"
    bad_role = "primary" if s_ok else "secondary"
    hints.append(
        f"The {bad_role} copy is damaged while the {good_role} copy verifies. "
        "Recommended order: (1) image the whole disk / take "
        "luksHeaderBackup now; (2) 'cryptsetup repair <device>' rewrites the "
        "damaged copy from the good one (it never touches user data or "
        "keyslot material); (3) re-run this audit. Manual equivalent with dd "
        "is possible but repair is safer because it recomputes checksums.")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def audit_path(path: str) -> AuditReport:
    report = AuditReport(path=path)
    flags = os.O_RDONLY
    if os.path.exists(path) and not os.path.isdir(path):
        try:
            flags |= os.O_BINARY  # type: ignore[attr-defined]
        except AttributeError:
            pass
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        report.add("OPEN_FAILED", C.SEV_CRITICAL,
                   f"cannot open {path} read-only: {exc}")
        return report

    try:
        report.file_size = os.fstat(fd).st_size
        magic = _peek_magic(fd, 0)
        if magic == C.MAGIC_LUKS:
            version_bytes = _read_at(fd, 6, 2)
            version = int.from_bytes(version_bytes, "big") if len(version_bytes) == 2 else None
            report.luks_version = version
            if version == C.LUKS1_VERSION:
                report.add("LUKS1_NOT_SUPPORTED", C.SEV_ERROR,
                           "image is LUKS1 (single header, no redundant copy, "
                           "PBKDF2-only). This tool audits LUKS2; upgrade via "
                           "'cryptsetup convert --type luks2' after backing up",
                           "primary",
                           "cryptsetup luksHeaderBackup, then "
                           "'cryptsetup convert --type luks2 <device>'")
                report.readable = True
                return report
        elif magic != C.MAGIC_LUKS2_SECONDARY:
            report.add("NOT_LUKS", C.SEV_CRITICAL,
                       f"no LUKS magic at offset 0 (found {magic.hex() or 'EOF'})")
            return report

        primary = _audit_copy(fd, "primary", 0, report)
        report.copies["primary"] = primary
        report.readable = True
        if primary.hdr and primary.hdr.is_luks1:
            return report
        if primary.hdr:
            report.luks_version = primary.hdr.fields.get("version")

        secondary_offset = _locate_secondary(
            fd, primary.hdr.hdr_size if primary.hdr else None,
            report.file_size)
        if secondary_offset is None:
            report.add("SECONDARY_MISSING", C.SEV_CRITICAL,
                       "no secondary header found at primary hdr_size or any "
                       "known fallback offset "
                       f"{[hex(x) for x in C.LUKS2_HDR2_FALLBACK_OFFSETS]}",
                       "secondary",
                       "if the disk is truncated this is expected on partial "
                       "images; otherwise the redundant copy has been erased - "
                       "restore from header backup immediately")
            secondary = CopyReport(role="secondary", disk_offset=-1)
        else:
            secondary = _audit_copy(fd, "secondary", secondary_offset, report)
        report.copies["secondary"] = secondary

        _compare_binary(primary, secondary, report)
        _localize_corruption(primary, secondary, report)
        _compare_json(primary, secondary, report)
        _seqid_verdict(primary, secondary, report)

        # KDF policy runs against whichever copy parses, preferring the
        # authoritative (higher seqid, checksum-valid) one.
        source = _pick_authoritative(primary, secondary)
        if source and source.json_area and isinstance(source.json_area.parsed, dict):
            slots = source.json_area.parsed.get("keyslots", {})
            for slot_id in sorted(slots, key=lambda x: (len(str(x)), str(x))):
                report.keyslot_verdicts[str(slot_id)] = \
                    K.evaluate_keyslot(str(slot_id), slots[slot_id])
            segments = source.json_area.parsed.get("segments", {})
            for seg_id, seg in segments.items():
                if isinstance(seg, dict):
                    enc = seg.get("encryption")
                    verdict = _segment_cipher_verdict(enc, seg_id)
                    if verdict:
                        report.findings.append(
                            Finding(verdict.code, verdict.severity,
                                    verdict.message, "cross", verdict.repair))

        _repair_guidance(report, primary, secondary)
        return report
    finally:
        os.close(fd)


def _pick_authoritative(primary: CopyReport,
                        secondary: CopyReport) -> Optional[CopyReport]:
    candidates = [c for c in (primary, secondary)
                  if c.json_area and isinstance(c.json_area.parsed, dict)]
    if not candidates:
        return None
    valid = [c for c in candidates if c.checksum_ok is True]
    pool = valid or candidates
    pool.sort(key=lambda c: c.hdr.seqid or 0, reverse=True)
    return pool[0]


def _segment_cipher_verdict(encryption: Any, seg_id: Any) -> Optional[Finding]:
    if not isinstance(encryption, str) or not encryption:
        return None
    low = encryption.lower()
    if any(pat in low for pat in C.WEAK_CIPHER_PATTERNS):
        return Finding("WEAK_CIPHER", C.SEV_WARNING,
                       f"segment {seg_id} encryption {encryption!r} is weak/null",
                       "cross", "re-encrypt with cryptsetup reencrypt")
    if low.startswith("cbc") or "-cbc-" in low:
        return Finding("LEGACY_CIPHER_MODE", C.SEV_INFO,
                       f"segment {seg_id} uses CBC ({encryption!r}); XTS is the "
                       "standard FDE mode", "cross")
    return None
