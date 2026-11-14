"""
Keyslot KDF strength policy.

All thresholds live in constants.py next to their source citation. The
references used here:

* RFC 9106 section 3.1/4: Argon2 memory cost MUST be at least 8*p (KiB).
* cryptsetup-luksFormat(8), MINIMAL AND MAXIMAL PBKDF COSTS:
  argon2 time >= 4, memory 32 KiB..4 GiB (benchmark floor 64 MiB),
  parallel 1..4; PBKDF2 iterations 1000..2^32-1.
* OWASP Password Storage Cheat Sheet (current): five equal-defense
  Argon2id minimum rows, headline baseline m=19456 KiB / t=2 / p=1;
  PBKDF2-HMAC-SHA256 600000, SHA512 220000, SHA1 1400000; Argon2id is
  the first-choice KDF, PBKDF2 mainly for FIPS-validated deployments.
* cryptsetup compiled-in defaults changed at 2.4.0: 32 MiB -> 1 GiB
  memory ceiling, parallel 4.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any, Optional

from . import constants as C
from .jsonmeta import as_uint64


@dataclass
class KdfVerdict:
    code: str
    severity: str
    message: str
    repair: Optional[str] = None


def _b64_len(value: Any) -> Optional[int]:
    if not isinstance(value, str):
        return None
    try:
        return len(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None


def _argon_repair(slot_id: str) -> str:
    return (f"cryptsetup luksConvertKey <device> --key-slot {slot_id} "
            "--pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 "
            "--iterations 4   (luksConvertKey needs cryptsetup >= 2.4; "
            "older versions: luksAddKey a new strong slot then luksKillSlot)")


def _meets_any_owasp_row(memory_kib: int, time_cost: int) -> bool:
    return any(memory_kib >= m_r and time_cost >= t_r
               for m_r, t_r in C.OWASP_ARGON2ID_ROWS)


def _check_salt(kdf: dict[str, Any], prefix: str,
                verdicts: list[KdfVerdict]) -> None:
    salt_len = _b64_len(kdf.get("salt"))
    if salt_len is None:
        return
    if salt_len < C.MIN_SALT_BYTES:
        verdicts.append(KdfVerdict(
            "SALT_SHORT", C.SEV_WARNING,
            f"{prefix} salt is {salt_len} bytes; minimum practice is "
            f"{C.MIN_SALT_BYTES} bytes",
            "re-create the keyslot (luksConvertKey/luksAddKey); a short salt "
            "cannot be repaired in place"))


def _check_cipher(encryption: Any, where: str,
                  verdicts: list[KdfVerdict]) -> None:
    if not isinstance(encryption, str) or not encryption:
        return
    low = encryption.lower()
    if any(pat in low for pat in C.WEAK_CIPHER_PATTERNS):
        verdicts.append(KdfVerdict(
            "WEAK_CIPHER", C.SEV_WARNING,
            f"{where} uses suspicious/weak cipher {encryption!r}",
            "re-encrypt with an authenticated/standard mode "
            "(e.g. aes-xts-plain64) via cryptsetup reencrypt"))
    elif low.startswith("cbc") or "-cbc-" in low:
        verdicts.append(KdfVerdict(
            "LEGACY_CIPHER_MODE", C.SEV_INFO,
            f"{where} uses CBC mode {encryption!r}; XTS is the standard "
            "mode for full-disk encryption"))


def evaluate_argon2(slot_id: str, kdf: dict[str, Any]) -> list[KdfVerdict]:
    out: list[KdfVerdict] = []
    prefix = f"keyslot {slot_id}"
    m = as_uint64(kdf.get("memory"))
    t = as_uint64(kdf.get("time"))
    p = as_uint64(kdf.get("cpus"))
    kdf_type = kdf.get("type")
    repair = _argon_repair(slot_id)

    if m is None or t is None or p is None:
        return out  # structural problems already reported by schema checks

    # --- hard spec / implementation limits --------------------------------
    if p < C.ARGON2_MIN_PARALLEL or p > C.ARGON2_MAX_PARALLEL:
        out.append(KdfVerdict(
            "ARGON2_PARALLEL_RANGE", C.SEV_ERROR,
            f"{prefix} argon2 parallelism p={p} outside cryptsetup range "
            f"{C.ARGON2_MIN_PARALLEL}..{C.ARGON2_MAX_PARALLEL}", repair))
    if m < C.ARGON2_MIN_MEMORY_KIB:
        out.append(KdfVerdict(
            "ARGON2_MEMORY_BELOW_MIN", C.SEV_ERROR,
            f"{prefix} memory m={m} KiB below cryptsetup hard minimum "
            f"{C.ARGON2_MIN_MEMORY_KIB} KiB", repair))
    if m < C.ARGON2_MEMORY_PER_LANE_KIB * max(p, 1):
        out.append(KdfVerdict(
            "ARGON2_SPEC_VIOLATION", C.SEV_CRITICAL,
            f"{prefix} memory m={m} KiB < 8*p = "
            f"{C.ARGON2_MEMORY_PER_LANE_KIB * max(p, 1)} KiB; RFC 9106 "
            "forbids this and cryptsetup will refuse such a parameterset",
            repair))
    if t < C.ARGON2_OWASP_MIN_TIME:
        out.append(KdfVerdict(
            "ARGON2_TIME_BELOW_MIN", C.SEV_ERROR,
            f"{prefix} time cost t={t} below both the OWASP floor t=2 and "
            f"the cryptsetup format minimum t={C.ARGON2_MIN_TIME}", repair))
    elif t < C.ARGON2_MIN_TIME:
        out.append(KdfVerdict(
            "ARGON2_TIME_BELOW_CRYPTSETUP_MIN", C.SEV_INFO,
            f"{prefix} time cost t={t} is an accepted OWASP parameter with "
            f"adequate memory but below the cryptsetup format minimum "
            f"t={C.ARGON2_MIN_TIME}; valid on disk, cannot be created by "
            "current cryptsetup without explicit override", repair))

    # --- strength against OWASP equal-defense rows ------------------------
    if m >= C.CRYPTSETUP_MODERN_MEMORY_KIB:
        mem_note = ("meets the modern cryptsetup 1 GiB default memory ceiling",
                    C.SEV_OK)
    elif m == C.CRYPTSETUP_LEGACY_MEMORY_KIB:
        mem_note = ("m=32768 KiB is exactly the pre-2.4 cryptsetup 32 MiB "
                    "default; modern default is "
                    f"{C.CRYPTSETUP_MODERN_MEMORY_KIB} KiB", C.SEV_INFO)
    elif m < C.CRYPTSETUP_LEGACY_MEMORY_KIB:
        mem_note = (f"m={m} KiB is below even the pre-2.4 32 MiB default; "
                    f"modern default is {C.CRYPTSETUP_MODERN_MEMORY_KIB} KiB",
                    C.SEV_INFO)
    else:
        mem_note = (f"m={m} KiB is below the modern 1 GiB default", C.SEV_INFO)

    if not _meets_any_owasp_row(m, t):
        out.append(KdfVerdict(
            "ARGON2_WEAK_PARAMS", C.SEV_WARNING,
            f"{prefix} ({kdf_type}) m={m} KiB t={t} p={p} meets none of the "
            f"OWASP Argon2id minimum rows (weakest listed: "
            f"m=7168 KiB/t=5; baseline m=19456 KiB/t=2)", repair))
    else:
        below_baseline = (m < C.OWASP_ARGON2ID_BASELINE_MEMORY_KIB or
                          t < C.OWASP_ARGON2ID_BASELINE_TIME)
        if below_baseline:
            out.append(KdfVerdict(
                "ARGON2_BELOW_BASELINE", C.SEV_INFO,
                f"{prefix} ({kdf_type}) m={m} KiB t={t} p={p} sits on an OWASP "
                "equal-defense row but below the headline baseline "
                "(19 MiB / t=2); acceptable, raise when hardware allows",
                repair))
        elif mem_note[1] != C.SEV_OK:
            out.append(KdfVerdict("ARGON2_MODERNIZE", C.SEV_INFO,
                                  f"{prefix} ({kdf_type}) m={m} KiB t={t} p={p}: "
                                  f"{mem_note[0]}", repair))

    if kdf_type == C.KDF_ARGON2I:
        out.append(KdfVerdict(
            "ARGON2I_PREFER_ID", C.SEV_WARNING,
            f"{prefix} uses argon2i; OWASP and current LUKS2 defaults prefer "
            "argon2id (side-channel resistant hybrid)",
            repair))

    _check_salt(kdf, prefix, out)
    return out


def evaluate_pbkdf2(slot_id: str, kdf: dict[str, Any]) -> list[KdfVerdict]:
    out: list[KdfVerdict] = []
    prefix = f"keyslot {slot_id}"
    iters = as_uint64(kdf.get("iterations"))
    hash_name = (kdf.get("hash") or "").lower()
    repair = _argon_repair(slot_id)

    out.append(KdfVerdict(
        "PBKDF2_KDF_LEGACY", C.SEV_WARNING,
        f"{prefix} uses PBKDF2, which is not memory-hard; OWASP recommends "
        "Argon2id except where FIPS-140 validated PBKDF2 is required",
        repair))

    if iters is None:
        return out
    if iters < C.PBKDF2_MIN_ITERATIONS:
        out.append(KdfVerdict(
            "PBKDF2_BELOW_HARD_MIN", C.SEV_ERROR,
            f"{prefix} iterations={iters} below cryptsetup hard minimum "
            f"{C.PBKDF2_MIN_ITERATIONS}", repair))

    recommended = C.OWASP_PBKDF2_ITERATIONS.get(hash_name)
    if recommended is None:
        recommended = C.OWASP_PBKDF2_ITERATIONS["sha256"]
        hash_note = f"unrecognized hash {hash_name!r}, benchmarking against SHA-256"
    else:
        hash_note = f"OWASP recommendation for {hash_name} is {recommended:,} iterations"
    if iters >= recommended:
        out.append(KdfVerdict(
            "PBKDF2_ITERATIONS_OK", C.SEV_INFO,
            f"{prefix} {iters:,} iterations >= {recommended:,} ({hash_note})"))
    elif iters >= recommended // C.PBKDF2_WEAK_FACTOR:
        out.append(KdfVerdict(
            "PBKDF2_LOW_ITERATIONS", C.SEV_WARNING,
            f"{prefix} {iters:,} iterations is under the {recommended:,} "
            f"recommendation ({hash_note}) but above half of it", repair))
    else:
        out.append(KdfVerdict(
            "PBKDF2_VERY_LOW_ITERATIONS", C.SEV_WARNING,
            f"{prefix} {iters:,} iterations is less than half of the "
            f"{recommended:,} recommendation ({hash_note})", repair))

    if hash_name in C.WEAK_PBKDF2_HASHES:
        out.append(KdfVerdict(
            "PBKDF2_WEAK_HASH", C.SEV_WARNING,
            f"{prefix} PBKdf2 inner hash {hash_name} is legacy/weak "
            "(OWASP: SHA-1 only for legacy systems, never new ones)",
            repair))

    _check_salt(kdf, prefix, out)
    return out


def evaluate_keyslot(slot_id: str, slot: dict[str, Any]) -> list[KdfVerdict]:
    """Full per-keyslot policy evaluation. Structural schema problems are
    handled elsewhere; this focuses on cryptographic strength."""
    out: list[KdfVerdict] = []
    if not isinstance(slot, dict):
        return out

    key_size = slot.get("key_size")
    if isinstance(key_size, int) and 0 < key_size < C.MIN_KEY_SIZE_BYTES:
        out.append(KdfVerdict(
            "KEY_SIZE_SMALL", C.SEV_WARNING,
            f"keyslot {slot_id} master key is {key_size} bytes; modern "
            f"baseline is {C.MIN_KEY_SIZE_BYTES} bytes (256 bit)",
            "requires re-encryption (cryptsetup reencrypt) to grow the key"))

    area = slot.get("area")
    if isinstance(area, dict):
        _check_cipher(area.get("encryption"), f"keyslot {slot_id} area", out)

    kdf = slot.get("kdf")
    if not isinstance(kdf, dict):
        return out
    kdf_type = kdf.get("type")
    if kdf_type in C.ARGON2_KDFS:
        out.extend(evaluate_argon2(slot_id, kdf))
    elif kdf_type == C.KDF_PBKDF2:
        out.extend(evaluate_pbkdf2(slot_id, kdf))
    elif isinstance(kdf_type, str) and kdf_type:
        out.append(KdfVerdict(
            "KDF_UNKNOWN", C.SEV_ERROR,
            f"keyslot {slot_id} uses unknown KDF {kdf_type!r}",
            "verify against your cryptsetup version before relying on it"))
    return out
