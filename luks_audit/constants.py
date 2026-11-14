"""
LUKS2 on-disk layout constants and audit policy thresholds.

Every numeric fact here is traceable to one of:

* cryptsetup source (the on-disk format authority), files
  lib/luks2/luks2.h and lib/luks2/luks2_disk_metadata.c
  (struct luks2_hdr_disk, LUKS2_HDR2_OFFSETS, checksum calculation).
* docs/on-disk-format-luks2.adoc shipped with cryptsetup.
* RFC 9106 (Argon2), OWASP Password Storage Cheat Sheet (current edition),
  cryptsetup-luksFormat(8) "MINIMAL AND MAXIMAL PBKDF COSTS".

All multi-byte integer fields on disk are BIG ENDIAN (network byte order).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity / verdict vocabulary
# ---------------------------------------------------------------------------

SEV_CRITICAL = "CRITICAL"   # format violation / data corruption
SEV_ERROR = "ERROR"         # spec-invalid metadata
SEV_WARNING = "WARNING"     # valid but weak / legacy
SEV_INFO = "INFO"           # noteworthy, no action strictly required
SEV_OK = "OK"

SEVERITIES = (SEV_CRITICAL, SEV_ERROR, SEV_WARNING, SEV_INFO, SEV_OK)

# Exit codes
EXIT_CLEAN = 0
EXIT_WEAK = 1       # warnings / weak crypto only, structure intact
EXIT_CORRUPT = 2    # structural / checksum / parse problems
EXIT_USAGE = 3

# ---------------------------------------------------------------------------
# Binary header (struct luks2_hdr_disk, packed, 4096 bytes)
# ---------------------------------------------------------------------------

MAGIC_LUKS = b"LUKS\xba\xbe"          # LUKS1 and LUKS2 primary share this magic
MAGIC_LUKS2_SECONDARY = b"SKUL\xba\xbe"
LUKS1_VERSION = 1
LUKS2_VERSION = 2

LUKS2_MAGIC_L = 6
LUKS2_VERSION_L = 2
LUKS2_UUID_L = 40
LUKS2_LABEL_L = 48
LUKS2_SALT_L = 64
LUKS2_CHECKSUM_ALG_L = 32
LUKS2_CHECKSUM_L = 64

LUKS2_HDR_BIN_LEN = 4096              # sizeof(struct luks2_hdr_disk)
LUKS2_HDR_16K_LEN = 0x4000            # minimum total header size (bin + JSON)
LUKS2_HDR_OFFSET_MAX = 0x400000       # 4 MiB: maximum hdr_offset / JSON text
                                      # size cap used by cryptsetup validators
LUKS2_HDR_SIZE_MAX = 0x1000000        # 16 MiB: maximum permitted hdr_size
                                      # (equals the modern default size)
LUKS2_DEFAULT_HDR_SIZE = 0x1000000    # 16 MiB: typical primary hdr_size and
                                      # therefore typical secondary offset
LUKS2_MAX_KEYSLOTS_SIZE = 0x8000000   # 128 MiB

# Probed when the primary header cannot tell us where the secondary lives.
# LUKS2_HDR2_OFFSETS in lib/luks2/luks2.h (terminated by LUKS2_HDR_OFFSET_MAX).
LUKS2_HDR2_FALLBACK_OFFSETS = (
    0x04000, 0x008000, 0x010000, 0x020000,
    0x40000, 0x080000, 0x100000, 0x200000, LUKS2_HDR_OFFSET_MAX,
)

# Field table: name -> (offset, length, struct format or None for raw bytes).
# Integer formats use ">" (big endian); "32s" style entries are NUL padded
# strings/raw bytes handled explicitly by the parser.
HDR_FIELDS = {
    "magic":       (0x000, 6, None),
    "version":     (0x006, 2, ">H"),
    "hdr_size":    (0x008, 8, ">Q"),    # total size incl. JSON area
    "seqid":       (0x010, 8, ">Q"),
    "label":       (0x018, 48, None),
    "csum_alg":    (0x048, 32, None),
    "salt":        (0x068, 64, None),
    "uuid":        (0x0A8, 40, None),
    "subsystem":   (0x0D0, 48, None),
    "hdr_offset":  (0x100, 8, ">Q"),    # 0 primary; own hdr_size secondary
    # 0x108..0x1BF: 184 bytes reserved padding, must be zero
    "csum":        (0x1C0, 64, None),
    # 0x200..0xFFF: 3584 bytes padding, must be zero
}

# Reserved regions that must contain only zero bytes on a conforming header.
HDR_ZERO_REGIONS = (
    ("reserved_padding", 0x108, 184),
    ("csum_tail", 0x1C0 + LUKS2_CHECKSUM_L,
     LUKS2_HDR_BIN_LEN - (0x1C0 + LUKS2_CHECKSUM_L)),
)

# ---------------------------------------------------------------------------
# JSON metadata area
# ---------------------------------------------------------------------------

JSON_REQUIRED_TOP_KEYS = ("keyslots", "digests", "segments", "tokens", "config")
LUKS2_OBJECTS_MAX = 32

# ---------------------------------------------------------------------------
# KDF policy
# ---------------------------------------------------------------------------

KDF_ARGON2I = "argon2i"
KDF_ARGON2ID = "argon2id"
KDF_PBKDF2 = "pbkdf2"
ARGON2_KDFS = (KDF_ARGON2I, KDF_ARGON2ID)

# cryptsetup hardcoded limits (luksFormat man page, MINIMAL AND MAXIMAL
# PBKDF COSTS) and LUKS2 JSON spec.
ARGON2_MIN_TIME = 4            # cryptsetup refuses time < 4 on format
ARGON2_OWASP_MIN_TIME = 2      # lowest time appearing in the OWASP rows;
                               # t=2/3 with adequate memory is accepted policy
ARGON2_MIN_MEMORY_KIB = 32     # hard minimum; cryptsetup benchmark floor 64 MiB
ARGON2_MIN_PARALLEL = 1
ARGON2_MAX_PARALLEL = 4        # cryptsetup ceiling
ARGON2_MIN_SALT = 16
PBKDF2_MIN_ITERATIONS = 1000   # cryptsetup hardcoded minimum

# RFC 9106 section 4 / section 3.1: m >= 8 * p (in KiB) is a MUST;
# cryptsetup additionally enforces m >= 8*p when formatting.
ARGON2_MEMORY_PER_LANE_KIB = 8

# OWASP Password Storage Cheat Sheet, Argon2id "equal defense" minimum
# configurations (m in KiB; all p=1). 19 MiB / t=2 is the headline baseline.
OWASP_ARGON2ID_ROWS = (
    (47104, 1),   # 46 MiB, t=1
    (19456, 2),   # 19 MiB, t=2  <- baseline
    (12288, 3),   # 12 MiB, t=3
    (9216, 4),    #  9 MiB, t=4
    (7168, 5),    #  7 MiB, t=5
)
OWASP_ARGON2ID_BASELINE_MEMORY_KIB = 19456
OWASP_ARGON2ID_BASELINE_TIME = 2

# Modern cryptsetup compiled-in default ceiling (since 2.4.0):
# memory 1 GiB, parallel 4, benchmarked time around 2 s -> t typically 4..6.
CRYPTSETUP_MODERN_MEMORY_KIB = 1 << 20   # 1048576 KiB = 1 GiB
CRYPTSETUP_LEGACY_MEMORY_KIB = 1 << 15   # 32768 KiB = 32 MiB (pre-2.4 default)

# OWASP PBKDF2 iteration recommendations.
OWASP_PBKDF2_ITERATIONS = {
    "sha256": 600_000,
    "sha512": 220_000,
    "sha1": 1_400_000,   # legacy hash, do not pick for new systems
}
# Half of the recommendation is where we stop merely warning and call it weak.
PBKDF2_WEAK_FACTOR = 2

# Salt / key material sanity (LUKS2 default and common sense).
MIN_SALT_BYTES = 16
MIN_KEY_SIZE_BYTES = 32     # 256-bit master key is the modern baseline

# PBKDF2 hashes regarded as legacy/weak.
WEAK_PBKDF2_HASHES = ("sha1", "md5", "ripemd160")

# Cipher patterns that are never a good sign for full-disk encryption.
WEAK_CIPHER_PATTERNS = ("ecb", "-ecb", "null", "xor-ecb")
