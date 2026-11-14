"""
Build LUKS2 (and a LUKS1) test images with the Python standard library only.

Everything here follows the same on-disk specification the auditor
implements, so the images are independently constructed rather than being
parsed-and-regurgitated:

* binary header layout: struct luks2_hdr_disk (big endian, 4096 bytes)
* JSON area: compact JSON + NUL padding to (hdr_size - 4096)
* checksum: csum_alg over (4096 header bytes with csum zeroed) + full area
* primary copy at 0, secondary at hdr_size, keyslot areas after 2*hdr_size

Run (always -I against freshly generated data):

    python3 -I tools/make_test_images.py testdata/
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import uuid

# Layout constants duplicated here on purpose: the builder must not import
# the package it is generating fixtures for, otherwise a shared bug would
# produce self-consistent garbage the audit could never catch.
MAGIC_1ST = b"LUKS\xba\xbe"
MAGIC_2ND = b"SKUL\xba\xbe"
HDR_BIN_LEN = 4096
DEFAULT_HDR_SIZE = 0x1000000          # 16 MiB
KEYSLOTS_SIZE = 0x400000              # 4 MiB (fits five 512 KiB slot areas)
SALT_LEN = 64
CSUM_ALG = b"sha256"


def _b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def make_kdf(kdf_type: str, *, time=None, memory=None, cpus=None,
             iterations=None, hash_name=None, salt=None) -> dict:
    salt = salt or os.urandom(SALT_LEN)
    kdf = {"type": kdf_type, "salt": _b64(salt)}
    if kdf_type in ("argon2i", "argon2id"):
        kdf.update({"time": str(time if time is not None else 4),
                    "memory": str(memory if memory is not None else 1 << 20),
                    "cpus": str(cpus if cpus is not None else 4)})
    elif kdf_type == "pbkdf2":
        kdf.update({"iterations": str(iterations if iterations is not None
                                      else 600_000),
                    "hash": hash_name or "sha256"})
    return kdf


def make_keyslot(slot_id: int, kdf: dict, *, key_size: int = 64,
                 area_offset: int | None = None,
                 area_size: int = 0x80000,
                 encryption: str = "aes-xts-plain64") -> dict:
    if area_offset is None:
        area_offset = 2 * DEFAULT_HDR_SIZE + slot_id * area_size
    return {
        "type": "luks2",
        "key_size": key_size,
        "af": {"type": "luks1", "stripes": "4000"},
        "area": {
            "type": "raw",
            "offset": str(area_offset),
            "size": str(area_size),
            "encryption": encryption,
        },
        "kdf": kdf,
    }


def make_metadata(keyslots: dict, *, json_size: int) -> dict:
    return {
        "keyslots": keyslots,
        "tokens": {},
        "segments": {
            "0": {
                "type": "crypt",
                "offset": str(2 * DEFAULT_HDR_SIZE + KEYSLOTS_SIZE),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-xts-plain64",
                "sector_size": 4096,
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": [str(k) for k in sorted(keyslots, key=int)],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": "100000",
                "salt": _b64(os.urandom(32)),
                "digest": _b64(os.urandom(32)),
            }
        },
        "config": {
            "json_size": str(json_size),
            "keyslots_size": str(KEYSLOTS_SIZE),
            "flags": [],
            "priority": {},
        },
    }


def pack_binary_header(*, magic: bytes, hdr_size: int, seqid: int,
                       label: str, csum_alg: bytes, salt: bytes,
                       uuid_text: str, subsystem: str,
                       hdr_offset: int) -> bytearray:
    buf = bytearray(HDR_BIN_LEN)
    struct.pack_into(">6s", buf, 0x000, magic)
    struct.pack_into(">H", buf, 0x006, 2)
    struct.pack_into(">Q", buf, 0x008, hdr_size)
    struct.pack_into(">Q", buf, 0x010, seqid)
    buf[0x018:0x018 + 48] = label.encode()[:48].ljust(48, b"\x00")
    buf[0x048:0x048 + 32] = csum_alg[:32].ljust(32, b"\x00")
    buf[0x068:0x068 + 64] = salt
    buf[0x0A8:0x0A8 + 40] = uuid_text.encode()[:40].ljust(40, b"\x00")
    buf[0x0D0:0x0D0 + 48] = subsystem.encode()[:48].ljust(48, b"\x00")
    struct.pack_into(">Q", buf, 0x100, hdr_offset)
    # 0x108..0x1bf reserved, 0x1c0..0x1ff csum (zero until checksum step),
    # 0x200..0xfff padding: bytearray is already zero.
    return buf


def checksum(csum_alg: bytes, binary: bytes, json_area: bytes) -> bytes:
    h = hashlib.new(csum_alg.rstrip(b"\x00").decode())
    h.update(binary)
    h.update(json_area)
    return h.digest()


def build_copy(*, secondary: bool, hdr_size: int, seqid: int,
               metadata: dict, label: str, uuid_text: str,
               subsystem: str, salt: bytes,
               csum_alg: bytes = CSUM_ALG) -> bytes:
    json_len = hdr_size - HDR_BIN_LEN
    json_text = json.dumps(metadata, separators=(",", ":"),
                           sort_keys=False).encode("utf-8")
    if len(json_text) >= json_len:
        raise ValueError("metadata does not fit JSON area")
    json_area = json_text + b"\x00" * (json_len - len(json_text))

    binary = pack_binary_header(
        magic=MAGIC_2ND if secondary else MAGIC_1ST,
        hdr_size=hdr_size, seqid=seqid, label=label,
        csum_alg=csum_alg, salt=salt, uuid_text=uuid_text,
        subsystem=subsystem,
        hdr_offset=hdr_size if secondary else 0)
    digest = checksum(csum_alg, bytes(binary), json_area)
    binary[0x1C0:0x1C0 + len(digest)] = digest
    return bytes(binary) + json_area


def build_image(metadata: dict, *, hdr_size: int = DEFAULT_HDR_SIZE,
                seqid: int = 1, label: str = "audit-fixture",
                subsystem: str = "",
                image_size: int | None = None,
                primary_salt: bytes | None = None,
                secondary_salt: bytes | None = None) -> bytearray:
    json_size = hdr_size - HDR_BIN_LEN
    metadata["config"]["json_size"] = str(json_size)
    uuid_text = str(uuid.uuid4())
    primary_salt = primary_salt or os.urandom(SALT_LEN)
    secondary_salt = secondary_salt or os.urandom(SALT_LEN)

    primary = build_copy(secondary=False, hdr_size=hdr_size, seqid=seqid,
                         metadata=metadata, label=label,
                         uuid_text=uuid_text, subsystem=subsystem,
                         salt=primary_salt)
    secondary = build_copy(secondary=True, hdr_size=hdr_size, seqid=seqid,
                           metadata=metadata, label=label,
                           uuid_text=uuid_text, subsystem=subsystem,
                           salt=secondary_salt)
    total = image_size or (2 * hdr_size + KEYSLOTS_SIZE + 0x4000)
    img = bytearray(total)
    img[0:len(primary)] = primary
    img[hdr_size:hdr_size + len(secondary)] = secondary
    return img


def write(path: str, data: bytes | bytearray) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def flip_bytes(blob: bytearray, offsets: list[int]) -> None:
    for off in offsets:
        blob[off] ^= 0xFF


# ---------------------------------------------------------------------------
# LUKS1 minimal fixture (magic + version only need to be recognizable)
# ---------------------------------------------------------------------------

def build_luks1_image() -> bytearray:
    # struct luks_phdr starts magic[6] + version uint16 BE; 592 bytes total.
    blob = bytearray(0x100000)
    blob[0:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", blob, 6, 1)
    return blob


def standard_metadata() -> dict:
    slots = {
        "0": make_keyslot(0, make_kdf("argon2id")),
        "1": make_keyslot(1, make_kdf("argon2id", memory=19456, time=2, cpus=1),
                          area_size=0x80000),
    }
    return make_metadata(slots, json_size=DEFAULT_HDR_SIZE - HDR_BIN_LEN)


def main(out_dir: str) -> None:
    # 1. healthy modern image
    write(f"{out_dir}/good_modern.img", build_image(standard_metadata()))

    # 2. legacy + weak KDF mix: PBKDF2 low iterations, argon2 pre-2.4 style,
    #    argon2i, RFC-violating memory, small key, sha1 pbkdf2
    legacy_slots = {
        "0": make_keyslot(0, make_kdf("pbkdf2", iterations=50_000,
                                      hash_name="sha256")),
        "1": make_keyslot(1, make_kdf("argon2id", memory=32768, time=4,
                                      cpus=4)),
        "2": make_keyslot(2, make_kdf("argon2i", memory=19456, time=2,
                                      cpus=1)),
        "3": make_keyslot(3, make_kdf("argon2id", memory=16, time=4, cpus=4)),
        "4": make_keyslot(4, make_kdf("pbkdf2", iterations=2_000,
                                      hash_name="sha1"), key_size=16),
    }
    write(f"{out_dir}/legacy_weak.img",
          build_image(make_metadata(legacy_slots,
                                    json_size=DEFAULT_HDR_SIZE - HDR_BIN_LEN)))

    # 3. corrupted primary binary header (one byte inside label area)
    img = bytearray(build_image(standard_metadata()))
    flip_bytes(img, [0x030])
    write(f"{out_dir}/corrupt_primary_bin.img", img)

    # 4. corrupted secondary JSON (offset = 16MiB + 4096 + 100)
    img = bytearray(build_image(standard_metadata()))
    flip_bytes(img, [DEFAULT_HDR_SIZE + HDR_BIN_LEN + 100])
    write(f"{out_dir}/corrupt_secondary_json.img", img)

    # 5. crash mid-update: secondary seqid one higher, both checksum-valid
    meta = standard_metadata()
    img = bytearray(build_image(meta, seqid=7))
    newer = build_copy(secondary=True, hdr_size=DEFAULT_HDR_SIZE, seqid=8,
                       metadata=meta, label="audit-fixture",
                       uuid_text=_uuid_of(img), subsystem="",
                       salt=os.urandom(SALT_LEN))
    img[DEFAULT_HDR_SIZE:DEFAULT_HDR_SIZE + len(newer)] = newer
    write(f"{out_dir}/crash_seqid.img", img)

    # 6. both copies corrupted
    img = bytearray(build_image(standard_metadata()))
    flip_bytes(img, [0x030, DEFAULT_HDR_SIZE + 0x040])
    write(f"{out_dir}/corrupt_both.img", img)

    # 7. truncated image: primary complete, secondary region missing
    img = build_image(standard_metadata())
    write(f"{out_dir}/truncated.img", img[:DEFAULT_HDR_SIZE + 2048])

    # 8. header backup file: primary 16 MiB region only (cryptsetup-compatible
    #    shape; auditor treats the missing secondary as a finding)
    img = build_image(standard_metadata())
    write(f"{out_dir}/header_backup.bin", img[:DEFAULT_HDR_SIZE])

    # 9. invalid JSON in primary: overwrite the colon after "keyslots" so
    #    the text still starts with '{' but is syntactically invalid, giving
    #    a genuine JSON parse error with a byte position.
    img = bytearray(build_image(standard_metadata()))
    text_start = HDR_BIN_LEN
    colon = bytes(img[text_start:text_start + 32]).index(b":")
    pos = text_start + colon
    img[pos] = ord("X")
    write(f"{out_dir}/invalid_json_primary.img", img)

    # 10. LUKS1 image
    write(f"{out_dir}/luks1.img", build_luks1_image())

    print(f"built 10 fixtures in {out_dir}/")


def _uuid_of(img: bytearray) -> str:
    raw = bytes(img[0x0A8:0x0A8 + 40]).rstrip(b"\x00")
    return raw.decode()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "testdata"
    main(target)
