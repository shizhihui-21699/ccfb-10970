"""
Tests for luks_audit. Run from the repo root:

    python3 -I -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luks_audit import constants as C          # noqa: E402
from luks_audit import binary as B             # noqa: E402
from luks_audit import jsonmeta as J           # noqa: E402
from luks_audit import kdfpolicy as K          # noqa: E402
from luks_audit.engine import audit_path       # noqa: E402
from luks_audit.report import exit_code        # noqa: E402

sys.path.insert(0, str(ROOT / "tools"))
import make_test_images as builder             # noqa: E402


def codes(report):
    return {f.code for f in report.findings}


def kdf_codes(report, slot_id):
    return {v.code for v in report.keyslot_verdicts[str(slot_id)]}


class BinaryLayoutTests(unittest.TestCase):
    def test_field_offsets_match_cryptsetup_struct(self):
        # struct luks2_hdr_disk documented layout
        self.assertEqual(C.HDR_FIELDS["magic"][:2], (0x000, 6))
        self.assertEqual(C.HDR_FIELDS["version"][:2], (0x006, 2))
        self.assertEqual(C.HDR_FIELDS["hdr_size"][:2], (0x008, 8))
        self.assertEqual(C.HDR_FIELDS["seqid"][:2], (0x010, 8))
        self.assertEqual(C.HDR_FIELDS["label"][:2], (0x018, 48))
        self.assertEqual(C.HDR_FIELDS["csum_alg"][:2], (0x048, 32))
        self.assertEqual(C.HDR_FIELDS["salt"][:2], (0x068, 64))
        self.assertEqual(C.HDR_FIELDS["uuid"][:2], (0x0A8, 40))
        self.assertEqual(C.HDR_FIELDS["subsystem"][:2], (0x0D0, 48))
        self.assertEqual(C.HDR_FIELDS["hdr_offset"][:2], (0x100, 8))
        self.assertEqual(C.HDR_FIELDS["csum"][:2], (0x1C0, 64))
        # struct occupies exactly one page and regions tile without gaps
        self.assertEqual(C.LUKS2_HDR_BIN_LEN, 4096)
        end = max(off + length for off, length, _ in C.HDR_FIELDS.values())
        self.assertLessEqual(end, 4096)

    def test_big_endian_integers(self):
        meta = builder.standard_metadata()
        img = builder.build_image(meta)
        hdr = B.parse_binary_header(bytes(img[:4096]), 0)
        self.assertEqual(hdr.fields["version"], 2)
        self.assertEqual(hdr.fields["hdr_size"], builder.DEFAULT_HDR_SIZE)
        self.assertEqual(hdr.fields["hdr_offset"], 0)
        # direct struct probe, independent of the parser
        self.assertEqual(struct.unpack(">Q", bytes(img[8:16]))[0],
                         builder.DEFAULT_HDR_SIZE)

    def test_checksum_independent_reimplementation(self):
        """Recompute the checksum with fresh code rather than the shared
        binary.compute_checksum helper, so builder/auditor common-mode bugs
        cannot hide."""
        meta = builder.standard_metadata()
        img = builder.build_image(meta)
        hdr_size = builder.DEFAULT_HDR_SIZE
        for base, magic in ((0, builder.MAGIC_1ST),
                            (hdr_size, builder.MAGIC_2ND)):
            raw_hdr = bytearray(img[base:base + 4096])
            area = bytes(img[base + 4096:base + hdr_size])
            self.assertEqual(bytes(raw_hdr[0:6]), magic)
            stored = bytes(raw_hdr[0x1C0:0x1E0])
            raw_hdr[0x1C0:0x200] = b"\x00" * 64
            digest = hashlib.sha256(bytes(raw_hdr) + area).digest()
            self.assertEqual(stored[:len(digest)], digest)


class ChecksumVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        meta = builder.standard_metadata()
        self.img_path = self.dir / "good.img"
        self.img_path.write_bytes(bytes(builder.build_image(meta)))

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_image_verifies_both_copies(self):
        report = audit_path(str(self.img_path))
        self.assertEqual(report.copies["primary"].checksum_ok, True)
        self.assertEqual(report.copies["secondary"].checksum_ok, True)
        self.assertEqual(exit_code(report), 0)
        self.assertNotIn("CHECKSUM_BAD", codes(report))
        self.assertIn("SEQID_SYNCED", codes(report))

    def test_flip_one_byte_fails_and_is_localized(self):
        data = bytearray(self.img_path.read_bytes())
        data[0x30] ^= 0xFF  # inside primary label field
        bad = self.dir / "bad.img"
        bad.write_bytes(bytes(data))
        report = audit_path(str(bad))
        self.assertIn("CHECKSUM_BAD", codes(report))
        self.assertIn("CORRUPT_BIN_RANGE", codes(report))
        # the localized range must name disk offset 0x30, length 1
        msg = next(f.message for f in report.findings
                   if f.code == "CORRUPT_BIN_RANGE")
        self.assertIn("0x30..0x31", msg)
        # secondary remains intact and is suggested as repair source
        self.assertEqual(report.copies["secondary"].checksum_ok, True)
        self.assertTrue(any("secondary copy verifies" in h
                            for h in report.repair_hints))

    def test_json_corruption_localized_to_json_range(self):
        data = bytearray(self.img_path.read_bytes())
        off = builder.DEFAULT_HDR_SIZE + 4096 + 100
        data[off] ^= 0xFF
        bad = self.dir / "jsonbad.img"
        bad.write_bytes(bytes(data))
        report = audit_path(str(bad))
        self.assertEqual(report.copies["secondary"].checksum_ok, False)
        self.assertTrue(any(f.code in ("CORRUPT_JSON_RANGE", "JSON_PARSE")
                            for f in report.findings))

    def test_invalid_json_reports_parse_position(self):
        data = bytearray(self.img_path.read_bytes())
        # overwrite the colon after "keyslots": stays '{' prefixed, but the
        # JSON parser now fails and reports a byte offset
        colon = bytes(data[4096:4096 + 32]).index(b":")
        data[4096 + colon] = ord("X")
        bad = self.dir / "invalidjson.img"
        bad.write_bytes(bytes(data))
        report = audit_path(str(bad))
        self.assertIn("JSON_PARSE", codes(report))
        self.assertEqual(report.copies["primary"].checksum_ok, False)


class JsonMetaTests(unittest.TestCase):
    def test_extract_requires_brace_and_nul_padding(self):
        area = b'{"a":1}\x00\x00\x00'
        ja = J.extract_json(area, 4096)
        self.assertEqual(ja.parsed, {"a": 1})
        self.assertIsNone(ja.padding_issue)

        ja = J.extract_json(b'x' + b"\x00" * 5, 4096)
        self.assertIsNotNone(ja.parse_error)

        ja = J.extract_json(b'{"a":1}\x00\x01\x00', 4096)
        self.assertIsNotNone(ja.padding_issue)

    def test_uint64_string_parsing(self):
        self.assertEqual(J.as_uint64("1048576"), 1048576)
        self.assertIsNone(J.as_uint64("12x"))
        self.assertIsNone(J.as_uint64(-3))
        self.assertIsNone(J.as_uint64(True))

    def test_schema_detects_missing_and_dangling_parts(self):
        meta = builder.standard_metadata()
        findings = J.validate_metadata(meta)
        self.assertEqual(findings, [])
        meta["digests"]["0"]["keyslots"] = ["99"]
        findings = J.validate_metadata(meta)
        self.assertIn("JSON_DANGLING_REF", {f.code for f in findings})

    def test_area_overlap_detected(self):
        meta = builder.standard_metadata()
        meta["keyslots"]["0"]["area"]["offset"] = \
            meta["keyslots"]["1"]["area"]["offset"]
        findings = J.validate_metadata(meta)
        self.assertIn("JSON_AREA_OVERLAP", {f.code for f in findings})


class KdfPolicyTests(unittest.TestCase):
    def _slot(self, kdf):
        return builder.make_keyslot(0, kdf)

    def test_modern_argon2id_is_clean(self):
        slot = self._slot(builder.make_kdf("argon2id"))
        verdicts = K.evaluate_keyslot("0", slot)
        self.assertEqual(verdicts, [])

    def test_rfc9106_memory_vs_parallelism_violation(self):
        # m=16 KiB >= hard minimum 32? No: pick m=64 (>=32 hard floor) with
        # p=4: 8*p=32 <= 64, also compliant. Use m=16/p=4 instead, which
        # violates BOTH the hard floor and m >= 8*p (32 KiB).
        slot = self._slot(builder.make_kdf("argon2id", memory=16, time=4,
                                           cpus=4))
        codes_ = {v.code for v in K.evaluate_keyslot("0", slot)}
        self.assertIn("ARGON2_SPEC_VIOLATION", codes_)

    def test_time_below_cryptsetup_minimum(self):
        # t=2 with 1 GiB memory: OWASP-acceptable, below cryptsetup's t=4
        # format floor -> warning rather than hard error
        slot = self._slot(builder.make_kdf("argon2id", memory=1 << 20,
                                           time=2, cpus=4))
        codes_ = {v.code for v in K.evaluate_keyslot("0", slot)}
        self.assertIn("ARGON2_TIME_BELOW_CRYPTSETUP_MIN", codes_)

        # t=1 is below even the OWASP floor -> hard error
        slot = self._slot(builder.make_kdf("argon2id", memory=1 << 20,
                                           time=1, cpus=4))
        codes_ = {v.code for v in K.evaluate_keyslot("0", slot)}
        self.assertIn("ARGON2_TIME_BELOW_MIN", codes_)

    def test_owasp_equal_defense_rows_accepted(self):
        for memory, time in C.OWASP_ARGON2ID_ROWS:
            slot = self._slot(builder.make_kdf(
                "argon2id", memory=memory, time=time, cpus=1))
            codes_ = {v.code for v in K.evaluate_keyslot("0", slot)}
            self.assertNotIn("ARGON2_WEAK_PARAMS", codes_)

    def test_argon2i_warns(self):
        slot = self._slot(builder.make_kdf("argon2i"))
        self.assertIn("ARGON2I_PREFER_ID",
                      {v.code for v in K.evaluate_keyslot("0", slot)})

    def test_pbkdf2_iteration_bands(self):
        weak = builder.make_kdf("pbkdf2", iterations=10_000, hash_name="sha256")
        codes_ = {v.code for v in K.evaluate_keyslot("0", self._slot(weak))}
        self.assertIn("PBKDF2_VERY_LOW_ITERATIONS", codes_)
        self.assertIn("PBKDF2_KDF_LEGACY", codes_)

        ok = builder.make_kdf("pbkdf2", iterations=600_000, hash_name="sha256")
        codes_ = {v.code for v in K.evaluate_keyslot("0", self._slot(ok))}
        self.assertIn("PBKDF2_ITERATIONS_OK", codes_)
        self.assertNotIn("PBKDF2_LOW_ITERATIONS", codes_)
        self.assertNotIn("PBKDF2_VERY_LOW_ITERATIONS", codes_)

        sha1 = builder.make_kdf("pbkdf2", iterations=500, hash_name="sha1")
        codes_ = {v.code for v in K.evaluate_keyslot("0", self._slot(sha1))}
        self.assertIn("PBKDF2_WEAK_HASH", codes_)
        self.assertIn("PBKDF2_BELOW_HARD_MIN", codes_)

    def test_small_master_key(self):
        slot = builder.make_keyslot(0, builder.make_kdf("argon2id"),
                                    key_size=16)
        self.assertIn("KEY_SIZE_SMALL",
                      {v.code for v in K.evaluate_keyslot("0", slot)})


class EndToEndFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        builder.main(cls.tmp.name)
        cls.dir = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def audit(self, name):
        return audit_path(str(self.dir / name))

    def test_good_modern_clean(self):
        report = self.audit("good_modern.img")
        self.assertEqual(exit_code(report), 0)
        self.assertEqual(
            report.copies["primary"].json_area.parsed["keyslots"]["0"]
            ["kdf"]["type"], "argon2id")

    def test_legacy_weak_mix_flags_every_family(self):
        report = self.audit("legacy_weak.img")
        self.assertEqual(exit_code(report), 1)
        self.assertIn("PBKDF2_VERY_LOW_ITERATIONS", kdf_codes(report, 0))
        # pre-2.4 32 MiB default: info-level modernize note, not a hard fail
        self.assertTrue(kdf_codes(report, 1) &
                        {"ARGON2_MODERNIZE", "ARGON2_BELOW_BASELINE"})
        self.assertIn("ARGON2I_PREFER_ID", kdf_codes(report, 2))
        self.assertIn("ARGON2_SPEC_VIOLATION", kdf_codes(report, 3))
        self.assertIn("KEY_SIZE_SMALL", kdf_codes(report, 4))
        self.assertIn("PBKDF2_WEAK_HASH", kdf_codes(report, 4))

    def test_corrupt_primary_bin(self):
        report = self.audit("corrupt_primary_bin.img")
        self.assertEqual(exit_code(report), 2)
        self.assertIn("CORRUPT_BIN_RANGE", codes(report))

    def test_corrupt_secondary_json(self):
        report = self.audit("corrupt_secondary_json.img")
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(report.copies["primary"].checksum_ok, True)

    def test_crash_seqid(self):
        report = self.audit("crash_seqid.img")
        self.assertIn("SEQID_MISMATCH", codes(report))
        # both copies individually checksum-valid -> no corruption exit code
        self.assertEqual(exit_code(report), 1)
        newer = next(f.message for f in report.findings
                     if f.code == "SEQID_MISMATCH")
        self.assertIn("secondary copy is authoritative", newer)

    def test_corrupt_both(self):
        report = self.audit("corrupt_both.img")
        self.assertEqual(exit_code(report), 2)
        self.assertTrue(any("BOTH copies fail" in h
                            for h in report.repair_hints))

    def test_truncated_image(self):
        report = self.audit("truncated.img")
        self.assertIn("SECONDARY_MISSING", codes(report))

    def test_header_backup_shape(self):
        report = self.audit("header_backup.bin")
        self.assertEqual(report.copies["primary"].checksum_ok, True)
        self.assertIn("SECONDARY_MISSING", codes(report))

    def test_invalid_json(self):
        report = self.audit("invalid_json_primary.img")
        self.assertIn("JSON_PARSE", codes(report))

    def test_luks1_rejected_gracefully(self):
        report = self.audit("luks1.img")
        self.assertIn("LUKS1_NOT_SUPPORTED", codes(report))
        self.assertEqual(report.luks_version, 1)

    def test_nonexistent_path(self):
        report = audit_path(str(self.dir / "nope.img"))
        self.assertIn("OPEN_FAILED", codes(report))
        self.assertEqual(exit_code(report), 2)

    def test_json_output_is_serializable(self):
        from luks_audit.report import render_json
        report = self.audit("legacy_weak.img")
        payload = json.loads(render_json(report))
        # legacy fixture includes an RFC 9106-violating argon2 parameterset,
        # which is a policy CRITICAL (structure itself is intact, so the
        # process exit code stays 1, not 2)
        self.assertEqual(payload["worst_severity"], C.SEV_CRITICAL)
        self.assertEqual(payload["exit_code"], 1)
        self.assertIn("keyslot_verdicts", payload)


class CliTests(unittest.TestCase):
    def test_cli_exit_codes_and_readonly_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            builder.main(tmp)
            good = os.path.join(tmp, "good_modern.img")
            bad = os.path.join(tmp, "corrupt_primary_bin.img")
            # -I ignores PYTHONPATH/cwd, so inject the repo root from inside
            # the interpreter rather than relying on sys.path side effects.
            runner = (
                "import sys; sys.path.insert(0, %r); "
                "from luks_audit.__main__ import main; sys.exit(main(sys.argv[1:]))"
                % str(ROOT)
            )
            r1 = subprocess.run(
                [sys.executable, "-I", "-c", runner, good],
                cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
            r2 = subprocess.run(
                [sys.executable, "-I", "-c", runner, "--json", bad],
                cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(r2.returncode, 2, r2.stdout + r2.stderr)
            json.loads(r2.stdout)


if __name__ == "__main__":
    unittest.main()
