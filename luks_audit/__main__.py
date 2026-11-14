"""
Command line entry point.

Usage:
    python -m luks_audit [--json] [--quiet] IMAGE [IMAGE ...]

Every target is opened O_RDONLY; the tool has no write code path at all and
works against block devices, raw disk images and luksHeaderBackup files
alike (a header backup is just the 16 MiB primary region).
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import constants as C
from .engine import audit_path
from .report import exit_code, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="luks_audit",
        description="Read-only LUKS2 header/JSON/KDF auditor. "
                    "Never writes to the target.")
    p.add_argument("images", nargs="+", metavar="IMAGE",
                   help="disk image, block device or LUKS2 header backup file")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON instead of text")
    p.add_argument("--quiet", action="store_true",
                   help="text mode: print only the summary block")
    p.add_argument("--version", action="version", version="luks_audit 1.0.0")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    worst = C.EXIT_CLEAN
    payloads = []
    for index, path in enumerate(args.images):
        report = audit_path(path)
        code = exit_code(report)
        worst = max(worst, code)
        if args.json:
            payloads.append(render_json(report))
        else:
            if index:
                print()
            text = render_text(report)
            if args.quiet:
                text = "\n".join(text.splitlines()[-4:])
            print(text)
    if args.json:
        if len(payloads) == 1:
            print(payloads[0])
        else:
            print("[" + ",".join(payloads) + "]")
    return worst


if __name__ == "__main__":
    sys.exit(main())
