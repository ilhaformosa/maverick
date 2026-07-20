#!/usr/bin/env python3
"""Reject complete Maverick credentials outside the canonical test vectors."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


TOKEN_PATTERN = re.compile(rb"(?<![A-Za-z0-9_-])mv1_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
CANONICAL_TEST_SECRET = (
    b"mv1_AAECAwQFBgcICQoLDA0O"
    b"DxAREhMUFRYXGBkaGxwdHh8"
)
CANONICAL_TEST_PATHS = {
    "conformance/vectors/auth_v1_client_hello.json",
    "conformance/vectors/auth_v1_server_hello.json",
    "conformance/vectors/auth_v2_client_hello.json",
    "conformance/vectors/auth_v2_server_hello.json",
    "crates/maverick-core/tests/conformance_vectors.rs",
}


def repository_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def scan_paths(root: Path, relative_paths: list[str]) -> list[tuple[str, int]]:
    findings: list[tuple[str, int]] = []
    for relative in relative_paths:
        path = root / relative
        try:
            data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        except (OSError, UnicodeError):
            continue
        for match in TOKEN_PATTERN.finditer(data):
            if relative in CANONICAL_TEST_PATHS and match.group() == CANONICAL_TEST_SECRET:
                continue
            findings.append((relative, data.count(b"\n", 0, match.start()) + 1))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    findings = scan_paths(root, repository_paths(root))
    for path, line in findings:
        print(f"secret-like Maverick credential: {path}:{line}", file=sys.stderr)
    if findings:
        print("source secret hygiene failed", file=sys.stderr)
        return 1
    print("source secret hygiene OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
