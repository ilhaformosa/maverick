#!/usr/bin/env python3
"""Verify the Maverick conformance vector SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    manifest_path = args.manifest
    root = manifest_path.parent
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    vectors = manifest_vectors(manifest)
    actual_paths = sorted(path.relative_to(root).as_posix() for path in (root / "vectors").glob("*.json"))
    listed_paths = sorted(vectors)
    if actual_paths != listed_paths:
        missing = sorted(set(actual_paths) - set(listed_paths))
        stale = sorted(set(listed_paths) - set(actual_paths))
        raise AssertionError(f"manifest mismatch: missing={missing} stale={stale}")

    for rel_path, expected_sha256 in vectors.items():
        actual_sha256 = sha256(root / rel_path)
        if actual_sha256 != expected_sha256:
            raise AssertionError(
                f"{rel_path}: sha256 mismatch expected={expected_sha256} actual={actual_sha256}"
            )

    print(f"vector manifest OK: {len(vectors)} vectors")


def manifest_vectors(manifest: dict[str, Any]) -> dict[str, str]:
    vectors: dict[str, str] = {}
    for entry in manifest.get("vectors", []):
        path = entry["path"]
        if path in vectors:
            raise AssertionError(f"duplicate vector manifest path: {path}")
        vectors[path] = entry["sha256"]
    if not vectors:
        raise AssertionError("vector manifest is empty")
    return vectors


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
