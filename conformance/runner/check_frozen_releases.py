#!/usr/bin/env python3
"""Verify Maverick frozen conformance release immutability policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"no-frozen-releases", "active"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()

    result = check_policy_file(args.policy)
    print(f"frozen release policy OK: {result} frozen releases")


def check_policy_file(policy_path: Path) -> int:
    with policy_path.open("r", encoding="utf-8") as handle:
        policy = json.load(handle)

    conformance_root = policy_path.parent
    return check_policy(policy, conformance_root)


def check_policy(policy: dict[str, Any], conformance_root: Path) -> int:
    if policy.get("version") != 1:
        raise AssertionError("frozen release policy version must be 1")
    status = policy.get("status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid frozen release policy status: {status!r}")

    releases = policy.get("frozen_releases")
    if not isinstance(releases, list):
        raise AssertionError("frozen_releases must be a list")
    if status == "no-frozen-releases" and releases:
        raise AssertionError("no-frozen-releases status cannot list releases")
    if status == "active" and not releases:
        raise AssertionError("active status must list at least one release")

    seen: set[str] = set()
    for release in releases:
        check_release(release, conformance_root, seen)

    return len(releases)


def check_release(release: dict[str, Any], conformance_root: Path, seen: set[str]) -> None:
    name = require_string(release, "release")
    if name in seen:
        raise AssertionError(f"duplicate frozen release: {name}")
    seen.add(name)

    manifest_path = safe_relative_path(require_string(release, "manifest_path"))
    manifest_sha256 = require_string(release, "manifest_sha256")
    actual_manifest_path = conformance_root / manifest_path
    if not actual_manifest_path.is_file():
        raise AssertionError(f"{name}: missing frozen manifest {manifest_path}")
    if sha256(actual_manifest_path) != manifest_sha256:
        raise AssertionError(f"{name}: frozen manifest sha256 mismatch")

    with actual_manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("release") != name:
        raise AssertionError(f"{name}: manifest release name mismatch")

    seen_paths: set[str] = set()
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise AssertionError(f"{name}: frozen manifest must list vectors")
    for vector in vectors:
        rel_path = safe_relative_path(require_string(vector, "path"))
        rel_path_text = rel_path.as_posix()
        if rel_path_text in seen_paths:
            raise AssertionError(f"{name}: duplicate vector path {rel_path_text}")
        seen_paths.add(rel_path_text)

        expected_sha256 = require_string(vector, "sha256")
        actual_vector_path = conformance_root / rel_path
        if not actual_vector_path.is_file():
            raise AssertionError(f"{name}: missing frozen vector {rel_path_text}")
        if sha256(actual_vector_path) != expected_sha256:
            raise AssertionError(f"{name}: frozen vector sha256 mismatch for {rel_path_text}")


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
