#!/usr/bin/env python3
"""Validate Maverick external security review package metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"review_package_ready", "incomplete"}
REQUIRED_GROUPS = {
    "protocol_and_security_docs",
    "roadmap_and_capability_docs",
    "privacy_and_experimental_docs",
    "platform_and_crypto_docs",
    "conformance_and_freeze_inputs",
    "harness_and_ci_inputs",
    "audit_process_and_decision_inputs",
}
REQUIRED_ARTIFACTS = {
    "docs/history/review/S3_REVIEW_HANDOFF_2026_07_08.md",
    "docs/history/review/S3_FINDINGS_TRIAGE_TEMPLATE_2026_07_08.md",
    "docs/INDEPENDENT_AUDIT_PACKAGE.md",
    "docs/AUDIT_EVIDENCE_INDEX.md",
    "docs/PRODUCTION_GO_NO_GO_TEMPLATE.md",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?", default="security-review-package.json", type=Path)
    args = parser.parse_args()

    result = check_package_file(args.package)
    print(
        "security review package OK: "
        f"{result['status']} "
        f"({result['artifact_group_count']} groups, "
        f"{result['artifact_count']} artifacts)"
    )


def check_package_file(package_path: Path) -> dict[str, int | str]:
    with package_path.open("r", encoding="utf-8") as handle:
        package = json.load(handle)

    repo_root = package_path.parent
    return check_package(package, repo_root)


def check_package(package: dict[str, Any], repo_root: Path) -> dict[str, int | str]:
    if package.get("version") != 1:
        raise AssertionError("security review package version must be 1")

    status = require_string(package, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid security review package status: {status!r}")

    if package.get("external_review_completed") is not False:
        raise AssertionError("security review package must not claim completed external review")

    reject_legacy_name("notes", require_string(package, "notes"))
    reject_review_claims("notes", package["notes"])

    groups = package.get("artifact_groups")
    if not isinstance(groups, list) or not groups:
        raise AssertionError("security review package artifact_groups must be a non-empty list")

    seen: set[str] = set()
    artifact_count = 0
    required_count = 0
    seen_paths: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise AssertionError("each security review package artifact group must be an object")
        group_id, paths, required = check_group(group, repo_root, seen, seen_paths)
        if group_id in REQUIRED_GROUPS and not required:
            raise AssertionError(f"{group_id}: required artifact group must remain required")
        artifact_count += paths
        required_count += int(required)

    missing = sorted(REQUIRED_GROUPS - seen)
    if missing:
        raise AssertionError(f"missing security review package artifact groups: {missing}")

    missing_artifacts = sorted(REQUIRED_ARTIFACTS - seen_paths)
    if missing_artifacts:
        raise AssertionError(f"missing security review package artifacts: {missing_artifacts}")

    if status == "review_package_ready" and required_count < len(REQUIRED_GROUPS):
        raise AssertionError("review package cannot be ready without all required groups")

    return {
        "status": status,
        "artifact_group_count": len(groups),
        "artifact_count": artifact_count,
    }


def check_group(
    group: dict[str, Any], repo_root: Path, seen: set[str], seen_paths: set[str]
) -> tuple[str, int, bool]:
    group_id = require_string(group, "id")
    reject_legacy_name(f"{group_id}.id", group_id)
    if group_id in seen:
        raise AssertionError(f"duplicate security review package artifact group: {group_id}")
    seen.add(group_id)

    required = group.get("required")
    if not isinstance(required, bool):
        raise AssertionError(f"{group_id}: required must be a boolean")

    paths = group.get("paths")
    if not isinstance(paths, list) or not paths:
        raise AssertionError(f"{group_id}: paths must be a non-empty list")

    path_seen: set[str] = set()
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{group_id}: path entries must be non-empty strings")
        reject_legacy_name(f"{group_id}.paths", raw_path)
        if raw_path in path_seen:
            raise AssertionError(f"{group_id}: duplicate path {raw_path!r}")
        path_seen.add(raw_path)
        seen_paths.add(raw_path)
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{group_id}: missing package artifact {raw_path}")

    notes = require_string(group, "notes")
    reject_legacy_name(f"{group_id}.notes", notes)
    reject_review_claims(f"{group_id}.notes", notes)
    return group_id, len(paths), required


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def reject_legacy_name(field: str, value: str) -> None:
    if "Mosaic" in value:
        raise AssertionError(f"{field} contains a legacy project name")


def reject_review_claims(field: str, value: str) -> None:
    lowered = value.lower()
    forbidden = (
        "audit completed",
        "audited",
        "reviewed release",
        "stable release",
        "production ready",
        "standardized",
    )
    for token in forbidden:
        if token in lowered:
            raise AssertionError(f"{field} contains an unsupported review claim: {token}")


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


if __name__ == "__main__":
    main()
