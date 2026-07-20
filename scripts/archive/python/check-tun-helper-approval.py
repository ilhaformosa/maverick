#!/usr/bin/env python3
"""Validate Maverick TUN helper approval boundary metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"approval_manifest_ready", "incomplete"}
VALID_SLICE_STATUSES = {"smoked_on_approved_vm", "planning_only", "blocked"}
REQUIRED_SLICES = {
    "local_machine_apply",
    "temporary_tun_device",
    "documentation_prefix_route",
    "namespace_scoped_dns",
    "global_dns_policy",
    "service_manager_integration",
    "leak_coexistence_testing",
}
APPROVED_VM_SMOKE_SLICES = {
    "temporary_tun_device",
    "documentation_prefix_route",
    "namespace_scoped_dns",
    "service_manager_integration",
    "leak_coexistence_testing",
}
BLOCKED_SLICES = {
    "local_machine_apply",
    "global_dns_policy",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default="docs/history/manifests/tun-helper-approval.json", type=Path)
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "tun helper approval OK: "
        f"{result['status']} "
        f"({result['slice_count']} slices, "
        f"{result['approved_host_allowed_count']} approved-host slices)"
    )


def check_manifest_file(manifest_path: Path) -> dict[str, int | str]:
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    repo_root = find_repo_root(manifest_path)
    return check_manifest(manifest, repo_root)


def find_repo_root(path: Path) -> Path:
    current = path.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / "Cargo.toml").exists():
            return candidate
    return path.parent


def check_manifest(manifest: dict[str, Any], repo_root: Path) -> dict[str, int | str]:
    if manifest.get("version") != 1:
        raise AssertionError("tun helper approval manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid TUN helper approval status: {status!r}")

    if manifest.get("local_machine_system_apply_allowed") is not False:
        raise AssertionError("TUN helper approval must not allow local-machine system apply")
    for field in (
        "requires_explicit_operator_approval",
        "requires_approved_external_host",
        "requires_rollback_plan",
        "requires_residue_check",
    ):
        if manifest.get(field) is not True:
            raise AssertionError(f"TUN helper approval must set {field}=true")

    reject_legacy_name("notes", require_string(manifest, "notes"))

    slices = manifest.get("mutation_slices")
    if not isinstance(slices, list) or not slices:
        raise AssertionError("TUN helper approval mutation_slices must be a non-empty list")

    seen: set[str] = set()
    approved_host_allowed_count = 0
    for item in slices:
        if not isinstance(item, dict):
            raise AssertionError("each TUN helper mutation slice must be an object")
        slice_id, approved_host_allowed = check_slice(item, repo_root, seen)
        approved_host_allowed_count += int(approved_host_allowed)
        if slice_id in APPROVED_VM_SMOKE_SLICES:
            if not approved_host_allowed:
                raise AssertionError(f"{slice_id}: approved-VM smoke slice must allow approved host")
            if require_string(item, "status") != "smoked_on_approved_vm":
                raise AssertionError(f"{slice_id}: approved-VM smoke slice status drifted")
        if slice_id in BLOCKED_SLICES:
            if approved_host_allowed:
                raise AssertionError(f"{slice_id}: blocked slice must not allow approved host yet")
            if require_string(item, "status") != "blocked":
                raise AssertionError(f"{slice_id}: blocked slice status drifted")

    missing = sorted(REQUIRED_SLICES - seen)
    if missing:
        raise AssertionError(f"missing TUN helper approval slices: {missing}")
    unknown = sorted(seen - REQUIRED_SLICES)
    if unknown:
        raise AssertionError(f"unknown TUN helper approval slices: {unknown}")

    return {
        "status": status,
        "slice_count": len(slices),
        "approved_host_allowed_count": approved_host_allowed_count,
    }


def check_slice(
    item: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, bool]:
    slice_id = require_string(item, "id")
    reject_legacy_name(f"{slice_id}.id", slice_id)
    if slice_id in seen:
        raise AssertionError(f"duplicate TUN helper mutation slice: {slice_id}")
    seen.add(slice_id)

    status = require_string(item, "status")
    if status not in VALID_SLICE_STATUSES:
        raise AssertionError(f"{slice_id}: invalid mutation slice status {status!r}")

    local_allowed = require_bool(item, "local_allowed", slice_id)
    approved_host_allowed = require_bool(item, "approved_host_allowed", slice_id)
    rollback_required = require_bool(item, "rollback_required", slice_id)
    residue_check_required = require_bool(item, "residue_check_required", slice_id)

    if local_allowed:
        raise AssertionError(f"{slice_id}: local mutation must remain disallowed")
    if approved_host_allowed and (not rollback_required or not residue_check_required):
        raise AssertionError(
            f"{slice_id}: approved-host mutation requires rollback and residue checks"
        )

    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError(f"{slice_id}: evidence must be a non-empty list")
    for raw_path in evidence:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{slice_id}: evidence path must be a non-empty string")
        reject_legacy_name(f"{slice_id}.evidence", raw_path)
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{slice_id}: missing evidence path {raw_path}")

    reject_legacy_name(f"{slice_id}.notes", require_string(item, "notes"))
    return slice_id, approved_host_allowed


def require_bool(mapping: dict[str, Any], key: str, item_id: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise AssertionError(f"{item_id}: {key} must be a boolean")
    return value


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def reject_legacy_name(field: str, value: str) -> None:
    if "Mosaic" in value:
        raise AssertionError(f"{field} contains a legacy project name")


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


if __name__ == "__main__":
    main()
