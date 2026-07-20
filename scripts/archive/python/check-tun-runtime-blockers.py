#!/usr/bin/env python3
"""Validate Maverick TUN runtime blocker execution-plan metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"blocker_execution_plan_ready", "incomplete"}
VALID_SLICE_STATUSES = {"completed_on_approved_vm", "approval_pending", "blocked"}
REQUIRED_SLICES = {
    "phase_a_helper_smoke",
    "phase_b_namespace_runtime_smoke",
    "production_route_policy",
    "default_route_policy",
    "global_dns_policy",
    "service_manager_integration",
    "full_privileged_helper_runtime_integration",
    "leak_coexistence_testing",
}
COMPLETED_SLICES = {
    "phase_a_helper_smoke",
    "phase_b_namespace_runtime_smoke",
    "production_route_policy",
    "default_route_policy",
    "global_dns_policy",
    "service_manager_integration",
    "leak_coexistence_testing",
    "full_privileged_helper_runtime_integration",
}
APPROVAL_PENDING_SLICES: set[str] = set()
BLOCKED_SLICES = REQUIRED_SLICES - COMPLETED_SLICES - APPROVAL_PENDING_SLICES


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default="docs/history/manifests/tun-runtime-blockers.json", type=Path)
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "TUN runtime blockers OK: "
        f"{result['status']} "
        f"({result['slice_count']} slices, "
        f"{result['completed_count']} completed, "
        f"{result['approval_pending_count']} approval-pending)"
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
        raise AssertionError("TUN runtime blocker manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid TUN runtime blocker status: {status!r}")

    for field in (
        "local_machine_network_mutation_allowed",
        "default_route_mutation_allowed",
        "global_dns_mutation_allowed",
    ):
        if manifest.get(field) is not False:
            raise AssertionError(f"TUN runtime blocker plan must set {field}=false")
    for field in (
        "requires_explicit_operator_confirmation",
        "requires_approved_external_host",
        "requires_rollback_plan",
        "requires_residue_check",
    ):
        if manifest.get(field) is not True:
            raise AssertionError(f"TUN runtime blocker plan must set {field}=true")

    reject_legacy_name("notes", require_string(manifest, "notes"))

    slices = manifest.get("blocker_slices")
    if not isinstance(slices, list) or not slices:
        raise AssertionError("TUN runtime blocker_slices must be a non-empty list")

    seen: set[str] = set()
    completed_count = 0
    approval_pending_count = 0
    for item in slices:
        if not isinstance(item, dict):
            raise AssertionError("each TUN runtime blocker slice must be an object")
        slice_id, slice_status = check_slice(item, repo_root, seen)
        completed_count += int(slice_status == "completed_on_approved_vm")
        approval_pending_count += int(slice_status == "approval_pending")

        if slice_id in COMPLETED_SLICES and slice_status != "completed_on_approved_vm":
            raise AssertionError(f"{slice_id}: completed slice status drifted")
        if slice_id in COMPLETED_SLICES:
            if item.get("requires_new_operator_confirmation") is not False:
                raise AssertionError(
                    f"{slice_id}: completed slice must not require new confirmation"
                )
        if slice_id in APPROVAL_PENDING_SLICES:
            if slice_status != "approval_pending":
                raise AssertionError(f"{slice_id}: approval-pending slice status drifted")
            if item.get("remote_mutation_allowed") is not False:
                raise AssertionError(
                    f"{slice_id}: approval-pending slice must not allow remote mutation"
                )
            if item.get("requires_new_operator_confirmation") is not True:
                raise AssertionError(
                    f"{slice_id}: approval-pending slice requires new confirmation"
                )
        if slice_id in BLOCKED_SLICES:
            if slice_status != "blocked":
                raise AssertionError(f"{slice_id}: blocked slice status drifted")
            if item.get("remote_mutation_allowed") is not False:
                raise AssertionError(f"{slice_id}: blocked slice must not allow mutation")

    missing = sorted(REQUIRED_SLICES - seen)
    if missing:
        raise AssertionError(f"missing TUN runtime blocker slices: {missing}")

    return {
        "status": status,
        "slice_count": len(slices),
        "completed_count": completed_count,
        "approval_pending_count": approval_pending_count,
    }


def check_slice(
    item: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, str]:
    slice_id = require_string(item, "id")
    reject_legacy_name(f"{slice_id}.id", slice_id)
    if slice_id in seen:
        raise AssertionError(f"duplicate TUN runtime blocker slice: {slice_id}")
    seen.add(slice_id)

    status = require_string(item, "status")
    if status not in VALID_SLICE_STATUSES:
        raise AssertionError(f"{slice_id}: invalid slice status {status!r}")

    local_allowed = require_bool(item, "local_allowed", slice_id)
    remote_mutation_allowed = require_bool(item, "remote_mutation_allowed", slice_id)
    require_string_or_empty(item, "approved_host_candidate", slice_id)
    require_bool(item, "requires_new_operator_confirmation", slice_id)
    rollback_required = require_bool(item, "rollback_required", slice_id)
    residue_check_required = require_bool(item, "residue_check_required", slice_id)

    if local_allowed:
        raise AssertionError(f"{slice_id}: local mutation must remain disallowed")
    if remote_mutation_allowed:
        raise AssertionError(f"{slice_id}: manifest must not authorize remote mutation")
    if not rollback_required or not residue_check_required:
        raise AssertionError(f"{slice_id}: rollback and residue checks are required")

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
    return slice_id, status


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


def require_string_or_empty(mapping: dict[str, Any], key: str, item_id: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise AssertionError(f"{item_id}: {key} must be a string")
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
