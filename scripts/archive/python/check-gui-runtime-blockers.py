#!/usr/bin/env python3
"""Validate Maverick GUI/tray runtime blocker metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"blocker_execution_plan_ready", "incomplete"}
VALID_SLICE_STATUSES = {
    "completed_locally",
    "blocked_product_runtime",
    "blocked_release_gate",
}
REQUIRED_SLICES = {
    "core_diagnostics",
    "sdk_runtime_baseline",
    "debug_redaction_tests",
    "ui_scope_decision",
    "platform_target_decision",
    "secure_profile_storage",
    "service_lifecycle_integration",
    "signing_notarization",
    "tun_safety_integration",
    "ui_smoke_tests",
    "release_packaging",
}
COMPLETED_LOCAL_SLICES = {
    "core_diagnostics",
    "sdk_runtime_baseline",
    "debug_redaction_tests",
    "ui_scope_decision",
    "platform_target_decision",
    "secure_profile_storage",
    "service_lifecycle_integration",
    "tun_safety_integration",
    "ui_smoke_tests",
}
BLOCKED_PRODUCT_RUNTIME_SLICES: set[str] = set()
BLOCKED_RELEASE_GATE_SLICES = {
    "signing_notarization",
    "release_packaging",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default="docs/history/manifests/gui-runtime-blockers.json", type=Path)
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "GUI runtime blockers OK: "
        f"{result['status']} "
        f"({result['slice_count']} slices, "
        f"{result['completed_local_count']} local-complete, "
        f"{result['blocked_product_count']} product-blocked, "
        f"{result['blocked_release_count']} release-blocked)"
    )


def check_manifest_file(manifest_path: Path) -> dict[str, int | str]:
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    return check_manifest(manifest, find_repo_root(manifest_path))


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
        raise AssertionError("GUI runtime blocker manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid GUI runtime blocker status: {status!r}")

    for field in (
        "gui_runtime_allowed",
        "local_machine_network_mutation_allowed",
        "system_proxy_mutation_allowed",
        "system_dns_route_firewall_mutation_allowed",
    ):
        if manifest.get(field) is not False:
            raise AssertionError(f"GUI runtime blocker manifest must set {field}=false")

    reject_legacy_name("notes", require_string(manifest, "notes"))
    reject_unsupported_claims("notes", manifest["notes"])

    slices = manifest.get("blocker_slices")
    if not isinstance(slices, list) or not slices:
        raise AssertionError("GUI runtime blocker_slices must be a non-empty list")

    seen: set[str] = set()
    completed_local_count = 0
    blocked_product_count = 0
    blocked_release_count = 0
    for item in slices:
        if not isinstance(item, dict):
            raise AssertionError("each GUI runtime blocker slice must be an object")
        slice_id, slice_status = check_slice(item, repo_root, seen)
        completed_local_count += int(slice_status == "completed_locally")
        blocked_product_count += int(slice_status == "blocked_product_runtime")
        blocked_release_count += int(slice_status == "blocked_release_gate")

        if slice_id in COMPLETED_LOCAL_SLICES and slice_status != "completed_locally":
            raise AssertionError(f"{slice_id}: local-complete slice status drifted")
        if (
            slice_id in BLOCKED_PRODUCT_RUNTIME_SLICES
            and slice_status != "blocked_product_runtime"
        ):
            raise AssertionError(f"{slice_id}: product-runtime slice status drifted")
        if slice_id in BLOCKED_RELEASE_GATE_SLICES and slice_status != "blocked_release_gate":
            raise AssertionError(f"{slice_id}: release-gate slice status drifted")

    missing = sorted(REQUIRED_SLICES - seen)
    if missing:
        raise AssertionError(f"missing GUI runtime blocker slices: {missing}")

    if completed_local_count != len(COMPLETED_LOCAL_SLICES):
        raise AssertionError("GUI runtime blocker plan has unexpected local-complete count")
    if blocked_product_count != len(BLOCKED_PRODUCT_RUNTIME_SLICES):
        raise AssertionError("GUI runtime blocker plan has unexpected product-blocked count")
    if blocked_release_count != len(BLOCKED_RELEASE_GATE_SLICES):
        raise AssertionError("GUI runtime blocker plan has unexpected release-blocked count")

    return {
        "status": status,
        "slice_count": len(slices),
        "completed_local_count": completed_local_count,
        "blocked_product_count": blocked_product_count,
        "blocked_release_count": blocked_release_count,
    }


def check_slice(item: dict[str, Any], repo_root: Path, seen: set[str]) -> tuple[str, str]:
    slice_id = require_string(item, "id")
    reject_legacy_name(f"{slice_id}.id", slice_id)
    if slice_id in seen:
        raise AssertionError(f"duplicate GUI runtime blocker slice: {slice_id}")
    seen.add(slice_id)

    status = require_string(item, "status")
    if status not in VALID_SLICE_STATUSES:
        raise AssertionError(f"{slice_id}: invalid slice status {status!r}")
    if item.get("runtime_allowed") is not False:
        raise AssertionError(f"{slice_id}: runtime_allowed must remain false")
    if not isinstance(item.get("requires_user_action"), bool):
        raise AssertionError(f"{slice_id}: requires_user_action must be a boolean")

    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError(f"{slice_id}: evidence must be a non-empty list")
    for raw_path in evidence:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{slice_id}: evidence path must be a non-empty string")
        reject_legacy_name(f"{slice_id}.evidence", raw_path)
        actual_path = repo_root / safe_relative_path(raw_path)
        if not actual_path.exists():
            raise AssertionError(f"{slice_id}: missing evidence path {raw_path}")

    reject_legacy_name(f"{slice_id}.notes", require_string(item, "notes"))
    reject_unsupported_claims(f"{slice_id}.notes", item["notes"])
    return slice_id, status


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def reject_legacy_name(field: str, value: str) -> None:
    if "Mosaic" in value:
        raise AssertionError(f"{field} contains a legacy project name")


def reject_unsupported_claims(field: str, value: str) -> None:
    lowered = value.lower()
    forbidden = (
        "production ready",
        "release ready",
        "notarized",
        "signed app",
        "system proxy enabled",
        "system network manager integration",
    )
    for token in forbidden:
        if token in lowered:
            raise AssertionError(f"{field} contains unsupported GUI claim: {token}")


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


if __name__ == "__main__":
    main()
