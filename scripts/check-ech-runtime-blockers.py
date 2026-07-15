#!/usr/bin/env python3
"""Validate Maverick ECH runtime blocker execution-plan metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"blocker_execution_plan_ready", "incomplete"}
VALID_SLICE_STATUSES = {
    "completed_locally",
    "completed_external",
    "completed_on_approved_host",
    "host_approved_no_runtime",
    "operator_action_ready",
    "blocked_provider_behavior",
    "blocked_upstream",
    "blocked_runtime_dependency",
}
REQUIRED_SLICES = {
    "client_tls_api_tracking",
    "fallback_policy_tests",
    "approved_integration_host",
    "controlled_dns_record_plan",
    "cloudflare_edge_preflight",
    "cloudflare_origin_reachability",
    "cloudflare_fronted_runtime_smoke",
    "server_tls_backend",
    "ech_config_distribution",
    "runtime_handshake_smoke",
    "runtime_config_acceptance",
}
COMPLETED_LOCAL_SLICES = {
    "client_tls_api_tracking",
    "fallback_policy_tests",
}
HOST_APPROVED_SLICES = {"approved_integration_host"}
COMPLETED_EXTERNAL_SLICES = {"controlled_dns_record_plan"}
COMPLETED_APPROVED_HOST_SLICES = {
    "cloudflare_edge_preflight",
    "cloudflare_origin_reachability",
    "cloudflare_fronted_runtime_smoke",
}
OPERATOR_ACTION_READY_SLICES = set()
BLOCKED_PROVIDER_BEHAVIOR_SLICES = set()
BLOCKED_UPSTREAM_SLICES = {"server_tls_backend"}
BLOCKED_RUNTIME_DEPENDENCY_SLICES = {
    "ech_config_distribution",
    "runtime_handshake_smoke",
    "runtime_config_acceptance",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default="docs/history/manifests/ech-runtime-blockers.json", type=Path)
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "ECH runtime blockers OK: "
        f"{result['status']} "
        f"({result['slice_count']} slices, "
        f"{result['completed_local_count']} local-complete, "
        f"{result['completed_external_count']} external-complete, "
        f"{result['completed_approved_host_count']} approved-host-complete, "
        f"{result['blocked_count']} blocked)"
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
        raise AssertionError("ECH runtime blocker manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid ECH runtime blocker status: {status!r}")

    for field in (
        "runtime_ech_allowed",
        "runtime_network_activity_allowed",
        "local_machine_network_mutation_allowed",
    ):
        if manifest.get(field) is not False:
            raise AssertionError(f"ECH runtime blocker plan must set {field}=false")
    for field in (
        "requires_server_tls_backend",
        "requires_controlled_dns_distribution",
        "requires_approved_external_host",
        "requires_explicit_operator_dns_change",
    ):
        if manifest.get(field) is not True:
            raise AssertionError(f"ECH runtime blocker plan must set {field}=true")

    reject_legacy_name("notes", require_string(manifest, "notes"))
    reject_review_claims("notes", manifest["notes"])

    slices = manifest.get("blocker_slices")
    if not isinstance(slices, list) or not slices:
        raise AssertionError("ECH runtime blocker_slices must be a non-empty list")

    seen: set[str] = set()
    completed_local_count = 0
    completed_external_count = 0
    completed_approved_host_count = 0
    operator_action_ready_count = 0
    blocked_count = 0
    for item in slices:
        if not isinstance(item, dict):
            raise AssertionError("each ECH runtime blocker slice must be an object")
        slice_id, slice_status = check_slice(item, repo_root, seen)
        completed_local_count += int(slice_status == "completed_locally")
        completed_external_count += int(slice_status == "completed_external")
        completed_approved_host_count += int(slice_status == "completed_on_approved_host")
        operator_action_ready_count += int(slice_status == "operator_action_ready")
        blocked_count += int(slice_status.startswith("blocked_"))

        if slice_id in COMPLETED_LOCAL_SLICES:
            if slice_status != "completed_locally":
                raise AssertionError(f"{slice_id}: local-complete slice status drifted")
            if item.get("requires_user_action") is not False:
                raise AssertionError(f"{slice_id}: local-complete slice needs no user action")
            if item.get("requires_upstream_change") is not False:
                raise AssertionError(
                    f"{slice_id}: local-complete slice must not require upstream change"
                )
        if slice_id in HOST_APPROVED_SLICES:
            if slice_status != "host_approved_no_runtime":
                raise AssertionError(f"{slice_id}: approved-host slice status drifted")
            if item.get("approved_host_candidate") != "approved-linux-vm":
                raise AssertionError(f"{slice_id}: approved host must be approved-linux-vm")
        if slice_id in COMPLETED_EXTERNAL_SLICES:
            if slice_status != "completed_external":
                raise AssertionError(f"{slice_id}: external-complete slice status drifted")
            if item.get("requires_user_action") is not False:
                raise AssertionError(f"{slice_id}: external-complete slice needs no user action")
        if slice_id in COMPLETED_APPROVED_HOST_SLICES:
            if slice_status != "completed_on_approved_host":
                raise AssertionError(
                    f"{slice_id}: approved-host-complete slice status drifted"
                )
            if item.get("approved_host_candidate") != "approved-linux-vm":
                raise AssertionError(f"{slice_id}: approved host must be approved-linux-vm")
            if item.get("requires_user_action") is not False:
                raise AssertionError(
                    f"{slice_id}: approved-host-complete slice needs no user action"
                )
            if item.get("requires_upstream_change") is not False:
                raise AssertionError(
                    f"{slice_id}: approved-host-complete slice must not require upstream"
                )
        if slice_id in OPERATOR_ACTION_READY_SLICES:
            if slice_status != "operator_action_ready":
                raise AssertionError(f"{slice_id}: operator-action slice status drifted")
            if item.get("requires_user_action") is not True:
                raise AssertionError(f"{slice_id}: operator-action slice needs user action")
        if slice_id in BLOCKED_PROVIDER_BEHAVIOR_SLICES:
            if slice_status != "blocked_provider_behavior":
                raise AssertionError(
                    f"{slice_id}: provider-behavior slice status drifted"
                )
            if item.get("approved_host_candidate") != "approved-linux-vm":
                raise AssertionError(f"{slice_id}: approved host must be approved-linux-vm")
            if item.get("requires_user_action") is not False:
                raise AssertionError(f"{slice_id}: provider-behavior slice needs no user action")
            if item.get("requires_upstream_change") is not False:
                raise AssertionError(
                    f"{slice_id}: provider-behavior slice must not require upstream change"
                )
        if slice_id in BLOCKED_UPSTREAM_SLICES:
            if slice_status != "blocked_upstream":
                raise AssertionError(f"{slice_id}: upstream-blocked slice status drifted")
            if item.get("requires_upstream_change") is not True:
                raise AssertionError(f"{slice_id}: upstream-blocked slice needs upstream change")
        if slice_id in BLOCKED_RUNTIME_DEPENDENCY_SLICES:
            if slice_status != "blocked_runtime_dependency":
                raise AssertionError(f"{slice_id}: runtime-blocked slice status drifted")
            if item.get("requires_upstream_change") is not True:
                raise AssertionError(f"{slice_id}: runtime-blocked slice needs upstream change")

    missing = sorted(REQUIRED_SLICES - seen)
    if missing:
        raise AssertionError(f"missing ECH runtime blocker slices: {missing}")

    if completed_local_count != len(COMPLETED_LOCAL_SLICES):
        raise AssertionError("ECH runtime blocker plan has an unexpected local-complete count")
    if completed_external_count != len(COMPLETED_EXTERNAL_SLICES):
        raise AssertionError(
            "ECH runtime blocker plan has an unexpected external-complete count"
        )
    if completed_approved_host_count != len(COMPLETED_APPROVED_HOST_SLICES):
        raise AssertionError(
            "ECH runtime blocker plan has an unexpected approved-host-complete count"
        )
    if operator_action_ready_count != len(OPERATOR_ACTION_READY_SLICES):
        raise AssertionError(
            "ECH runtime blocker plan has an unexpected operator-action count"
        )

    return {
        "status": status,
        "slice_count": len(slices),
        "completed_local_count": completed_local_count,
        "completed_external_count": completed_external_count,
        "completed_approved_host_count": completed_approved_host_count,
        "operator_action_ready_count": operator_action_ready_count,
        "blocked_count": blocked_count,
    }


def check_slice(
    item: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, str]:
    slice_id = require_string(item, "id")
    reject_legacy_name(f"{slice_id}.id", slice_id)
    if slice_id in seen:
        raise AssertionError(f"duplicate ECH runtime blocker slice: {slice_id}")
    seen.add(slice_id)

    status = require_string(item, "status")
    if status not in VALID_SLICE_STATUSES:
        raise AssertionError(f"{slice_id}: invalid slice status {status!r}")

    if require_bool(item, "local_network_mutation_allowed", slice_id):
        raise AssertionError(f"{slice_id}: local network mutation must remain disallowed")
    if require_bool(item, "dns_mutation_allowed", slice_id):
        raise AssertionError(f"{slice_id}: manifest must not authorize DNS mutation")
    if require_bool(item, "runtime_network_activity_allowed", slice_id):
        raise AssertionError(f"{slice_id}: manifest must not allow runtime network activity")
    require_string_or_empty(item, "approved_host_candidate", slice_id)
    require_bool(item, "requires_user_action", slice_id)
    require_bool(item, "requires_upstream_change", slice_id)

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
    reject_review_claims(f"{slice_id}.notes", item["notes"])
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
