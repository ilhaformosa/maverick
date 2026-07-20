#!/usr/bin/env python3
"""Validate Maverick ECH runtime approval boundary metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"approval_manifest_ready", "incomplete"}
VALID_GATE_STATUSES = {
    "blocked",
    "blocked_native_dependency",
    "blocked_upstream",
    "completed_external",
    "completed_locally",
    "completed_on_approved_host",
    "deferred_runtime_gate",
    "host_approved_no_runtime",
    "planning_only",
    "tracked_locally",
}
REQUIRED_GATES = {
    "client_tls_api_tracking",
    "cloudflare_fronted_runtime_smoke",
    "server_tls_backend",
    "ech_config_distribution",
    "controlled_dns_records",
    "approved_integration_host",
    "fallback_policy_tests",
    "runtime_config_acceptance",
}
TRACKED_LOCAL_GATES = {"client_tls_api_tracking"}
COMPLETED_LOCAL_GATES = {"fallback_policy_tests"}
COMPLETED_EXTERNAL_GATES = {"controlled_dns_records"}
COMPLETED_APPROVED_HOST_GATES = {"cloudflare_fronted_runtime_smoke"}
HOST_APPROVED_GATES = {"approved_integration_host"}
BLOCKED_UPSTREAM_GATES = {"server_tls_backend"}
BLOCKED_NATIVE_DEPENDENCY_GATES = {"ech_config_distribution"}
DEFERRED_RUNTIME_GATES = {"runtime_config_acceptance"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default="docs/history/manifests/ech-runtime-approval.json", type=Path)
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "ECH runtime approval OK: "
        f"{result['status']} "
        f"({result['gate_count']} gates, "
        f"{result['tracked_local_count']} tracked local, "
        f"{result['completed_count']} completed, "
        f"{result['blocked_count']} blocked, "
        f"{result['runtime_allowed_count']} runtime-allowed gates)"
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
        raise AssertionError("ECH runtime approval manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid ECH runtime approval status: {status!r}")

    if manifest.get("runtime_ech_allowed") is not False:
        raise AssertionError("ECH runtime approval must not allow runtime ECH")
    for field in (
        "requires_server_tls_backend",
        "requires_controlled_ech_config_source",
        "requires_controlled_dns_distribution",
        "requires_approved_integration_host",
        "requires_fallback_policy_tests",
        "requires_runtime_config_gate",
    ):
        if manifest.get(field) is not True:
            raise AssertionError(f"ECH runtime approval must set {field}=true")

    reject_legacy_name("notes", require_string(manifest, "notes"))
    reject_review_claims("notes", manifest["notes"])

    gates = manifest.get("runtime_gates")
    if not isinstance(gates, list) or not gates:
        raise AssertionError("ECH runtime approval runtime_gates must be a non-empty list")

    seen: set[str] = set()
    runtime_allowed_count = 0
    network_activity_allowed_count = 0
    tracked_local_count = 0
    completed_count = 0
    blocked_count = 0
    for gate in gates:
        if not isinstance(gate, dict):
            raise AssertionError("each ECH runtime gate must be an object")
        gate_id, gate_status, runtime_allowed, network_activity_allowed = check_gate(
            gate, repo_root, seen
        )
        runtime_allowed_count += int(runtime_allowed)
        network_activity_allowed_count += int(network_activity_allowed)
        tracked_local_count += int(gate_status == "tracked_locally")
        completed_count += int(gate_status.startswith("completed_"))
        blocked_count += int(gate_status.startswith("blocked_"))

        if gate_id in TRACKED_LOCAL_GATES and gate_status != "tracked_locally":
            raise AssertionError(f"{gate_id}: local API gate must remain tracked_locally")
        if gate_id in COMPLETED_LOCAL_GATES and gate_status != "completed_locally":
            raise AssertionError(f"{gate_id}: local-complete gate status drifted")
        if gate_id in COMPLETED_EXTERNAL_GATES and gate_status != "completed_external":
            raise AssertionError(f"{gate_id}: external-complete gate status drifted")
        if (
            gate_id in COMPLETED_APPROVED_HOST_GATES
            and gate_status != "completed_on_approved_host"
        ):
            raise AssertionError(
                f"{gate_id}: approved-host-complete gate status drifted"
            )
        if gate_id in HOST_APPROVED_GATES and gate_status != "host_approved_no_runtime":
            raise AssertionError(f"{gate_id}: approved-host gate status drifted")
        if gate_id in BLOCKED_UPSTREAM_GATES and gate_status != "blocked_upstream":
            raise AssertionError(f"{gate_id}: upstream-blocked gate status drifted")
        if (
            gate_id in BLOCKED_NATIVE_DEPENDENCY_GATES
            and gate_status != "blocked_native_dependency"
        ):
            raise AssertionError(f"{gate_id}: native-dependency gate status drifted")
        if gate_id in DEFERRED_RUNTIME_GATES and gate_status != "deferred_runtime_gate":
            raise AssertionError(f"{gate_id}: runtime gate status drifted")
        if gate_id in REQUIRED_GATES:
            if runtime_allowed:
                raise AssertionError(f"{gate_id}: required gate must not allow runtime")
            if network_activity_allowed:
                raise AssertionError(
                    f"{gate_id}: manifest must not allow network activity"
                )

    missing = sorted(REQUIRED_GATES - seen)
    if missing:
        raise AssertionError(f"missing ECH runtime approval gates: {missing}")

    if runtime_allowed_count:
        raise AssertionError("ECH runtime approval cannot have runtime-allowed gates")
    if network_activity_allowed_count:
        raise AssertionError("ECH runtime approval cannot allow network activity")

    return {
        "status": status,
        "gate_count": len(gates),
        "tracked_local_count": tracked_local_count,
        "completed_count": completed_count,
        "blocked_count": blocked_count,
        "runtime_allowed_count": runtime_allowed_count,
    }


def check_gate(
    gate: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, str, bool, bool]:
    gate_id = require_string(gate, "id")
    reject_legacy_name(f"{gate_id}.id", gate_id)
    if gate_id in seen:
        raise AssertionError(f"duplicate ECH runtime gate: {gate_id}")
    seen.add(gate_id)

    status = require_string(gate, "status")
    if status not in VALID_GATE_STATUSES:
        raise AssertionError(f"{gate_id}: invalid gate status {status!r}")

    runtime_allowed = require_bool(gate, "runtime_allowed", gate_id)
    network_activity_allowed = require_bool(gate, "network_activity_allowed", gate_id)
    evidence = gate.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError(f"{gate_id}: evidence must be a non-empty list")
    for raw_path in evidence:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{gate_id}: evidence path must be a non-empty string")
        reject_legacy_name(f"{gate_id}.evidence", raw_path)
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{gate_id}: missing evidence path {raw_path}")

    reject_legacy_name(f"{gate_id}.notes", require_string(gate, "notes"))
    reject_review_claims(f"{gate_id}.notes", gate["notes"])
    return gate_id, status, runtime_allowed, network_activity_allowed


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
