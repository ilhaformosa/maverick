#!/usr/bin/env python3
"""Validate Maverick Noise runtime approval boundary metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"approval_manifest_ready", "incomplete"}
VALID_GATE_STATUSES = {
    "blocked",
    "planning_only",
    "completed_non_runtime",
    "completed_runtime_harness",
    "deferred_product_gate",
    "deferred_claim_gate",
}
REQUIRED_GATES = {
    "implementation_selection",
    "implementation_backed_vectors",
    "transcript_prologue_tests",
    "downgrade_tests",
    "runtime_session_harness",
    "runtime_config_acceptance",
    "community_crypto_review",
}
COMPLETED_NON_RUNTIME_GATES = {
    "implementation_selection",
    "implementation_backed_vectors",
    "transcript_prologue_tests",
    "downgrade_tests",
}
COMPLETED_RUNTIME_HARNESS_GATES = {"runtime_session_harness"}
DEFERRED_PRODUCT_GATES = {"runtime_config_acceptance"}
DEFERRED_CLAIM_GATES = {"community_crypto_review"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "manifest", nargs="?", default="docs/history/manifests/noise-runtime-approval.json", type=Path
    )
    args = parser.parse_args()

    result = check_manifest_file(args.manifest)
    print(
        "noise runtime approval OK: "
        f"{result['status']} "
        f"({result['gate_count']} gates, "
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
        raise AssertionError("Noise runtime approval manifest version must be 1")

    status = require_string(manifest, "status")
    if status not in VALID_STATUSES:
        raise AssertionError(f"invalid Noise runtime approval status: {status!r}")

    if manifest.get("runtime_noise_allowed") is not False:
        raise AssertionError("Noise runtime approval must not allow runtime Noise")
    for field in (
        "requires_candidate_implementation",
        "requires_implementation_vectors",
        "requires_transcript_prologue_tests",
        "requires_downgrade_tests",
        "requires_runtime_config_gate",
        "requires_community_crypto_review_before_security_claims",
    ):
        if manifest.get(field) is not True:
            raise AssertionError(f"Noise runtime approval must set {field}=true")

    if manifest.get("requires_formal_human_crypto_review") is not False:
        raise AssertionError(
            "Noise runtime approval must set requires_formal_human_crypto_review=false"
        )

    reject_legacy_name("notes", require_string(manifest, "notes"))
    reject_review_claims("notes", manifest["notes"])

    gates = manifest.get("runtime_gates")
    if not isinstance(gates, list) or not gates:
        raise AssertionError("Noise runtime approval runtime_gates must be a non-empty list")

    seen: set[str] = set()
    runtime_allowed_count = 0
    for gate in gates:
        if not isinstance(gate, dict):
            raise AssertionError("each Noise runtime gate must be an object")
        gate_id, runtime_allowed = check_gate(gate, repo_root, seen)
        runtime_allowed_count += int(runtime_allowed)
        if gate_id in REQUIRED_GATES:
            if runtime_allowed:
                raise AssertionError(f"{gate_id}: required gate must not allow runtime")
            gate_status = require_string(gate, "status")
            if gate_id in COMPLETED_NON_RUNTIME_GATES and gate_status != "completed_non_runtime":
                raise AssertionError(
                    f"{gate_id}: required evidence gate must be completed_non_runtime"
                )
            if (
                gate_id in COMPLETED_RUNTIME_HARNESS_GATES
                and gate_status != "completed_runtime_harness"
            ):
                raise AssertionError(
                    f"{gate_id}: runtime harness gate must be completed_runtime_harness"
                )
            if gate_id in DEFERRED_PRODUCT_GATES and gate_status != "deferred_product_gate":
                raise AssertionError(
                    f"{gate_id}: product gate must remain deferred_product_gate"
                )
            if gate_id in DEFERRED_CLAIM_GATES and gate_status != "deferred_claim_gate":
                raise AssertionError(
                    f"{gate_id}: claim gate must remain deferred_claim_gate"
                )

    missing = sorted(REQUIRED_GATES - seen)
    if missing:
        raise AssertionError(f"missing Noise runtime approval gates: {missing}")

    if runtime_allowed_count:
        raise AssertionError("Noise runtime approval cannot have runtime-allowed gates")

    return {
        "status": status,
        "gate_count": len(gates),
        "runtime_allowed_count": runtime_allowed_count,
    }


def check_gate(
    gate: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, bool]:
    gate_id = require_string(gate, "id")
    reject_legacy_name(f"{gate_id}.id", gate_id)
    if gate_id in seen:
        raise AssertionError(f"duplicate Noise runtime gate: {gate_id}")
    seen.add(gate_id)

    status = require_string(gate, "status")
    if status not in VALID_GATE_STATUSES:
        raise AssertionError(f"{gate_id}: invalid gate status {status!r}")

    runtime_allowed = require_bool(gate, "runtime_allowed", gate_id)
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
    return gate_id, runtime_allowed


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
