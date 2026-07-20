#!/usr/bin/env python3
"""Validate the redacted, reproducible TUN engine comparison package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


EXPECTED_COMPONENTS = {
    "ipstack_family": {
        "ipstack": (
            "1.0.0",
            "c06e2a1aaecfd78033e1dca233c2e871b007ae30",
            "d603c9807158f8054f56c3672c8670096580c3ec1d5bab6f27b2aca89be89117",
            "Apache-2.0",
            "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        ),
        "tun2proxy": (
            "0.8.2",
            "eed123fbbec06295bf83f9be36d5a0f64ed9a8cb",
            "058486886fa3987ca284673b467f52f7c60e22ac6cf5d1e91f2d63b8f024bad4",
            "MIT",
            "8cddc80ccbbb14a8a3d7fee1fc1795d7fcd647f4c7063ad95246f9ff24b407c7",
        ),
    },
    "smoltcp": {
        "smoltcp": (
            "0.13.1",
            "e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897",
            "5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e",
            "0BSD",
            "beb2cad88fab8447f7975564e21f9506e733e14c344836f146fa02e811216694",
        ),
    },
    "gvisor_sidecar": {
        "gvisor-netstack": (
            "unversioned-api-snapshot",
            "6d73c10d795c9d08ce277545a5a6a8227c601681",
            "not_applicable",
            "Apache-2.0",
            "0fbab5c58efbdf6d31e8085214f2dd821659c03d73cff3ed2b08e98826ea1cd9",
        ),
    },
}

EXPECTED_STATUSES = {
    "ipstack_family": "rejected",
    "smoltcp": "selected_for_phase_1",
    "gvisor_sidecar": "rejected",
}

REQUIRED_SELECTED_CASES = {
    "PKT-01",
    "PKT-02",
    "PKT-03",
    "PKT-04",
    "PKT-05",
    "PKT-06",
    "PKT-07",
    "PKT-09",
    "PKT-10",
    "TCP-01",
    "TCP-02",
    "TCP-03",
    "TCP-05",
    "TCP-06",
    "TCP-07",
    "TCP-09",
    "TCP-10",
    "TCP-11",
    "TCP-12",
    "TCP-14",
    "UDP-01",
    "UDP-02",
    "UDP-11",
    "RES-03",
    "RES-04",
    "RES-05",
}

REQUIRED_SMOLTCP_FEATURES = {
    "std",
    "medium-ip",
    "proto-ipv4",
    "proto-ipv4-fragmentation",
    "proto-ipv6",
    "proto-ipv6-fragmentation",
    "socket-tcp",
    "socket-tcp-reno",
    "socket-udp",
}

FORBIDDEN_FEATURES = {
    "medium-ethernet",
    "phy-raw_socket",
    "phy-tuntap_interface",
}

PRIVATE_MARKERS = (
    "/Users/",
    "\\Users\\",
    ".ssh/",
    "known_hosts",
    "PRIVATE_LAUNCH",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    args = parser.parse_args()
    summary = check_repository(args.repo_root.resolve())
    print(
        "TUN engine comparison OK: "
        f"{summary['candidate_count']} candidates, "
        f"selected={summary['selected']}, "
        f"{summary['selected_case_count']} selected cases"
    )


def check_repository(repo_root: Path) -> dict[str, Any]:
    comparison_root = repo_root / "spikes/tun-engine-comparison"
    manifest_path = comparison_root / "candidates.json"
    manifest = load_json(manifest_path)
    candidates = validate_candidate_manifest(manifest)

    results: dict[str, dict[str, Any]] = {}
    for candidate_id in candidates:
        result_path = comparison_root / "results" / f"{result_file_stem(candidate_id)}.json"
        result = load_json(result_path)
        validate_result(result, candidates[candidate_id], repo_root)
        results[candidate_id] = result

    validate_isolated_harness(results["smoltcp"], repo_root)
    scan_privacy(comparison_root)

    return {
        "candidate_count": len(candidates),
        "selected": "smoltcp",
        "selected_case_count": results["smoltcp"]["cases_passed"],
    }


def validate_candidate_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(manifest.get("schema") == 1, "candidate schema must be 1")
    require(manifest.get("candidate_limit") == 3, "candidate limit must remain 3")
    require_revision(manifest.get("comparison_base_commit"), "comparison base commit")

    safety = require_mapping(manifest, "safety")
    for key in (
        "development_machine_network_mutation",
        "real_tun_device_used",
        "remote_host_used",
        "public_socket_used",
        "candidate_setup_api_used",
    ):
        require(safety.get(key) is False, f"safety.{key} must be false")

    raw_candidates = manifest.get("candidates")
    require(isinstance(raw_candidates, list), "candidates must be a list")
    require(0 < len(raw_candidates) <= 3, "candidate count must be between 1 and 3")

    candidates: dict[str, dict[str, Any]] = {}
    for candidate in raw_candidates:
        require(isinstance(candidate, dict), "candidate must be an object")
        candidate_id = require_string(candidate, "id")
        require(candidate_id not in candidates, f"duplicate candidate {candidate_id}")
        require(candidate_id in EXPECTED_COMPONENTS, f"unexpected candidate {candidate_id}")
        require(
            candidate.get("status") == EXPECTED_STATUSES[candidate_id],
            f"{candidate_id}: status drifted",
        )
        require(candidate.get("injected_packet_device") is True, f"{candidate_id}: injected device required")
        require(
            candidate.get("host_setup_required_for_evaluated_path") is False,
            f"{candidate_id}: evaluated path must not require host setup",
        )
        require_string(candidate, "unsafe_boundary")
        require_string(candidate, "decision_reason")
        validate_components(candidate_id, candidate.get("components"))
        validate_resource_model(candidate_id, require_mapping(candidate, "resource_model"))
        candidates[candidate_id] = candidate

    require(set(candidates) == set(EXPECTED_COMPONENTS), "candidate set drifted")
    selected = [candidate for candidate in candidates.values() if candidate["status"] == "selected_for_phase_1"]
    require(len(selected) == 1 and selected[0]["id"] == "smoltcp", "exactly smoltcp must be selected")
    return candidates


def validate_components(candidate_id: str, raw_components: Any) -> None:
    require(isinstance(raw_components, list) and raw_components, f"{candidate_id}: components required")
    expected = EXPECTED_COMPONENTS[candidate_id]
    seen: set[str] = set()
    for component in raw_components:
        require(isinstance(component, dict), f"{candidate_id}: component must be an object")
        name = require_string(component, "name")
        require(name in expected, f"{candidate_id}: unexpected component {name}")
        require(name not in seen, f"{candidate_id}: duplicate component {name}")
        seen.add(name)
        version, revision, archive_hash, license_name, license_hash = expected[name]
        require(component.get("version") == version, f"{name}: version drifted")
        require(component.get("revision") == revision, f"{name}: revision drifted")
        require(component.get("registry_archive_sha256") == archive_hash, f"{name}: archive hash drifted")
        require(component.get("license") == license_name, f"{name}: license drifted")
        require(component.get("license_sha256") == license_hash, f"{name}: license hash drifted")
        require_string(component, "source_url")
        require_revision(revision, f"{name} revision")
        if archive_hash != "not_applicable":
            require_sha256(archive_hash, f"{name} archive hash")
        require_sha256(license_hash, f"{name} license hash")
    require(seen == set(expected), f"{candidate_id}: component set drifted")


def validate_resource_model(candidate_id: str, model: dict[str, Any]) -> None:
    required = {
        "flow_count",
        "accept_queue",
        "per_flow_packet_queue",
        "per_flow_data_queue",
        "device_egress_queue",
    }
    require(set(model) == required, f"{candidate_id}: resource model fields drifted")
    for key, value in model.items():
        require(isinstance(value, str) and value, f"{candidate_id}: {key} must be documented")
    if candidate_id == "ipstack_family":
        require(any(value == "unbounded" for value in model.values()), "ipstack unbounded queues disappeared without review")
    if candidate_id == "smoltcp":
        require(all("fixed" in value or "maximum" in value for value in model.values()), "smoltcp bounds must stay explicit")


def validate_result(result: dict[str, Any], candidate: dict[str, Any], repo_root: Path) -> None:
    candidate_id = candidate["id"]
    require(result.get("schema") == 2, f"{candidate_id}: result schema must be 2")
    require(result.get("candidate_id") == candidate_id, f"{candidate_id}: result id drifted")
    require_revision(result.get("comparison_base_commit"), f"{candidate_id}: comparison commit")

    case_results = result.get("case_results")
    require(isinstance(case_results, list), f"{candidate_id}: case_results must be a list")
    seen_cases: set[str] = set()
    passed = 0
    failed = 0
    for case in case_results:
        require(isinstance(case, dict), f"{candidate_id}: case result must be an object")
        case_id = require_string(case, "id")
        require(case_id not in seen_cases, f"{candidate_id}: duplicate case {case_id}")
        seen_cases.add(case_id)
        status = case.get("status")
        require(status in {"passed", "failed", "unsupported"}, f"{candidate_id}: bad case status")
        passed += int(status == "passed")
        failed += int(status == "failed")

    require(result.get("cases_total") == len(case_results), f"{candidate_id}: case total mismatch")
    require(result.get("cases_passed") == passed, f"{candidate_id}: passed count mismatch")
    require(result.get("cases_failed") == failed, f"{candidate_id}: failed count mismatch")
    require(isinstance(result.get("known_gaps"), list) and result["known_gaps"], f"{candidate_id}: known gaps required")

    if candidate_id == "smoltcp":
        require(result.get("decision") == "selected_for_phase_1", "smoltcp decision drifted")
        require(failed == 0, "selected result contains a failed case")
        require(REQUIRED_SELECTED_CASES <= seen_cases, "selected result lost a required case")
        require(all(case["status"] == "passed" for case in case_results), "selected cases must pass")
        comparison_tests = require_mapping(result, "comparison_tests")
        require(comparison_tests.get("passed") == 19, "comparison test count drifted")
        require(comparison_tests.get("failed") == 0, "comparison tests failed")
        unsafe_inventory = require_mapping(result, "unsafe_inventory")
        require(unsafe_inventory.get("harness_forbids_unsafe") is True, "harness unsafe gate drifted")
        require(
            unsafe_inventory.get("selected_smoltcp_used_unsafe_expressions") == 0,
            "selected smoltcp compiled unsafe boundary drifted",
        )
        require(unsafe_inventory.get("hosted_os_phy_compiled") is False, "hosted PHY must stay excluded")
        require(unsafe_inventory.get("ffi_boundary_compiled") is False, "FFI must stay excluded")
        transitive_unsafe = unsafe_inventory.get("transitive_crates_with_used_unsafe")
        require(
            isinstance(transitive_unsafe, list) and "heapless" in transitive_unsafe,
            "transitive unsafe inventory must remain explicit",
        )
        resource_peak = require_mapping(result, "resource_peak")
        require(resource_peak.get("active_flows") == 100, "100-flow evidence missing")
        require(resource_peak.get("queued_packets") == 4, "packet queue bound drifted")
        require(
            any(
                case.get("id") == "RES-05" and case.get("status") == "passed"
                for case in case_results
            ),
            "one-above flow admission rejection evidence missing",
        )
    else:
        require(result.get("decision") == "rejected", f"{candidate_id}: rejection decision drifted")
        require(not case_results, f"{candidate_id}: rejected preflight must not claim functional cases")
        reasons = result.get("rejection_reasons")
        require(isinstance(reasons, list) and len(reasons) >= 2, f"{candidate_id}: rejection reasons required")

    for path in result_paths(result):
        actual = repo_root / safe_relative_path(path)
        require(actual.is_file(), f"{candidate_id}: missing evidence file {path}")


def validate_isolated_harness(result: dict[str, Any], repo_root: Path) -> None:
    harness = require_mapping(result, "harness")
    manifest_rel = safe_relative_path(require_string(harness, "manifest"))
    manifest_path = repo_root / manifest_rel
    lock_path = manifest_path.with_name("Cargo.lock")
    source_path = manifest_path.parent / "src/lib.rs"

    expected_hashes = {
        manifest_path: require_string(harness, "manifest_sha256"),
        lock_path: require_string(harness, "lock_sha256"),
        source_path: require_string(harness, "source_sha256"),
    }
    for path, expected in expected_hashes.items():
        require_sha256(expected, f"{path.name} expected hash")
        require(path.is_file(), f"missing harness file {path.name}")
        require(sha256(path) == expected, f"{path.name} hash mismatch")

    with manifest_path.open("rb") as handle:
        manifest = tomllib.load(handle)
    require(manifest.get("workspace") == {}, "comparison crate must remain an isolated workspace")
    dependencies = manifest.get("dependencies")
    require(isinstance(dependencies, dict), "comparison dependencies missing")
    require(set(dependencies) == {"etherparse", "smoltcp"}, "comparison dependency set drifted")
    smoltcp = dependencies.get("smoltcp")
    require(isinstance(smoltcp, dict), "smoltcp dependency must be a table")
    require(smoltcp.get("version") == "=0.13.1", "smoltcp version must be exact")
    require(smoltcp.get("default-features") is False, "smoltcp defaults must be disabled")
    features = smoltcp.get("features")
    require(isinstance(features, list), "smoltcp features must be a list")
    require(set(features) == REQUIRED_SMOLTCP_FEATURES, "smoltcp feature set drifted")
    require(not (set(features) & FORBIDDEN_FEATURES), "hosted or link-layer feature enabled")

    with lock_path.open("rb") as handle:
        lock = tomllib.load(handle)
    packages = lock.get("package")
    require(isinstance(packages, list), "comparison lock packages missing")
    selected = [package for package in packages if package.get("name") == "smoltcp"]
    require(len(selected) == 1, "lock must contain exactly one smoltcp")
    require(selected[0].get("version") == "0.13.1", "locked smoltcp version drifted")
    require(
        selected[0].get("checksum")
        == "5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e",
        "locked smoltcp checksum drifted",
    )
    forbidden_packages = {"ipstack", "tun", "tun2proxy", "tproxy-config"}
    require(not ({package.get("name") for package in packages} & forbidden_packages), "host setup package entered harness lock")


def scan_privacy(comparison_root: Path) -> None:
    for path in comparison_root.rglob("*"):
        if not path.is_file() or "target" in path.parts:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8")
        for marker in PRIVATE_MARKERS:
            require(marker not in text, f"private marker found in {path.name}")


def result_paths(result: dict[str, Any]) -> list[str]:
    harness = result.get("harness")
    if not isinstance(harness, dict):
        return []
    manifest = harness.get("manifest")
    return [manifest] if isinstance(manifest, str) else []


def result_file_stem(candidate_id: str) -> str:
    return candidate_id.replace("_", "-")


def safe_relative_path(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    require(not path.is_absolute(), f"absolute evidence path forbidden: {raw}")
    require(all(part not in {"", ".", ".."} for part in path.parts), f"unsafe evidence path: {raw}")
    return path


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), f"{path.name} must contain an object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_mapping(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    require(isinstance(value, dict), f"{key} must be an object")
    return value


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    require(isinstance(value, str) and value, f"{key} must be a non-empty string")
    return value


def require_revision(value: Any, label: str) -> None:
    require(isinstance(value, str) and REVISION_RE.fullmatch(value) is not None, f"{label} must be a full revision")


def require_sha256(value: Any, label: str) -> None:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} must be SHA-256")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    main()
