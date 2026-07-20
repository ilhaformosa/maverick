#!/usr/bin/env python3
"""Validate the experimental Phase 1 TUN packet runtime boundary."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path
from typing import Any


EXPECTED_SMOLTCP_FEATURES = {
    "std",
    "assembler-max-segment-count-4",
    "fragmentation-buffer-size-1500",
    "medium-ip",
    "proto-ipv4",
    "proto-ipv4-fragmentation",
    "proto-ipv6",
    "proto-ipv6-fragmentation",
    "reassembly-buffer-count-1",
    "reassembly-buffer-size-1500",
    "socket-tcp",
    "socket-tcp-reno",
    "socket-udp",
}

EXPECTED_SMOLTCP_CHECKSUM = (
    "5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e"
)

REQUIRED_RUNTIME_TESTS = {
    "ipv4_tcp_round_trip_and_clean_idempotent_shutdown",
    "ipv6_tcp_round_trip",
    "dns_and_generic_udp_round_trip_without_cross_flow_mix",
    "flow_limit_and_malformed_burst_remain_bounded",
    "disabled_ipv4_rejects_non_initial_fragments_before_engine_admission",
    "shutdown_during_stalled_connect_is_forced_but_leak_free",
    "remote_open_refusal_emits_reset_and_releases_flow",
    "stalled_tcp_reader_propagates_fixed_backpressure_and_cancels",
    "local_half_close_delivers_response_and_fin",
    "dns_and_udp_admission_limits_reject_excess_without_leaks",
    "oversized_dns_and_udp_responses_are_rejected_before_queueing",
    "dns_connector_failure_is_counted_without_shutdown_noise",
    "inconsistent_connector_resource_snapshot_rejects_startup",
    "packet_read_error_and_reader_panic_fail_coarsely_and_clean_up",
    "packet_write_error_fails_coarsely_and_clean_up",
    "packet_eof_stops_cleanly_before_explicit_shutdown",
    "packet_eof_drains_packets_already_accepted_by_the_reader",
    "flow_task_panic_fails_runtime_and_cleans_up",
}

REQUIRED_SYNC_RUNTIME_TESTS = {"startup_without_tokio_runtime_returns_an_error"}

REQUIRED_CONNECTOR_TESTS = {
    "relay_failure_becomes_connection_reset",
    "clean_relay_close_remains_eof",
}

REQUIRED_REAL_TESTS = {
    "packet_runtime_reuses_real_auth_h2_tcp_dns_and_udp_paths",
    "packet_runtime_requires_explicit_runtime_gate",
}

FORBIDDEN_RUNTIME_TOKENS = {
    "std::process::Command",
    "tokio::process::Command",
    "/dev/net/tun",
    "TUNSETIFF",
    "SIOCSIF",
}

PRIVATE_MARKERS = ("/Users/", "\\Users\\", ".ssh/", "known_hosts", "PRIVATE_LAUNCH")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    args = parser.parse_args()
    result = check_repository(args.repo_root.resolve())
    print(
        "TUN packet runtime OK: "
        f"engine={result['engine']}, "
        f"{result['packet_tests']} packet tests, "
        f"{result['connector_tests']} connector tests, "
        f"{result['real_tests']} real-loopback tests"
    )


def check_repository(repo_root: Path) -> dict[str, int | str]:
    workspace = load_toml(repo_root / "Cargo.toml")
    validate_smoltcp_dependency(workspace)
    validate_smoltcp_lock(load_toml(repo_root / "Cargo.lock"))
    members = workspace.get("workspace", {}).get("members", [])
    require("crates/maverick-tun" in members, "maverick-tun is not a workspace member")

    tun_manifest = load_toml(repo_root / "crates/maverick-tun/Cargo.toml")
    require(tun_manifest.get("package", {}).get("name") == "maverick-tun", "bad TUN package name")
    require(
        tun_manifest.get("dependencies", {}).get("smoltcp", {}).get("workspace") is True,
        "maverick-tun must use the pinned workspace smoltcp dependency",
    )

    runtime_sources = read_tree(repo_root / "crates/maverick-tun/src", "*.rs")
    validate_runtime_source(runtime_sources)
    require_tokens(
        runtime_sources,
        {
            "#![forbid(unsafe_code)]",
            'pub const ENGINE_NAME: &str = "smoltcp"',
            'pub const ENGINE_VERSION: &str = "0.13.1"',
            'const ENGINE_REASSEMBLY_BUFFER_COUNT: usize = 1',
            'const ENGINE_REASSEMBLY_BUFFER_BYTES: usize = 1500',
            '"smoltcp build-time buffer configuration drifted"',
            "pub struct PacketIo",
            "pub trait FlowConnector",
            "pub struct FlowConnectorSnapshot",
            "pub struct PacketRuntimeConfig",
            "pub struct PacketRuntimeSnapshot",
            "pub tcp_flows_failed: u64",
            "pub udp_associations_failed: u64",
            "pub dns_queries_failed: u64",
            "pub fn start_packet_runtime",
        },
        "maverick-tun API",
    )

    client_manifest = load_toml(repo_root / "crates/maverick-client/Cargo.toml")
    client_feature = set(client_manifest.get("features", {}).get("tun-runtime", []))
    require(
        client_feature == {"dep:maverick-tun", "dep:tokio-util"},
        "client tun-runtime feature drifted",
    )
    sdk_manifest = load_toml(repo_root / "crates/maverick-sdk/Cargo.toml")
    sdk_feature = set(sdk_manifest.get("features", {}).get("tun-runtime", []))
    require(
        sdk_feature == {"maverick-client/tun-runtime", "dep:maverick-tun"},
        "SDK tun-runtime feature drifted",
    )

    core_config = read(repo_root / "crates/maverick-core/src/config.rs")
    require_tokens(
        core_config,
        {
            "pub experimental_tun: bool",
            '"advanced.experimental_tun is not allowed in stable mode"',
        },
        "runtime config gate",
    )
    registry = read(repo_root / "crates/maverick-core/src/experimental.rs")
    descriptor_marker = "track: ExperimentalTrackId::ProductTunRuntime"
    require(descriptor_marker in registry, "ProductTunRuntime descriptor is missing")
    product_descriptor = registry.split(descriptor_marker, 1)[1].split("},", 1)[0]
    require_tokens(
        product_descriptor,
        {
            'build_gate: Some("tun-runtime")',
            'runtime_gate: Some("advanced.experimental_tun")',
            "requires_external_test_host: true",
        },
        "experimental registry",
    )
    client_source = read(repo_root / "crates/maverick-client/src/lib.rs")
    require_tokens(
        client_source,
        {
            "pub async fn start_tun_runtime",
            '"advanced.experimental_tun must be enabled"',
            '"advanced.experimental_tun requires the tun-runtime build feature"',
        },
        "client gates",
    )
    sdk_source = read(repo_root / "crates/maverick-sdk/src/lib.rs")
    require_tokens(
        sdk_source,
        {"pub async fn start_tun_runtime", "pub fn tun_runtime_snapshot"},
        "SDK packet boundary",
    )

    runtime_tests_source = read(repo_root / "crates/maverick-tun/tests/runtime.rs")
    runtime_tests = async_test_names(runtime_tests_source)
    require(runtime_tests == REQUIRED_RUNTIME_TESTS, "Phase 1 runtime test surface drifted")
    sync_runtime_tests = sync_test_names(runtime_tests_source)
    require(
        sync_runtime_tests == REQUIRED_SYNC_RUNTIME_TESTS,
        "Phase 1 sync runtime test surface drifted",
    )
    unit_source = read(repo_root / "crates/maverick-tun/src/runtime.rs")
    require(unit_source.count("#[test]") == 3, "Phase 1 unit test count drifted")
    connector_source = read(repo_root / "crates/maverick-client/src/tun_runtime.rs")
    connector_tests = async_test_names(connector_source)
    require(
        connector_tests == REQUIRED_CONNECTOR_TESTS,
        "Maverick connector test surface drifted",
    )
    real_source = read(repo_root / "crates/maverick-tests/tests/tun_packet_runtime.rs")
    real_tests = async_test_names(real_source)
    require(real_tests == REQUIRED_REAL_TESTS, "real Maverick loopback test surface drifted")

    docs = "\n".join(
        read(repo_root / path)
        for path in (
            "docs/TUN_PACKET_ADAPTER_CONTRACT.md",
            "docs/TUN_SYNTHETIC_TEST_MATRIX.md",
            "docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md",
            "docs/TUN_PHASE2_EXECUTION_GATE.md",
            "docs/PLAN_POST_V1.md",
        )
    )
    require_tokens(
        docs,
        {
            "Phase 1 complete",
            "Phase 2",
            "explicit operator approval",
            "real TUN",
            "no product-readiness claim",
        },
        "Phase 1 documentation",
    )

    harness = read(repo_root / "scripts/local-harness.sh")
    require_tokens(
        harness,
        {
            "cargo_bin\" test -p maverick-client --features tun-runtime --lib",
            "cargo_bin\" test -p maverick-tests --features tun-runtime --test tun_packet_runtime",
            "scripts/test-tun-packet-runtime.py",
            "scripts/check-tun-packet-runtime.py",
        },
        "local harness",
    )
    scan_private_markers(runtime_sources + client_source + sdk_source + docs)

    return {
        "engine": "smoltcp-0.13.1",
        "packet_tests": len(runtime_tests) + len(sync_runtime_tests) + 2,
        "connector_tests": len(connector_tests),
        "real_tests": len(real_tests),
    }


def validate_smoltcp_dependency(workspace: dict[str, Any]) -> None:
    dependency = workspace.get("workspace", {}).get("dependencies", {}).get("smoltcp")
    require(isinstance(dependency, dict), "workspace smoltcp dependency is missing")
    require(dependency.get("version") == "=0.13.1", "smoltcp version must stay exact")
    require(dependency.get("default-features") is False, "smoltcp defaults must stay disabled")
    require(
        set(dependency.get("features", [])) == EXPECTED_SMOLTCP_FEATURES,
        "smoltcp selected feature set drifted",
    )


def validate_smoltcp_lock(lock: dict[str, Any]) -> None:
    packages = lock.get("package", [])
    require(isinstance(packages, list), "Cargo.lock package list is missing")
    selected = [package for package in packages if package.get("name") == "smoltcp"]
    require(len(selected) == 1, "Cargo.lock must contain exactly one smoltcp package")
    package = selected[0]
    require(package.get("version") == "0.13.1", "locked smoltcp version drifted")
    require(
        package.get("source") == "registry+https://github.com/rust-lang/crates.io-index",
        "locked smoltcp source drifted",
    )
    require(
        package.get("checksum") == EXPECTED_SMOLTCP_CHECKSUM,
        "locked smoltcp checksum drifted",
    )


def validate_runtime_source(source: str) -> None:
    require("unsafe {" not in source, "first-party TUN runtime contains unsafe code")
    for token in FORBIDDEN_RUNTIME_TOKENS:
        require(token not in source, f"TUN runtime contains host-network API token {token!r}")


def async_test_names(source: str) -> set[str]:
    return set(
        re.findall(r"#\[tokio::test\]\s*async fn ([a-z0-9_]+)\s*\(", source)
    )


def sync_test_names(source: str) -> set[str]:
    return set(re.findall(r"#\[test\]\s*fn ([a-z0-9_]+)\s*\(", source))


def require_tokens(source: str, tokens: set[str], scope: str) -> None:
    missing = sorted(token for token in tokens if token not in source)
    require(not missing, f"{scope} is missing: {', '.join(missing)}")


def scan_private_markers(source: str) -> None:
    for marker in PRIVATE_MARKERS:
        require(marker not in source, f"public TUN material contains private marker {marker!r}")


def read_tree(root: Path, pattern: str) -> str:
    paths = sorted(root.rglob(pattern))
    require(bool(paths), f"no files found under {root}")
    return "\n".join(read(path) for path in paths)


def read(path: Path) -> str:
    require(path.is_file(), f"missing file: {path}")
    return path.read_text(encoding="utf-8")


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    main()
