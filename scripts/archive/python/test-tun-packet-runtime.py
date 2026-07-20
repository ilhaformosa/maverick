#!/usr/bin/env python3
"""Unit tests for the Phase 1 TUN packet runtime checker."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tun-packet-runtime.py")
SPEC = importlib.util.spec_from_file_location("check_tun_packet_runtime", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TunPacketRuntimeTests(unittest.TestCase):
    def test_repository_boundary_is_valid(self) -> None:
        result = runtime.check_repository(REPO_ROOT)
        self.assertEqual(result["engine"], "smoltcp-0.13.1")
        self.assertEqual(result["packet_tests"], 21)
        self.assertEqual(result["connector_tests"], 2)
        self.assertEqual(result["real_tests"], 2)

    def test_smoltcp_feature_drift_is_rejected(self) -> None:
        manifest = runtime.load_toml(REPO_ROOT / "Cargo.toml")
        manifest = copy.deepcopy(manifest)
        manifest["workspace"]["dependencies"]["smoltcp"]["features"].append(
            "phy-tuntap_interface"
        )
        with self.assertRaisesRegex(AssertionError, "feature set drifted"):
            runtime.validate_smoltcp_dependency(manifest)

    def test_smoltcp_lock_checksum_drift_is_rejected(self) -> None:
        lock = runtime.load_toml(REPO_ROOT / "Cargo.lock")
        lock = copy.deepcopy(lock)
        package = next(item for item in lock["package"] if item["name"] == "smoltcp")
        package["checksum"] = "0" * 64
        with self.assertRaisesRegex(AssertionError, "checksum drifted"):
            runtime.validate_smoltcp_lock(lock)

    def test_host_network_api_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "host-network API"):
            runtime.validate_runtime_source("tokio::process::Command::new(\"ip\")")

    def test_missing_required_test_is_rejected(self) -> None:
        source = "#[tokio::test]\nasync fn only_one() {}"
        self.assertNotEqual(runtime.async_test_names(source), runtime.REQUIRED_RUNTIME_TESTS)

    def test_private_marker_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "private marker"):
            runtime.scan_private_markers("/Users/example/private")


if __name__ == "__main__":
    unittest.main()
