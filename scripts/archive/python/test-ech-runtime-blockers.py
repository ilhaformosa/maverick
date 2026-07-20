#!/usr/bin/env python3
"""Unit tests for ECH runtime blocker execution-plan validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-ech-runtime-blockers.py")
SPEC = importlib.util.spec_from_file_location("check_ech_runtime_blockers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_ech_runtime_blockers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_ech_runtime_blockers)


class EchRuntimeBlockerTests(unittest.TestCase):
    def test_valid_manifest_counts_slices(self) -> None:
        with fixture_repo() as repo_root:
            result = check_ech_runtime_blockers.check_manifest(
                valid_manifest(), repo_root
            )

        self.assertEqual(result["status"], "blocker_execution_plan_ready")
        self.assertEqual(result["slice_count"], 11)
        self.assertEqual(result["completed_local_count"], 2)
        self.assertEqual(result["completed_external_count"], 1)
        self.assertEqual(result["completed_approved_host_count"], 3)
        self.assertEqual(result["operator_action_ready_count"], 0)
        self.assertEqual(result["blocked_count"], 4)

    def test_runtime_ech_enablement_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_ech_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime_ech_allowed"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_runtime_network_activity_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_network_activity_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime_network"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

        manifest = valid_manifest()
        manifest["blocker_slices"][0]["runtime_network_activity_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime network"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_local_or_dns_mutation_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["local_machine_network_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local_machine"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

        manifest = valid_manifest()
        manifest["blocker_slices"][3]["dns_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "DNS mutation"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_local_slice_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["status"] = "blocked_runtime_dependency"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local-complete"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_external_complete_slice_must_not_require_user_action(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][3]["requires_user_action"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "no user action"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_approved_host_slice_must_use_approved_linux_vm(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][2]["approved_host_candidate"] = "approved-server-vm"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "approved-linux-vm"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_edge_preflight_must_use_approved_linux_vm(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][4]["approved_host_candidate"] = "localhost"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "approved-linux-vm"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_origin_reachability_must_use_approved_linux_vm(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][5]["approved_host_candidate"] = "localhost"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "approved-linux-vm"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_cloudflare_fronted_runtime_slice_requires_no_user_action(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][6]["requires_user_action"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "no user action"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_upstream_blocked_slice_must_require_upstream_change(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][7]["requires_upstream_change"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "upstream change"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_missing_required_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"] = manifest["blocker_slices"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing ECH runtime"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_ech_runtime_blockers.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "blocker_execution_plan_ready",
        "runtime_ech_allowed": False,
        "runtime_network_activity_allowed": False,
        "local_machine_network_mutation_allowed": False,
        "requires_server_tls_backend": True,
        "requires_controlled_dns_distribution": True,
        "requires_approved_external_host": True,
        "requires_explicit_operator_dns_change": True,
        "notes": "Execution plan metadata only.",
        "blocker_slices": [
            completed_local_slice("client_tls_api_tracking"),
            completed_local_slice("fallback_policy_tests"),
            host_approved_slice("approved_integration_host"),
            completed_external_slice("controlled_dns_record_plan"),
            completed_approved_host_slice("cloudflare_edge_preflight"),
            completed_approved_host_slice("cloudflare_origin_reachability"),
            completed_approved_host_slice("cloudflare_fronted_runtime_smoke"),
            upstream_blocked_slice("server_tls_backend"),
            runtime_blocked_slice("ech_config_distribution"),
            runtime_blocked_slice("runtime_handshake_smoke"),
            runtime_blocked_slice("runtime_config_acceptance"),
        ],
    }


def completed_local_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "completed_locally"
    return item


def host_approved_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "host_approved_no_runtime"
    item["approved_host_candidate"] = "approved-linux-vm"
    return item


def completed_external_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "completed_external"
    return item


def completed_approved_host_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "completed_on_approved_host"
    item["approved_host_candidate"] = "approved-linux-vm"
    return item


def upstream_blocked_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "blocked_upstream"
    item["requires_upstream_change"] = True
    return item


def runtime_blocked_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "blocked_runtime_dependency"
    item["requires_upstream_change"] = True
    return item


def base_slice(slice_id: str) -> dict:
    return {
        "id": slice_id,
        "status": "blocked_runtime_dependency",
        "local_network_mutation_allowed": False,
        "dns_mutation_allowed": False,
        "runtime_network_activity_allowed": False,
        "approved_host_candidate": "",
        "requires_user_action": False,
        "requires_upstream_change": False,
        "evidence": ["evidence/shared.txt"],
        "notes": "Tracked.",
    }


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "shared.txt").write_text("evidence\n", encoding="utf-8")
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
