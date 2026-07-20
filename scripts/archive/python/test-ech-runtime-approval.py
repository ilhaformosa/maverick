#!/usr/bin/env python3
"""Unit tests for ECH runtime approval manifest validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-ech-runtime-approval.py")
SPEC = importlib.util.spec_from_file_location("check_ech_runtime_approval", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_ech_runtime_approval = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_ech_runtime_approval)


class EchRuntimeApprovalTests(unittest.TestCase):
    def test_valid_manifest_counts_gates(self) -> None:
        with fixture_repo() as repo_root:
            result = check_ech_runtime_approval.check_manifest(valid_manifest(), repo_root)

        self.assertEqual(result["status"], "approval_manifest_ready")
        self.assertEqual(result["gate_count"], 8)
        self.assertEqual(result["tracked_local_count"], 1)
        self.assertEqual(result["completed_count"], 3)
        self.assertEqual(result["blocked_count"], 2)
        self.assertEqual(result["runtime_allowed_count"], 0)

    def test_runtime_ech_allowed_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_ech_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime ECH"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_missing_global_gate_requirement_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["requires_controlled_dns_distribution"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(
                AssertionError, "requires_controlled_dns_distribution"
            ):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_local_api_gate_must_remain_tracked_locally(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["status"] = "blocked"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "tracked_locally"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_upstream_gate_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][1]["status"] = "blocked"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "upstream-blocked"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_completed_gate_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][5]["status"] = "blocked"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local-complete"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_runtime_allowed_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][1]["runtime_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "must not allow runtime"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_network_activity_allowed_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][2]["network_activity_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "network activity"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_missing_required_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"] = manifest["runtime_gates"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing ECH runtime"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)

    def test_review_claim_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["notes"] = "Production ready."
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsupported review claim"):
                check_ech_runtime_approval.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "approval_manifest_ready",
        "runtime_ech_allowed": False,
        "requires_server_tls_backend": True,
        "requires_controlled_ech_config_source": True,
        "requires_controlled_dns_distribution": True,
        "requires_approved_integration_host": True,
        "requires_fallback_policy_tests": True,
        "requires_runtime_config_gate": True,
        "notes": "Approval metadata only.",
        "runtime_gates": [
            tracked_gate("client_tls_api_tracking"),
            upstream_blocked_gate("server_tls_backend"),
            native_dependency_gate("ech_config_distribution"),
            completed_external_gate("controlled_dns_records"),
            host_approved_gate("approved_integration_host"),
            completed_local_gate("fallback_policy_tests"),
            completed_approved_host_gate("cloudflare_fronted_runtime_smoke"),
            deferred_runtime_gate("runtime_config_acceptance"),
        ],
    }


def tracked_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "tracked_locally"
    return gate


def completed_local_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "completed_locally"
    return gate


def completed_external_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "completed_external"
    return gate


def completed_approved_host_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "completed_on_approved_host"
    return gate


def host_approved_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "host_approved_no_runtime"
    return gate


def upstream_blocked_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "blocked_upstream"
    return gate


def native_dependency_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "blocked_native_dependency"
    return gate


def deferred_runtime_gate(gate_id: str) -> dict:
    gate = blocked_gate(gate_id)
    gate["status"] = "deferred_runtime_gate"
    return gate


def blocked_gate(gate_id: str) -> dict:
    return {
        "id": gate_id,
        "status": "blocked",
        "runtime_allowed": False,
        "network_activity_allowed": False,
        "evidence": ["evidence/shared.txt"],
        "notes": "Blocked.",
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
