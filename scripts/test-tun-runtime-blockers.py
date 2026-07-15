#!/usr/bin/env python3
"""Unit tests for TUN runtime blocker execution-plan validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tun-runtime-blockers.py")
SPEC = importlib.util.spec_from_file_location("check_tun_runtime_blockers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_tun_runtime_blockers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_tun_runtime_blockers)


class TunRuntimeBlockerTests(unittest.TestCase):
    def test_valid_manifest_counts_slices(self) -> None:
        with fixture_repo() as repo_root:
            result = check_tun_runtime_blockers.check_manifest(
                valid_manifest(), repo_root
            )

        self.assertEqual(result["status"], "blocker_execution_plan_ready")
        self.assertEqual(result["slice_count"], 8)
        self.assertEqual(result["completed_count"], 8)
        self.assertEqual(result["approval_pending_count"], 0)

    def test_local_machine_network_mutation_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["local_machine_network_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local_machine"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_default_route_or_global_dns_enablement_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["default_route_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "default_route"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

        manifest = valid_manifest()
        manifest["global_dns_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "global_dns"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_slice_must_not_allow_remote_mutation(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][1]["remote_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "remote mutation"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_slice_must_not_require_new_confirmation(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][1]["requires_new_operator_confirmation"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "new confirmation"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_phase_b_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][1]["status"] = "approval_pending"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "completed slice"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_full_helper_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][6]["status"] = "approval_pending"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "completed slice"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_missing_required_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"] = manifest["blocker_slices"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing TUN runtime"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_tun_runtime_blockers.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "blocker_execution_plan_ready",
        "local_machine_network_mutation_allowed": False,
        "default_route_mutation_allowed": False,
        "global_dns_mutation_allowed": False,
        "requires_explicit_operator_confirmation": True,
        "requires_approved_external_host": True,
        "requires_rollback_plan": True,
        "requires_residue_check": True,
        "notes": "Execution plan metadata only.",
        "blocker_slices": [
            completed_slice("phase_a_helper_smoke"),
            completed_slice("phase_b_namespace_runtime_smoke"),
            completed_slice("production_route_policy"),
            completed_slice("default_route_policy"),
            completed_slice("global_dns_policy"),
            completed_slice("service_manager_integration"),
            completed_slice("full_privileged_helper_runtime_integration"),
            completed_slice("leak_coexistence_testing"),
        ],
    }


def completed_slice(slice_id: str) -> dict:
    item = blocked_slice(slice_id)
    item["status"] = "completed_on_approved_vm"
    item["approved_host_candidate"] = "approved-linux-vm"
    item["requires_new_operator_confirmation"] = False
    return item

def blocked_slice(slice_id: str) -> dict:
    return {
        "id": slice_id,
        "status": "blocked",
        "local_allowed": False,
        "remote_mutation_allowed": False,
        "approved_host_candidate": "",
        "requires_new_operator_confirmation": True,
        "rollback_required": True,
        "residue_check_required": True,
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
