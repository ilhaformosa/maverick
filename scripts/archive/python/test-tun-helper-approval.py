#!/usr/bin/env python3
"""Unit tests for TUN helper approval manifest validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tun-helper-approval.py")
SPEC = importlib.util.spec_from_file_location("check_tun_helper_approval", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_tun_helper_approval = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_tun_helper_approval)


class TunHelperApprovalTests(unittest.TestCase):
    def test_valid_manifest_counts_slices(self) -> None:
        with fixture_repo() as repo_root:
            result = check_tun_helper_approval.check_manifest(valid_manifest(), repo_root)

        self.assertEqual(result["status"], "approval_manifest_ready")
        self.assertEqual(result["slice_count"], 7)
        self.assertEqual(result["approved_host_allowed_count"], 5)

    def test_local_system_apply_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["local_machine_system_apply_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local-machine system apply"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_missing_global_approval_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["requires_approved_external_host"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "requires_approved_external_host"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_slice_local_mutation_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"][1]["local_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local mutation"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_approved_host_requires_rollback_and_residue_check(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"][1]["rollback_required"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "rollback and residue"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

        manifest = valid_manifest()
        manifest["mutation_slices"][1]["residue_check_required"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "rollback and residue"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_blocked_slice_must_not_allow_approved_host(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"][4]["approved_host_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "blocked slice"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_missing_required_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"] = manifest["mutation_slices"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing TUN helper"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_unknown_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"].append(blocked_slice("unexpected_mutation"))
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unknown TUN helper"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["mutation_slices"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_tun_helper_approval.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "approval_manifest_ready",
        "local_machine_system_apply_allowed": False,
        "requires_explicit_operator_approval": True,
        "requires_approved_external_host": True,
        "requires_rollback_plan": True,
        "requires_residue_check": True,
        "notes": "Approval metadata only.",
        "mutation_slices": [
            blocked_slice("local_machine_apply"),
            approved_slice("temporary_tun_device"),
            approved_slice("documentation_prefix_route"),
            approved_slice("namespace_scoped_dns"),
            blocked_slice("global_dns_policy"),
            approved_slice("service_manager_integration"),
            approved_slice("leak_coexistence_testing"),
        ],
    }


def approved_slice(slice_id: str) -> dict:
    return {
        "id": slice_id,
        "status": "smoked_on_approved_vm",
        "local_allowed": False,
        "approved_host_allowed": True,
        "rollback_required": True,
        "residue_check_required": True,
        "evidence": ["evidence/shared.txt"],
        "notes": "Approved-host only.",
    }


def blocked_slice(slice_id: str) -> dict:
    return {
        "id": slice_id,
        "status": "blocked",
        "local_allowed": False,
        "approved_host_allowed": False,
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
