#!/usr/bin/env python3
"""Unit tests for GUI/tray runtime blocker metadata validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-gui-runtime-blockers.py")
SPEC = importlib.util.spec_from_file_location("check_gui_runtime_blockers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_gui_runtime_blockers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_gui_runtime_blockers)


class GuiRuntimeBlockerTests(unittest.TestCase):
    def test_valid_manifest_counts_slices(self) -> None:
        with fixture_repo() as repo_root:
            result = check_gui_runtime_blockers.check_manifest(valid_manifest(), repo_root)

        self.assertEqual(result["status"], "blocker_execution_plan_ready")
        self.assertEqual(result["slice_count"], 11)
        self.assertEqual(result["completed_local_count"], 9)
        self.assertEqual(result["blocked_product_count"], 0)
        self.assertEqual(result["blocked_release_count"], 2)

    def test_gui_runtime_allowed_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["gui_runtime_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "gui_runtime_allowed"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_system_mutation_flags_are_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["system_proxy_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "system_proxy"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

        manifest = valid_manifest()
        manifest["system_dns_route_firewall_mutation_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "system_dns"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_completed_slice_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][3]["status"] = "blocked_product_runtime"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "local-complete"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_release_gate_status_drift_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][7]["status"] = "completed_locally"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "release-gate"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_missing_required_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"] = manifest["blocker_slices"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing GUI runtime"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_runtime_allowed_slice_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["runtime_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime_allowed"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_unsupported_claim_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["notes"] = "Production ready."
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsupported GUI claim"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["blocker_slices"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_gui_runtime_blockers.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "blocker_execution_plan_ready",
        "gui_runtime_allowed": False,
        "local_machine_network_mutation_allowed": False,
        "system_proxy_mutation_allowed": False,
        "system_dns_route_firewall_mutation_allowed": False,
        "notes": "Metadata only.",
        "blocker_slices": [
            completed_local_slice("core_diagnostics"),
            completed_local_slice("sdk_runtime_baseline"),
            completed_local_slice("debug_redaction_tests"),
            completed_local_slice("ui_scope_decision"),
            completed_local_slice("platform_target_decision"),
            completed_local_slice("secure_profile_storage"),
            completed_local_slice("service_lifecycle_integration"),
            release_blocked_slice("signing_notarization"),
            completed_local_slice("tun_safety_integration"),
            completed_local_slice("ui_smoke_tests"),
            release_blocked_slice("release_packaging"),
        ],
    }


def completed_local_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "completed_locally"
    return item


def product_blocked_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "blocked_product_runtime"
    return item


def release_blocked_slice(slice_id: str) -> dict:
    item = base_slice(slice_id)
    item["status"] = "blocked_release_gate"
    return item


def base_slice(slice_id: str) -> dict:
    return {
        "id": slice_id,
        "status": "blocked_product_runtime",
        "runtime_allowed": False,
        "requires_user_action": False,
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
