#!/usr/bin/env python3
"""Unit tests for Noise runtime approval manifest validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-noise-runtime-approval.py")
SPEC = importlib.util.spec_from_file_location("check_noise_runtime_approval", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_noise_runtime_approval = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_noise_runtime_approval)


class NoiseRuntimeApprovalTests(unittest.TestCase):
    def test_valid_manifest_counts_gates(self) -> None:
        with fixture_repo() as repo_root:
            result = check_noise_runtime_approval.check_manifest(valid_manifest(), repo_root)

        self.assertEqual(result["status"], "approval_manifest_ready")
        self.assertEqual(result["gate_count"], 7)
        self.assertEqual(result["runtime_allowed_count"], 0)

    def test_runtime_noise_allowed_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_noise_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "runtime Noise"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_missing_global_gate_requirement_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["requires_community_crypto_review_before_security_claims"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(
                AssertionError,
                "requires_community_crypto_review_before_security_claims",
            ):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_evidence_gate_must_remain_completed_non_runtime(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["status"] = "planning_only"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "completed_non_runtime"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_runtime_harness_gate_must_remain_completed(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][4]["status"] = "completed_non_runtime"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "completed_runtime_harness"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_product_gate_must_remain_deferred(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][5]["status"] = "blocked"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "deferred_product_gate"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_runtime_allowed_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][1]["runtime_allowed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "must not allow runtime"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_missing_required_gate_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"] = manifest["runtime_gates"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing Noise runtime"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)

    def test_review_claim_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_gates"][0]["notes"] = "Production ready."
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsupported review claim"):
                check_noise_runtime_approval.check_manifest(manifest, repo_root)


def valid_manifest() -> dict:
    return {
        "version": 1,
        "status": "approval_manifest_ready",
        "runtime_noise_allowed": False,
        "requires_candidate_implementation": True,
        "requires_implementation_vectors": True,
        "requires_transcript_prologue_tests": True,
        "requires_downgrade_tests": True,
        "requires_runtime_config_gate": True,
        "requires_formal_human_crypto_review": False,
        "requires_community_crypto_review_before_security_claims": True,
        "notes": "Approval metadata only.",
        "runtime_gates": [
            gate("implementation_selection", "completed_non_runtime"),
            gate("implementation_backed_vectors", "completed_non_runtime"),
            gate("transcript_prologue_tests", "completed_non_runtime"),
            gate("downgrade_tests", "completed_non_runtime"),
            gate("runtime_session_harness", "completed_runtime_harness"),
            gate("runtime_config_acceptance", "deferred_product_gate"),
            gate("community_crypto_review", "deferred_claim_gate"),
        ],
    }


def gate(gate_id: str, status: str) -> dict:
    return {
        "id": gate_id,
        "status": status,
        "runtime_allowed": False,
        "evidence": ["evidence/shared.txt"],
        "notes": "Evidence recorded without runtime enablement.",
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
