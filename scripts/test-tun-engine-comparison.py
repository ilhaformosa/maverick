#!/usr/bin/env python3
"""Unit tests for TUN engine comparison validation."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tun-engine-comparison.py")
SPEC = importlib.util.spec_from_file_location("check_tun_engine_comparison", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)

REPO_ROOT = Path(__file__).resolve().parent.parent
CANDIDATES_PATH = REPO_ROOT / "spikes/tun-engine-comparison/candidates.json"
SMOLTCP_RESULT_PATH = REPO_ROOT / "spikes/tun-engine-comparison/results/smoltcp.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class TunEngineComparisonTests(unittest.TestCase):
    def test_repository_package_is_valid(self) -> None:
        summary = comparison.check_repository(REPO_ROOT)
        self.assertEqual(summary["candidate_count"], 3)
        self.assertEqual(summary["selected"], "smoltcp")
        self.assertEqual(summary["selected_case_count"], 26)

    def test_fourth_candidate_is_rejected(self) -> None:
        manifest = load(CANDIDATES_PATH)
        manifest["candidates"].append(copy.deepcopy(manifest["candidates"][0]))
        with self.assertRaisesRegex(AssertionError, "candidate count"):
            comparison.validate_candidate_manifest(manifest)

    def test_selected_candidate_drift_is_rejected(self) -> None:
        manifest = load(CANDIDATES_PATH)
        manifest["candidates"][0]["status"] = "selected_for_phase_1"
        with self.assertRaisesRegex(AssertionError, "status drifted"):
            comparison.validate_candidate_manifest(manifest)

    def test_unbounded_smoltcp_resource_is_rejected(self) -> None:
        manifest = load(CANDIDATES_PATH)
        selected = next(item for item in manifest["candidates"] if item["id"] == "smoltcp")
        selected["resource_model"]["device_egress_queue"] = "unbounded"
        with self.assertRaisesRegex(AssertionError, "bounds must stay explicit"):
            comparison.validate_candidate_manifest(manifest)

    def test_result_count_drift_is_rejected(self) -> None:
        manifest = load(CANDIDATES_PATH)
        candidates = comparison.validate_candidate_manifest(manifest)
        result = load(SMOLTCP_RESULT_PATH)
        result["cases_passed"] -= 1
        with self.assertRaisesRegex(AssertionError, "passed count mismatch"):
            comparison.validate_result(result, candidates["smoltcp"], REPO_ROOT)

    def test_missing_required_case_is_rejected(self) -> None:
        manifest = load(CANDIDATES_PATH)
        candidates = comparison.validate_candidate_manifest(manifest)
        result = load(SMOLTCP_RESULT_PATH)
        result["case_results"] = [
            item for item in result["case_results"] if item["id"] != "TCP-10"
        ]
        result["cases_total"] -= 1
        result["cases_passed"] -= 1
        with self.assertRaisesRegex(AssertionError, "lost a required case"):
            comparison.validate_result(result, candidates["smoltcp"], REPO_ROOT)

    def test_res_05_cannot_be_marked_unsupported(self) -> None:
        manifest = load(CANDIDATES_PATH)
        candidates = comparison.validate_candidate_manifest(manifest)
        result = load(SMOLTCP_RESULT_PATH)
        case = next(item for item in result["case_results"] if item["id"] == "RES-05")
        case["status"] = "unsupported"
        result["cases_passed"] -= 1
        with self.assertRaisesRegex(AssertionError, "selected cases must pass"):
            comparison.validate_result(result, candidates["smoltcp"], REPO_ROOT)

    def test_absolute_evidence_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "absolute evidence path"):
            comparison.safe_relative_path("/private/evidence.json")


if __name__ == "__main__":
    unittest.main()
