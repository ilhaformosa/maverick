#!/usr/bin/env python3
"""Unit tests for the production-readiness ledger validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-production-readiness.py")
SPEC = importlib.util.spec_from_file_location("check_production_readiness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class ProductionReadinessTests(unittest.TestCase):
    def test_current_blocked_ledger_is_valid(self) -> None:
        with fixture_repo() as (root, ledger):
            result = checker.check_ledger(ledger, root)
        self.assertEqual(result["candidate_status"], "not_frozen")
        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["complete_dimensions"], 0)

    def test_unfrozen_candidate_rejects_hashes(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["candidate"]["maverick_release_commit"] = "a" * 40
            with self.assertRaisesRegex(AssertionError, "unfrozen candidate"):
                checker.check_ledger(ledger, root)

    def test_missing_phase_input_cannot_carry_evidence(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["phase_inputs"]["phase_3a"]["accepted_manifest_sha256"] = "b" * 64
            with self.assertRaisesRegex(AssertionError, "missing input"):
                checker.check_ledger(ledger, root)

    def test_missing_non_claim_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["scope"]["non_claims"].pop()
            with self.assertRaisesRegex(AssertionError, "canonical set"):
                checker.check_ledger(ledger, root)

    def test_go_without_complete_dimensions_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["decision"] = {
                "status": "GO",
                "kind": "final",
                "decided_at": "2026-07-16T00:00:00Z",
                "approver": "maintainer",
                "reason_codes": [],
            }
            with self.assertRaisesRegex(AssertionError, "GO requires production_ready"):
                checker.check_ledger(ledger, root)

    def test_stable_gate_cannot_skip_dependencies(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["release_gates"]["v1.2.0"] = "pass"
            with self.assertRaisesRegex(AssertionError, "prerequisite dimensions"):
                checker.check_ledger(ledger, root)

    def test_release_gates_cannot_skip_an_earlier_stage(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["release_gates"]["v1.2.0-beta.1"] = "pass"
            with self.assertRaisesRegex(AssertionError, "prerequisite|alpha, beta"):
                checker.check_ledger(ledger, root)

    def test_unsafe_repo_path_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["scope"]["docs"] = ["../private/evidence.md"]
            with self.assertRaisesRegex(AssertionError, "unsafe path"):
                checker.check_ledger(ledger, root)

    def test_complete_state_transition_is_valid(self) -> None:
        with fixture_repo() as (root, ledger):
            candidate = ledger["candidate"]
            evidence_path = ledger["scope"]["docs"][0]
            candidate.update(
                {
                    "status": "frozen",
                    "maverick_release_commit": "a" * 40,
                    "maverick_sdk_commit": "b" * 40,
                    "reference_client_commit": "c" * 40,
                    "reference_client_sdk_pin": "b" * 40,
                    "sdk_pin_verified": True,
                    "sdk_pin_evidence_path": evidence_path,
                    "reference_package_sha256": "d" * 64,
                }
            )
            candidate["versions"]["software"] = "1.2.0"
            candidate["versions"]["reference_package"] = "1.2.0-1"
            for phase in ("phase_3a", "phase_3b"):
                ledger["phase_inputs"][phase] = {
                    "status": "accepted",
                    "accepted_manifest_sha256": "e" * 64,
                    "public_summary_paths": [evidence_path],
                }
            for dimension in checker.DIMENSIONS:
                ledger["dimensions"][dimension] = {
                    "status": "complete",
                    "reason": None,
                    "evidence_paths": [evidence_path],
                }
            ledger["audit"] = {
                "status": "complete",
                "independent": True,
                "reviewer": "Independent reviewer",
                "report_sha256": "f" * 64,
                "remediation_complete": True,
            }
            ledger["current_claim_state"] = {
                "formal_audit": "completed",
                "production_readiness": "approved",
            }
            ledger["release_gates"] = {release: "pass" for release in checker.RELEASES}
            ledger["decision"] = {
                "status": "GO",
                "kind": "final",
                "decided_at": "2026-07-16T00:00:00Z",
                "approver": "maintainer",
                "reason_codes": [],
            }

            result = checker.check_ledger(ledger, root)

        self.assertEqual(result["candidate_status"], "frozen")
        self.assertEqual(result["decision"], "GO")
        self.assertEqual(result["complete_dimensions"], 5)

    def test_completed_audit_can_remain_production_no_go(self) -> None:
        with fixture_repo() as (root, ledger):
            evidence_path = ledger["scope"]["docs"][0]
            candidate = ledger["candidate"]
            candidate.update(
                {
                    "status": "frozen",
                    "maverick_release_commit": "a" * 40,
                    "maverick_sdk_commit": "b" * 40,
                    "reference_client_commit": "c" * 40,
                    "reference_client_sdk_pin": "b" * 40,
                    "sdk_pin_verified": True,
                    "sdk_pin_evidence_path": evidence_path,
                    "reference_package_sha256": "d" * 64,
                }
            )
            candidate["versions"]["software"] = "1.2.0-alpha.1"
            candidate["versions"]["reference_package"] = "1.2.0~alpha.1-1"
            ledger["phase_inputs"]["phase_3b"] = {
                "status": "accepted",
                "accepted_manifest_sha256": "e" * 64,
                "public_summary_paths": [evidence_path],
            }
            for dimension in ("code_complete", "audit_complete"):
                ledger["dimensions"][dimension] = {
                    "status": "complete",
                    "reason": None,
                    "evidence_paths": [evidence_path],
                }
            ledger["audit"] = {
                "status": "complete",
                "independent": True,
                "reviewer": "Independent reviewer",
                "report_sha256": "f" * 64,
                "remediation_complete": False,
            }
            ledger["current_claim_state"]["formal_audit"] = "completed"
            ledger["release_gates"]["v1.2.0-alpha.1"] = "pass"

            result = checker.check_ledger(ledger, root)

        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["complete_dimensions"], 2)

    def test_sdk_pin_must_match_frozen_sdk_commit(self) -> None:
        with fixture_repo() as (root, ledger):
            candidate = ledger["candidate"]
            candidate.update(
                {
                    "status": "frozen",
                    "maverick_release_commit": "a" * 40,
                    "maverick_sdk_commit": "b" * 40,
                    "reference_client_commit": "c" * 40,
                    "reference_client_sdk_pin": "d" * 40,
                    "sdk_pin_verified": True,
                    "sdk_pin_evidence_path": ledger["scope"]["docs"][0],
                    "reference_package_sha256": "e" * 64,
                }
            )
            candidate["versions"]["software"] = "1.2.0-alpha.1"
            candidate["versions"]["reference_package"] = "1.2.0-1"
            with self.assertRaisesRegex(AssertionError, "SDK pin must match"):
                checker.check_ledger(ledger, root)

    def test_release_candidate_request_binds_release_commit_and_stage(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "1.2.0-alpha.1")
            ledger["dimensions"]["code_complete"] = complete_dimension(ledger)
            checker.check_ledger(ledger, root)

            checker.check_release_candidate_request(
                ledger, "a" * 40, "v1.2.0-alpha.1"
            )

            with self.assertRaisesRegex(AssertionError, "match maverick_release_commit"):
                checker.check_release_candidate_request(
                    ledger, "f" * 40, "v1.2.0-alpha.1"
                )

    def test_release_candidate_request_requires_earlier_stage(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "1.2.0-beta.1", accept_phase_3a=True)
            ledger["dimensions"]["code_complete"] = complete_dimension(ledger)
            ledger["dimensions"]["evidence_complete"] = complete_dimension(ledger)
            checker.check_ledger(ledger, root)

            with self.assertRaisesRegex(AssertionError, "earlier release stage"):
                checker.check_release_candidate_request(
                    ledger, "a" * 40, "v1.2.0-beta.1"
                )

    def test_stable_candidate_ci_can_precede_final_go(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "1.2.0", accept_phase_3a=True)
            for dimension in (
                "code_complete",
                "evidence_complete",
                "audit_complete",
                "deployable",
            ):
                ledger["dimensions"][dimension] = complete_dimension(ledger)
            ledger["audit"] = {
                "status": "complete",
                "independent": True,
                "reviewer": "Independent reviewer",
                "report_sha256": "f" * 64,
                "remediation_complete": True,
            }
            ledger["current_claim_state"]["formal_audit"] = "completed"
            for stage in checker.RELEASES[:-1]:
                ledger["release_gates"][stage] = "pass"
            checker.check_ledger(ledger, root)

            checker.check_release_candidate_request(ledger, "a" * 40, "v1.2.0")


def freeze_candidate(
    ledger: dict, software_version: str, *, accept_phase_3a: bool = False
) -> None:
    evidence_path = ledger["scope"]["docs"][0]
    ledger["candidate"].update(
        {
            "status": "frozen",
            "maverick_release_commit": "a" * 40,
            "maverick_sdk_commit": "b" * 40,
            "reference_client_commit": "c" * 40,
            "reference_client_sdk_pin": "b" * 40,
            "sdk_pin_verified": True,
            "sdk_pin_evidence_path": evidence_path,
            "reference_package_sha256": "d" * 64,
        }
    )
    ledger["candidate"]["versions"]["software"] = software_version
    ledger["candidate"]["versions"]["reference_package"] = f"{software_version}-1"
    ledger["phase_inputs"]["phase_3b"] = accepted_phase(evidence_path)
    if accept_phase_3a:
        ledger["phase_inputs"]["phase_3a"] = accepted_phase(evidence_path)


def accepted_phase(evidence_path: str) -> dict:
    return {
        "status": "accepted",
        "accepted_manifest_sha256": "e" * 64,
        "public_summary_paths": [evidence_path],
    }


def complete_dimension(ledger: dict) -> dict:
    return {
        "status": "complete",
        "reason": None,
        "evidence_paths": [ledger["scope"]["docs"][0]],
    }


class fixture_repo:
    def __enter__(self) -> tuple[Path, dict]:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        source_root = SCRIPT.parent.parent
        with (source_root / "production-readiness.json").open("r", encoding="utf-8") as handle:
            ledger = copy.deepcopy(json.load(handle))
        for raw_path in ledger["scope"]["docs"]:
            path = root / raw_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        return root, ledger

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
