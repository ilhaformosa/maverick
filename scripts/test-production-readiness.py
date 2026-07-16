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
        self.assertEqual(result["candidate_status"], "frozen")
        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["complete_dimensions"], 1)
        self.assertEqual(ledger["phase_inputs"]["phase_3b"]["status"], "accepted")
        self.assertEqual(ledger["scope"]["platform"], "Ubuntu 26.04 LTS")
        self.assertEqual(
            ledger["scope"]["formal_evidence_fixture"]["platform"],
            "Ubuntu 26.04 LTS",
        )
        self.assertEqual(
            ledger["candidate"]["versions"],
            {
                "release_train": "1.2.0",
                "release_tag": "v1.2.0-alpha.1",
                "maverick_software": "1.2.0-alpha.1",
                "reference_software": "1.2.0-alpha.1",
                "debian_package": "1.2.0~alpha.1-1",
                "protocol": 1,
                "auth_v1": 1,
                "auth_v2": 2,
                "config": 1,
                "helper_ipc": 1,
                "recovery_journal": 2,
                "platform_plan": 3,
            },
        )

    def test_unfrozen_candidate_rejects_hashes(self) -> None:
        with fixture_repo() as (root, ledger):
            unfreeze_candidate(ledger)
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

    def test_ubuntu_24_04_cannot_be_the_formal_target(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["scope"]["platform"] = "Ubuntu 24.04 LTS"
            ledger["scope"]["formal_evidence_fixture"]["platform"] = (
                "Ubuntu 24.04 LTS"
            )
            with self.assertRaisesRegex(AssertionError, "scope platform"):
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

    def test_symlink_evidence_path_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            evidence_path = root / ledger["scope"]["docs"][0]
            target = evidence_path.with_name("actual-evidence.md")
            target.write_text("fixture\n", encoding="utf-8")
            evidence_path.unlink()
            evidence_path.symlink_to(target.name)
            with self.assertRaisesRegex(AssertionError, "symlink"):
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
            set_version_identity(ledger, "v1.2.0")
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
            with self.assertRaisesRegex(AssertionError, "SDK pin must match"):
                checker.check_ledger(ledger, root)

    def test_release_candidate_request_binds_release_commit_and_stage(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "v1.2.0-alpha.1")
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
            freeze_candidate(ledger, "v1.2.0-beta.1", accept_phase_3a=True)
            ledger["dimensions"]["code_complete"] = complete_dimension(ledger)
            ledger["dimensions"]["evidence_complete"] = complete_dimension(ledger)
            checker.check_ledger(ledger, root)

            with self.assertRaisesRegex(AssertionError, "earlier release stage"):
                checker.check_release_candidate_request(
                    ledger, "a" * 40, "v1.2.0-beta.1"
                )

    def test_stable_candidate_ci_can_precede_final_go(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "v1.2.0", accept_phase_3a=True)
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

    def test_release_candidate_request_rejects_release_tag_mismatch(self) -> None:
        with fixture_repo() as (root, ledger):
            freeze_candidate(ledger, "v1.2.0-alpha.1")
            ledger["dimensions"]["code_complete"] = complete_dimension(ledger)
            checker.check_ledger(ledger, root)

            with self.assertRaisesRegex(AssertionError, "must match release_tag"):
                checker.check_release_candidate_request(
                    ledger, "a" * 40, "v1.2.0-beta.1"
                )

    def test_unfrozen_non_alpha_planned_identities_are_valid(self) -> None:
        identities = {
            "v1.2.0-beta.1": ("1.2.0-beta.1", "1.2.0~beta.1-1"),
            "v1.2.0-rc.1": ("1.2.0-rc.1", "1.2.0~rc.1-1"),
            "v1.2.0": ("1.2.0", "1.2.0-1"),
        }
        for release_tag, (software, debian) in identities.items():
            with self.subTest(release_tag=release_tag), fixture_repo() as (root, ledger):
                unfreeze_candidate(ledger)
                set_version_identity(ledger, release_tag)
                result = checker.check_ledger(ledger, root)
                self.assertEqual(result["candidate_status"], "not_frozen")
                self.assertEqual(
                    ledger["candidate"]["versions"]["reference_software"], software
                )
                self.assertEqual(
                    ledger["candidate"]["versions"]["debian_package"], debian
                )

    def test_alpha_reference_software_mismatch_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["candidate"]["versions"]["reference_software"] = (
                "1.2.0-alpha.2"
            )
            with self.assertRaisesRegex(AssertionError, "identity reference_software"):
                checker.check_ledger(ledger, root)

    def test_alpha_debian_package_mismatch_is_rejected(self) -> None:
        with fixture_repo() as (root, ledger):
            ledger["candidate"]["versions"]["debian_package"] = "1.2.0-alpha.1-1"
            with self.assertRaisesRegex(AssertionError, "identity debian_package"):
                checker.check_ledger(ledger, root)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ledger_path = Path(temp_dir) / "production-readiness.json"
            ledger_path.write_text(
                '{"schema_version": 1, "schema_version": 1}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(AssertionError, "duplicate JSON key"):
                checker.check_ledger_file(ledger_path)


def freeze_candidate(
    ledger: dict, release_tag: str, *, accept_phase_3a: bool = False
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
    set_version_identity(ledger, release_tag)
    ledger["phase_inputs"]["phase_3b"] = accepted_phase(evidence_path)
    if accept_phase_3a:
        ledger["phase_inputs"]["phase_3a"] = accepted_phase(evidence_path)


def unfreeze_candidate(ledger: dict) -> None:
    ledger["candidate"].update(
        {
            "status": "not_frozen",
            "maverick_release_commit": None,
            "maverick_sdk_commit": None,
            "reference_client_commit": None,
            "reference_client_sdk_pin": None,
            "sdk_pin_verified": False,
            "sdk_pin_evidence_path": None,
            "reference_package_sha256": None,
        }
    )
    ledger["phase_inputs"]["phase_3b"] = {
        "status": "missing",
        "accepted_manifest_sha256": None,
        "public_summary_paths": [],
    }
    ledger["dimensions"]["code_complete"] = {
        "status": "blocked",
        "reason": "candidate_not_frozen",
        "evidence_paths": [],
    }
    ledger["release_gates"] = {release: "blocked" for release in checker.RELEASES}


def set_version_identity(ledger: dict, release_tag: str) -> None:
    software = release_tag.removeprefix("v")
    if "-alpha." in software:
        debian = software.replace("-alpha.", "~alpha.") + "-1"
    elif "-beta." in software:
        debian = software.replace("-beta.", "~beta.") + "-1"
    elif "-rc." in software:
        debian = software.replace("-rc.", "~rc.") + "-1"
    else:
        debian = software + "-1"
    ledger["candidate"]["versions"].update(
        {
            "release_tag": release_tag,
            "maverick_software": software,
            "reference_software": software,
            "debian_package": debian,
        }
    )


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
        paths = set(ledger["scope"]["docs"])
        candidate_path = ledger["candidate"].get("sdk_pin_evidence_path")
        if candidate_path:
            paths.add(candidate_path)
        for phase in ledger["phase_inputs"].values():
            paths.update(phase["public_summary_paths"])
        for dimension in ledger["dimensions"].values():
            paths.update(dimension["evidence_paths"])
        for raw_path in paths:
            path = root / raw_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        return root, ledger

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
