#!/usr/bin/env python3
"""Unit tests for security review package validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-security-review-package.py")
SPEC = importlib.util.spec_from_file_location("check_security_review_package", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_security_review_package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_security_review_package)


class SecurityReviewPackageTests(unittest.TestCase):
    def test_valid_package_counts_groups_and_artifacts(self) -> None:
        with fixture_repo() as repo_root:
            result = check_security_review_package.check_package(valid_package(), repo_root)

        self.assertEqual(result["status"], "review_package_ready")
        self.assertEqual(result["artifact_group_count"], 6)
        self.assertEqual(result["artifact_count"], 8)

    def test_completed_external_review_claim_is_rejected(self) -> None:
        package = valid_package()
        package["external_review_completed"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "completed external review"):
                check_security_review_package.check_package(package, repo_root)

    def test_missing_required_group_is_rejected(self) -> None:
        package = valid_package()
        package["artifact_groups"] = package["artifact_groups"][:-1]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing security review package"):
                check_security_review_package.check_package(package, repo_root)

    def test_missing_required_artifact_is_rejected(self) -> None:
        package = valid_package()
        package["artifact_groups"][0]["paths"] = ["evidence/protocol.txt"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing security review package artifacts"):
                check_security_review_package.check_package(package, repo_root)

    def test_required_group_must_remain_required(self) -> None:
        package = valid_package()
        package["artifact_groups"][0]["required"] = False
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "must remain required"):
                check_security_review_package.check_package(package, repo_root)

    def test_unsafe_path_is_rejected(self) -> None:
        package = valid_package()
        package["artifact_groups"][0]["paths"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_security_review_package.check_package(package, repo_root)

    def test_review_claim_is_rejected(self) -> None:
        package = valid_package()
        package["artifact_groups"][0]["notes"] = "Production ready."
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsupported review claim"):
                check_security_review_package.check_package(package, repo_root)


def valid_package() -> dict:
    return {
        "version": 1,
        "status": "review_package_ready",
        "external_review_completed": False,
        "notes": "Review inputs only.",
        "artifact_groups": [
            {
                "id": "protocol_and_security_docs",
                "required": True,
                "paths": [
                    "evidence/protocol.txt",
                    "docs/history/review/S3_REVIEW_HANDOFF_2026_07_08.md",
                    "docs/history/review/S3_FINDINGS_TRIAGE_TEMPLATE_2026_07_08.md",
                ],
                "notes": "Protocol inputs.",
            },
            {
                "id": "roadmap_and_capability_docs",
                "required": True,
                "paths": ["evidence/roadmap.txt"],
                "notes": "Roadmap inputs.",
            },
            {
                "id": "privacy_and_experimental_docs",
                "required": True,
                "paths": ["evidence/privacy.txt"],
                "notes": "Privacy inputs.",
            },
            {
                "id": "platform_and_crypto_docs",
                "required": True,
                "paths": ["evidence/platform.txt"],
                "notes": "Platform inputs.",
            },
            {
                "id": "conformance_and_freeze_inputs",
                "required": True,
                "paths": ["evidence/conformance.txt"],
                "notes": "Conformance inputs.",
            },
            {
                "id": "harness_and_ci_inputs",
                "required": True,
                "paths": ["evidence/harness.txt"],
                "notes": "Harness inputs.",
            },
        ],
    }


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        evidence = root / "evidence"
        evidence.mkdir()
        review = root / "docs" / "history" / "review"
        review.mkdir(parents=True)
        for name in (
            "protocol.txt",
            "roadmap.txt",
            "privacy.txt",
            "platform.txt",
            "conformance.txt",
            "harness.txt",
        ):
            (evidence / name).write_text(f"{name} evidence\n", encoding="utf-8")
        (review / "S3_REVIEW_HANDOFF_2026_07_08.md").write_text(
            "handoff\n", encoding="utf-8"
        )
        (review / "S3_FINDINGS_TRIAGE_TEMPLATE_2026_07_08.md").write_text(
            "triage template\n", encoding="utf-8"
        )
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
