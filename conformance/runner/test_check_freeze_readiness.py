#!/usr/bin/env python3
"""Unit tests for the spec-freeze readiness checker."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_freeze_readiness


class FreezeReadinessTests(unittest.TestCase):
    def test_blocked_readiness_with_existing_evidence_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SPEC.md").write_text("# spec\n", encoding="utf-8")
            readiness = {
                "version": 1,
                "status": "blocked",
                "target": "candidate",
                "criteria": [
                    {
                        "id": "spec_review",
                        "level": "candidate",
                        "status": "partial",
                        "evidence": ["SPEC.md"],
                        "notes": "Manual review is pending.",
                    }
                ],
            }

            result = check_freeze_readiness.check_readiness(readiness, root)

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["blocking_count"], 1)

    def test_ready_status_rejects_blocking_criteria(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SPEC.md").write_text("# spec\n", encoding="utf-8")
            readiness = {
                "version": 1,
                "status": "ready",
                "target": "candidate",
                "criteria": [
                    {
                        "id": "spec_review",
                        "level": "candidate",
                        "status": "partial",
                        "evidence": ["SPEC.md"],
                        "notes": "Manual review is pending.",
                    }
                ],
            }

            with self.assertRaisesRegex(AssertionError, "ready status cannot"):
                check_freeze_readiness.check_readiness(readiness, root)

    def test_blocked_status_requires_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SPEC.md").write_text("# spec\n", encoding="utf-8")
            readiness = {
                "version": 1,
                "status": "blocked",
                "target": "candidate",
                "criteria": [
                    {
                        "id": "spec_review",
                        "level": "candidate",
                        "status": "satisfied",
                        "evidence": ["SPEC.md"],
                        "notes": "Reviewed.",
                    }
                ],
            }

            with self.assertRaisesRegex(AssertionError, "blocked status must"):
                check_freeze_readiness.check_readiness(readiness, root)

    def test_missing_or_unsafe_evidence_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readiness = {
                "version": 1,
                "status": "blocked",
                "target": "candidate",
                "criteria": [
                    {
                        "id": "spec_review",
                        "level": "candidate",
                        "status": "partial",
                        "evidence": ["../SPEC.md"],
                        "notes": "Manual review is pending.",
                    }
                ],
            }

            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_freeze_readiness.check_readiness(readiness, root)

            readiness["criteria"][0]["evidence"] = ["SPEC.md"]
            with self.assertRaisesRegex(AssertionError, "missing evidence path"):
                check_freeze_readiness.check_readiness(readiness, root)

    def test_duplicate_criteria_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SPEC.md").write_text("# spec\n", encoding="utf-8")
            criterion = {
                "id": "spec_review",
                "level": "candidate",
                "status": "partial",
                "evidence": ["SPEC.md"],
                "notes": "Manual review is pending.",
            }
            readiness = {
                "version": 1,
                "status": "blocked",
                "target": "candidate",
                "criteria": [criterion, dict(criterion)],
            }

            with self.assertRaisesRegex(AssertionError, "duplicate freeze criterion"):
                check_freeze_readiness.check_readiness(readiness, root)


if __name__ == "__main__":
    unittest.main()
