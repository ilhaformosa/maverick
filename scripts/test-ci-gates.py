#!/usr/bin/env python3
"""Unit tests for the three-layer CI gate checker."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-ci-gates.py")
SPEC = importlib.util.spec_from_file_location("check_ci_gates", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class CIGateTests(unittest.TestCase):
    def test_repository_design_is_valid(self) -> None:
        checker.check_ci_design(SCRIPT.parent.parent)

    def test_release_workflow_cannot_publish(self) -> None:
        with copied_gate_repo() as repo:
            path = repo / ".github" / "workflows" / "release-candidate.yml"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n      - run: git push origin tag\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "forbidden design tokens"):
                checker.check_ci_design(repo)

    def test_private_reference_client_cannot_enter_public_workflow(self) -> None:
        with copied_gate_repo() as repo:
            path = repo / ".github" / "workflows" / "release-candidate.yml"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n# maverick-reference-client\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "forbidden design tokens"):
                checker.check_ci_design(repo)

    def test_pr_matrix_is_rejected(self) -> None:
        with copied_gate_repo() as repo:
            path = repo / ".github" / "workflows" / "ci.yml"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n# matrix:\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "forbidden design tokens"):
                checker.check_ci_design(repo)


class copied_gate_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        repo = Path(self._tmp.name)
        (repo / ".github" / "workflows").mkdir(parents=True)
        (repo / "scripts").mkdir()
        source = SCRIPT.parent.parent
        for relative in (
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/release-candidate.yml"),
            Path("scripts/local-harness.sh"),
        ):
            shutil.copy2(source / relative, repo / relative)
        return repo

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
