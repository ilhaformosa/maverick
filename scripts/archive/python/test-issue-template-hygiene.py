#!/usr/bin/env python3
"""Unit tests for issue-template hygiene checks."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("issue-template-hygiene.py")
SPEC = importlib.util.spec_from_file_location("issue_template_hygiene", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class IssueTemplateHygieneTests(unittest.TestCase):
    def test_valid_templates_satisfy_requirements(self) -> None:
        with fixture_repo() as repo_root:
            count = module.check_issue_template_hygiene(repo_root)

        self.assertEqual(count, len(module.REQUIREMENTS))

    def test_missing_template_is_rejected(self) -> None:
        with fixture_repo() as repo_root:
            missing = repo_root / module.REQUIREMENTS[0].path
            missing.unlink()
            with self.assertRaisesRegex(AssertionError, "missing issue-template hygiene"):
                module.check_issue_template_hygiene(repo_root)

    def test_missing_required_prompt_is_rejected(self) -> None:
        with fixture_repo() as repo_root:
            path = repo_root / module.REQUIREMENTS[0].path
            path.write_text("name: Bug report\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "missing required prompt"):
                module.check_issue_template_hygiene(repo_root)

    def test_whitespace_is_normalized(self) -> None:
        requirement = module.Requirement("template.yml", "raw payload data")
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            (repo_root / "template.yml").write_text("raw\npayload\tdata\n", encoding="utf-8")
            module.check_requirement(repo_root, requirement)


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        for requirement in module.REQUIREMENTS:
            path = root / requirement.path
            path.parent.mkdir(parents=True, exist_ok=True)
            existing = path.read_text(encoding="utf-8") if path.exists() else ""
            path.write_text(
                f"{existing}\n{requirement.phrase}\n",
                encoding="utf-8",
            )
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
