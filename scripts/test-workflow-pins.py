#!/usr/bin/env python3
"""Unit tests for workflow supply-chain pins."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-workflow-pins.py")
SPEC = importlib.util.spec_from_file_location("check_workflow_pins", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class WorkflowPinTests(unittest.TestCase):
    def check(self, text: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(text, encoding="utf-8")
            module.check_workflows([path])

    def test_full_action_and_tool_pins_are_accepted(self) -> None:
        self.check(
            "steps:\n"
            "  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6\n"
            "  - run: cargo install cargo-audit --version 0.22.2 --locked\n"
        )

    def test_mutable_action_tag_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "full revision"):
            self.check("steps:\n  - uses: actions/checkout@v6\n")

    def test_unversioned_cargo_install_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "--version"):
            self.check("steps:\n  - run: cargo install cargo-audit --locked\n")


if __name__ == "__main__":
    unittest.main()
