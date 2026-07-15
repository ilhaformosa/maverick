#!/usr/bin/env python3
"""Unit tests for the Phase 2 Linux TUN bridge checker."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tun-phase2-bridge.py")
SPEC = importlib.util.spec_from_file_location("check_tun_phase2_bridge", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_tun_phase2_bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_tun_phase2_bridge)


class TunPhase2BridgeTests(unittest.TestCase):
    def test_current_repository_passes(self) -> None:
        result = check_tun_phase2_bridge.check_repository(SCRIPT.parent.parent)
        self.assertEqual(result["adapter"], "linux-ioctl-single-unsafe")
        self.assertGreaterEqual(result["snapshot_fields"], 30)

    def test_requirement_helper_rejects_false(self) -> None:
        with self.assertRaisesRegex(AssertionError, "expected failure"):
            check_tun_phase2_bridge.require(False, "expected failure")


if __name__ == "__main__":
    unittest.main()
