#!/usr/bin/env python3
"""Static regression checks for approved-host TUN runner safety gates."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNERS = (
    "approved-vm-tun-apply-smoke.sh",
    "approved-vm-tun-runtime-smoke.sh",
    "approved-vm-tun-policy-smoke.sh",
    "approved-vm-tun-service-smoke.sh",
    "approved-vm-tun-leak-coexistence-smoke.sh",
    "approved-vm-tun-full-helper-smoke.sh",
)


class ApprovedVmTunSafetyTests(unittest.TestCase):
    def test_every_runner_uses_resolved_approved_host_guard(self) -> None:
        for name in RUNNERS:
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("approved-host-guard.py", text)
                self.assertLess(text.index("approved-host-guard.py"), text.index('ssh -o BatchMode=yes'))

    def test_service_scripts_use_private_random_state_directory(self) -> None:
        text = (ROOT / "approved-vm-tun-service-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d /tmp/maverick-tun-service.XXXXXX", text)
        self.assertIn('chmod 700 "$STATE_DIR"', text)
        self.assertIn('SUCCESS_SCRIPT="$STATE_DIR/success.sh"', text)
        self.assertIn('FAIL_SCRIPT="$STATE_DIR/fail.sh"', text)
        self.assertNotIn('SUCCESS_SCRIPT="/tmp/', text)
        self.assertNotIn('FAIL_SCRIPT="/tmp/', text)


if __name__ == "__main__":
    unittest.main()
