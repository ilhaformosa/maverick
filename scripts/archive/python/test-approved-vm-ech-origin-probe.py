#!/usr/bin/env python3
"""Static regression checks for ECH origin probe temporary state."""

from __future__ import annotations

import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("approved-vm-ech-cloudflare-origin-probe.sh")


class EchOriginProbeSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_uses_random_private_state_directory(self) -> None:
        self.assertIn("secrets.token_hex(12)", self.text)
        self.assertIn("^/tmp/maverick-ech-origin-[a-f0-9]{24}$", self.text)
        self.assertIn('mkdir -m 700 "$STATE_DIR"', self.text)
        self.assertIn('chmod 600 "$pid_file"', self.text)
        self.assertNotIn('pid_file="/tmp/maverick-ech-origin-${MODE}.pid"', self.text)
        self.assertNotIn('work_file="/tmp/maverick-ech-origin-${MODE}.work"', self.text)

    def test_cleanup_checks_owner_and_process_identity(self) -> None:
        self.assertIn('stat -c %u "$STATE_DIR"', self.text)
        self.assertIn('readlink "/proc/$pid/cwd"', self.text)
        self.assertIn('"$command" == *"$work"* || "$cwd" == "$work"', self.text)

    def test_hosts_are_guarded_before_probe(self) -> None:
        self.assertGreaterEqual(self.text.count("approved-host-guard.py"), 2)
        self.assertLess(self.text.index("approved-host-guard.py"), self.text.index("cleanup_mode()"))


if __name__ == "__main__":
    unittest.main()
