#!/usr/bin/env python3
"""Static and fail-closed checks for approved-host S2 cleanup."""

from pathlib import Path
import os
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/s2-evidence-cleanup.sh"


class S2EvidenceCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_requires_explicit_approval_before_host_resolution(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "client", "/tmp/x", "server", "/tmp/y"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("MAVERICK_S2_CLEANUP_APPROVED=1 is required", result.stderr)

    def test_rejects_unknown_directories_before_ssh(self) -> None:
        env = os.environ.copy()
        env["MAVERICK_S2_CLEANUP_APPROVED"] = "1"
        result = subprocess.run(
            [str(SCRIPT), "client", "/tmp/x", "server", "/tmp/y"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing unexpected S2 client runtime directory", result.stderr)

    def test_contains_pid_firewall_and_netem_guards(self) -> None:
        for required in (
            "MAVERICK_S2_CLEANUP_APPROVED",
            "refusing S2 cleanup against local host",
            "validate_runtime_dir",
            "require_owned_safe_mode",
            "single_log_value",
            'case "$command" in',
            "refusing reused or unrelated pid",
            "refusing cleanup while netem namespace residue is present",
            "refusing cleanup while netem veth residue is present",
            'action" == "temporarily_opened',
            "refusing firewall cleanup while test port is listening",
            "matching server configuration",
            "cleanup_status=ok",
        ):
            self.assertIn(required, self.text)

    def test_rejects_nested_path_under_allowed_prefix_before_ssh(self) -> None:
        env = os.environ.copy()
        env["MAVERICK_S2_CLEANUP_APPROVED"] = "1"
        result = subprocess.run(
            [
                str(SCRIPT),
                "client",
                "/tmp/maverick-netem-client-good/../../other",
                "server",
                "/tmp/maverick-netem-server-good",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing unexpected S2 client runtime directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
