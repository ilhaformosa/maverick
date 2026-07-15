#!/usr/bin/env python3
"""Static safeguards for detailed approved-host long-haul evidence."""

from pathlib import Path
import os
import subprocess
import unittest


SCRIPT = Path(__file__).with_name("approved-vm-detached-tcp-longhaul.sh")


class ApprovedVmLonghaulTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_records_provenance_and_resource_evidence(self) -> None:
        for required in (
            "binary_sha256=",
            "system-inventory.log",
            "resource-metrics.log",
            "/proc/loadavg",
            "/proc/meminfo",
            "/proc/net/dev",
            "resource_samples",
            "resource_process_children: enabled",
        ):
            self.assertIn(required, self.text)

    def test_resource_evidence_includes_wrapped_process_children(self) -> None:
        self.assertIn(
            '-p "$server_pid,$echo_pid" --ppid "$server_pid,$echo_pid"',
            self.text,
        )
        self.assertGreaterEqual(self.text.count('--ppid "$client_pid"'), 1)
        self.assertIn('-p "$pid" --ppid "$pid"', self.text)

    def test_prebuilt_binary_is_commit_bound_and_verified_remotely(self) -> None:
        for required in (
            "MAVERICK_S2_PREBUILT_LINUX_BIN",
            "MAVERICK_S2_PREBUILT_COMMIT",
            'prebuilt_commit" != "$tested_commit',
            '"$SERVER_BIN" --version',
            '"$CLIENT_BIN" --version',
        ):
            self.assertIn(required, self.text)

    def test_records_detailed_iteration_outcomes(self) -> None:
        for required in (
            "stage=connect_socks ok",
            "stage=socks_method ok",
            "stage=socks_connect ok",
            "stage=echo_payload ok",
            "elapsed_ms=",
            "failure_stage=",
            "error_type=",
            "client process",
            "network counters",
        ):
            self.assertIn(required, self.text)

    def test_preflights_both_server_ports_before_mutation(self) -> None:
        for required in (
            "port-preflight.log",
            'checks = (("0.0.0.0", int(sys.argv[1]))',
            "sock.bind((host, port))",
        ):
            self.assertIn(required, self.text)

    def test_temporary_firewall_rule_is_expiring_and_auditable(self) -> None:
        for required in (
            "MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL",
            'firewall-cmd --add-port="$SERVER_PORT/tcp"',
            '--timeout="${SERVER_TIMEOUT}s"',
            "firewall.log",
            "state_before=closed",
            "action=temporarily_opened",
            "action=refused_existing_rule",
            "state_after=open",
        ):
            self.assertIn(required, self.text)

    def test_leaves_unambiguous_completion_marker(self) -> None:
        self.assertIn('>"$CLIENT_DIR/failed.marker"', self.text)
        self.assertIn('rm -f "CLIENT_DIR/failed.marker"', self.text)
        self.assertIn('touch "CLIENT_DIR/completed.marker"', self.text)

    def test_replaces_longer_interval_placeholder_first(self) -> None:
        replacements = self.text.split("replacements = {", 1)[1].split("}", 1)[0]
        self.assertLess(
            replacements.index('"RESOURCE_INTERVAL_SECS"'),
            replacements.index('"INTERVAL_SECS"'),
        )

    def test_rejects_path_like_detached_run_id_before_remote_access(self) -> None:
        env = os.environ.copy()
        env.update(
            {
                "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR": "example.invalid",
                "MAVERICK_PUBLIC_SMOKE_SERVER_NAME": "example.invalid",
                "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST": "approved-client",
                "MAVERICK_S2_BUILD_HOST": "approved-client",
                "MAVERICK_DETACHED_RUN_ID": "../escaped",
            }
        )
        result = subprocess.run(
            ["bash", str(SCRIPT), "approved-server"],
            cwd=SCRIPT.parents[1],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("safe single path component", result.stderr)


if __name__ == "__main__":
    unittest.main()
