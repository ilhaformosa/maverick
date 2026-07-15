#!/usr/bin/env python3
"""Static safety and evidence checks for approved-host S2 runners."""

from pathlib import Path
import os
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent
NETEM = (ROOT / "approved-vm-netem-impairment-smoke.sh").read_text(
    encoding="utf-8"
)
FAILURE = (ROOT / "approved-vm-failure-injection-smoke.sh").read_text(
    encoding="utf-8"
)
NETEM_PATH = ROOT / "approved-vm-netem-impairment-smoke.sh"
FAILURE_PATH = ROOT / "approved-vm-failure-injection-smoke.sh"


class ApprovedVmS2RunnerTests(unittest.TestCase):
    def test_prebuilt_binaries_are_commit_bound_and_verified(self) -> None:
        for script in (NETEM, FAILURE):
            for required in (
                "MAVERICK_S2_PREBUILT_LINUX_BIN",
                "MAVERICK_S2_PREBUILT_COMMIT",
                'prebuilt_commit" != "$tested_commit',
                "binary-version.log",
                "binary_sha256=",
                "system-inventory.log",
            ):
                self.assertIn(required, script)

    def test_netem_impairment_stays_namespace_veth_scoped(self) -> None:
        for required in (
            "MAVERICK_NETEM_IMPAIRMENT_APPROVED=1",
            "trap 'cleanup || true' EXIT",
            'sudo ip netns exec "$NS" tc qdisc replace',
            'sudo tc qdisc replace dev "$VETH_HOST"',
            "default_route_unchanged: true",
            "global_dns_unchanged: true",
            "remote_residue=absent",
            "iptables_residue=",
            "ip_forward_restored=",
            "iptables -t nat -C POSTROUTING",
            "if cleanup; then",
            'trap - EXIT',
        ):
            self.assertIn(required, NETEM)

    def test_netem_retains_timing_resources_and_failure_marker(self) -> None:
        for required in (
            "resource-metrics.log",
            "resource_samples",
            "resource_process_children: enabled",
            "elapsed_ms=",
            "failure_stage=",
            '>"$failed_marker"',
            'rm -f "$failed_marker"',
        ):
            self.assertIn(required, NETEM)

    def test_resource_evidence_includes_wrapped_process_children(self) -> None:
        self.assertIn(
            '-p "$server_pid,$echo_pid" --ppid "$server_pid,$echo_pid"',
            NETEM,
        )
        self.assertGreaterEqual(FAILURE.count('--ppid "$pid"'), 2)

    def test_temporary_firewall_rules_expire_and_refuse_existing_rules(self) -> None:
        expectations = (
            (NETEM, "MAVERICK_NETEM_TEMP_FIREWALL"),
            (FAILURE, "MAVERICK_FAILURE_TEMP_FIREWALL"),
        )
        for script, gate in expectations:
            for required in (
                gate,
                'firewall-cmd --add-port="$SERVER_PORT/tcp"',
                "--timeout=",
                "action=refused_existing_rule",
                "action=temporarily_opened",
                "firewall.log",
            ):
                self.assertIn(required, script)

    def test_failure_injection_limits_pid_stops_and_preserves_logs(self) -> None:
        for required in (
            'case "$command" in',
            '*"$SERVER_DIR"*)',
            '*"$CLIENT_DIR"*)',
            '>>"$SERVER_DIR/server.log"',
            "server_start_utc=",
            "post_cleanup_ports=free",
            "post_cleanup_firewall=closed_or_disabled",
            "post_cleanup_credentials=absent",
            'touch "$CLIENT_DIR/completed.marker"',
            'rm -f "$CLIENT_DIR/failed.marker"',
        ):
            self.assertIn(required, FAILURE)

    def test_failure_injection_retains_resources_and_timestamps(self) -> None:
        for required in (
            "resource-metrics.log",
            "server_resource_samples",
            "client_resource_samples",
            "server_binary_sha256",
            "client_binary_sha256",
            "resource_process_children: enabled",
            'CHECK utc=$(date -u',
        ):
                self.assertIn(required, FAILURE)

    def test_path_like_run_ids_are_rejected_before_remote_access(self) -> None:
        cases = (
            (
                NETEM_PATH,
                {
                    "MAVERICK_NETEM_IMPAIRMENT_APPROVED": "1",
                    "MAVERICK_NETEM_CLIENT_HOST": "approved-client",
                    "MAVERICK_NETEM_BUILD_HOST": "approved-client",
                    "MAVERICK_NETEM_RUN_ID": "../escaped",
                },
            ),
            (
                FAILURE_PATH,
                {
                    "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR": "example.invalid",
                    "MAVERICK_PUBLIC_SMOKE_SERVER_NAME": "example.invalid",
                    "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST": "approved-client",
                    "MAVERICK_S2_BUILD_HOST": "approved-client",
                    "MAVERICK_FAILURE_RUN_ID": "../escaped",
                },
            ),
        )
        for script, updates in cases:
            with self.subTest(script=script.name):
                env = os.environ.copy()
                env.update(updates)
                result = subprocess.run(
                    ["bash", str(script), "approved-server"],
                    cwd=ROOT.parent,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("safe single path component", result.stderr)


if __name__ == "__main__":
    unittest.main()
