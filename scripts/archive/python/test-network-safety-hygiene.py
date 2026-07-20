#!/usr/bin/env python3
"""Unit tests for network-safety hygiene checks."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("network-safety-hygiene.py")
SPEC = importlib.util.spec_from_file_location("network_safety_hygiene", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class NetworkSafetyHygieneTests(unittest.TestCase):
    def test_valid_scripts_are_accepted(self) -> None:
        with fixture_repo() as repo_root:
            count = module.check_network_safety(repo_root)

        self.assertEqual(count, 2)

    def test_route_mutation_is_rejected(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/bad-route.sh"
            script.write_text("#!/usr/bin/env bash\nroute add 0.0.0.0/0 1.2.3.4\n")
            with self.assertRaisesRegex(AssertionError, "route table mutation"):
                module.check_network_safety(repo_root)

    def test_rust_ip_command_is_rejected_outside_approved_helper(self) -> None:
        with fixture_repo() as repo_root:
            rust_dir = repo_root / "crates/other/src"
            rust_dir.mkdir(parents=True)
            rust_file = rust_dir / "main.rs"
            rust_file.write_text('fn main() { Command::new("ip").status(); }\n')
            with self.assertRaisesRegex(AssertionError, "Linux ip command"):
                module.check_network_safety(repo_root)

    def test_checker_files_are_excluded(self) -> None:
        with fixture_repo() as repo_root:
            checker = repo_root / "scripts/network-safety-hygiene.py"
            test = repo_root / "scripts/test-network-safety-hygiene.py"
            checker.write_text("networksetup -setdnsservers Wi-Fi empty\n", encoding="utf-8")
            test.write_text("iptables -F\n", encoding="utf-8")
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_read_only_iptables_presence_check_is_allowed(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/preflight.sh"
            script.write_text("command -v iptables >/dev/null\n", encoding="utf-8")
            self.assertEqual(module.check_network_safety(repo_root), 3)

    def test_iptables_mutation_is_rejected(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/bad-firewall.sh"
            script.write_text("iptables -F\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "iptables firewall mutation"):
                module.check_network_safety(repo_root)

    def test_firewalld_mutation_is_rejected(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/bad-firewalld.sh"
            script.write_text("firewall-cmd --add-port=24443/tcp\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "firewalld mutation"):
                module.check_network_safety(repo_root)

    def test_firewalld_read_only_query_is_allowed(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/firewalld-query.sh"
            script.write_text("firewall-cmd --query-port=24443/tcp\n", encoding="utf-8")
            self.assertEqual(module.check_network_safety(repo_root), 3)

    def test_approved_vm_tun_smoke_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-apply-smoke.sh"
            script.write_text("ip route add 192.0.2.0/24 dev mavtun0\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_netem_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-netem-impairment-smoke.sh"
            script.write_text("tc qdisc replace dev eth0 root netem loss 1%\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_runtime_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-runtime-smoke.sh"
            script.write_text("ip route add 192.0.2.0/24 dev mavtun0\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_policy_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-policy-smoke.sh"
            script.write_text("ip route add default dev mavtun0\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_service_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-service-smoke.sh"
            script.write_text("ip route add 192.0.2.0/24 dev mavtun0\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_leak_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-leak-coexistence-smoke.sh"
            script.write_text("ip route add default dev mavtun0\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_full_helper_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-full-helper-smoke.sh"
            script.write_text("MAVERICK_TUN_RUNTIME_APPROVED=1\n")
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_cli_tun_helper_exception_requires_safety_markers(self) -> None:
        with fixture_repo() as repo_root:
            cli = repo_root / "crates/maverick-cli/src/main.rs"
            cli.parent.mkdir(parents=True)
            cli.write_text('fn main() { Command::new("ip").status(); }\n')
            with self.assertRaisesRegex(
                AssertionError, "approved VM mutation exception missing"
            ):
                module.check_network_safety(repo_root)

    def test_approved_vm_tun_smoke_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-apply-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_APPLY_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN apply smoke against local host",
                        "trap cleanup EXIT",
                        "ip route add 192.0.2.0/24 dev mavtun0",
                        "approved_vm_tun_apply_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_netem_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-netem-impairment-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_NETEM_IMPAIRMENT_APPROVED",
                        "approved-host-guard.py",
                        'ssh -o BatchMode=yes "$client_host"',
                        "refusing to run approved VM netem impairment smoke against local host",
                        "trap 'cleanup || true' EXIT",
                        "tc qdisc replace dev mavnh root netem loss 1%",
                        "namespace_setup=ok",
                        "default_route_unchanged: true",
                        "global_dns_unchanged: true",
                        "remote_residue=absent",
                        "approved_vm_netem_impairment_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_tun_runtime_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-runtime-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_RUNTIME_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN runtime smoke against local host",
                        "trap cleanup EXIT",
                        "ip route add 192.0.2.0/24 dev mavtun0",
                        "namespace_veth_echo=ok",
                        "default_route_unchanged: true",
                        "global_dns_unchanged: true",
                        "approved_vm_tun_runtime_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_tun_policy_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-policy-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_POLICY_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN policy smoke against local host",
                        "trap cleanup EXIT",
                        "ip route add default dev mavtun0",
                        "namespace_policy_default_route=ok",
                        "namespace_policy_dns_route=ok",
                        "namespace_policy_control_plane=ok",
                        "default_route_unchanged: true",
                        "global_dns_unchanged: true",
                        "approved_vm_tun_policy_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_tun_service_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-service-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_SERVICE_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN service smoke against local host",
                        "trap cleanup EXIT",
                        "ip route add 192.0.2.0/24 dev mavtun0",
                        "systemd_lifecycle_success=ok",
                        "systemd_failure_cleanup=ok",
                        "default_route_unchanged: true",
                        "global_dns_unchanged: true",
                        "approved_vm_tun_service_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_tun_leak_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-leak-coexistence-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_LEAK_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN leak/coexistence smoke against local host",
                        "trap cleanup EXIT",
                        "ip route add default dev mavtun0",
                        "namespace_default_probe_uses_tun=ok",
                        "namespace_dns_probe_uses_tun=ok",
                        "namespace_control_plane_uses_veth=ok",
                        "host_listeners_unchanged: true",
                        "default_route_unchanged: true",
                        "global_dns_unchanged: true",
                        "approved_vm_tun_leak_coexistence_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_approved_vm_tun_full_helper_exception_is_excluded_when_gated(self) -> None:
        with fixture_repo() as repo_root:
            script = repo_root / "scripts/approved-vm-tun-full-helper-smoke.sh"
            script.write_text(
                "\n".join(
                    [
                        "MAVERICK_TUN_FULL_HELPER_APPROVED",
                        'ssh -o BatchMode=yes "$host"',
                        "refusing to run approved VM TUN full helper smoke against local host",
                        "MAVERICK_TUN_RUNTIME_APPROVED=1",
                        "MAVERICK_TUN_POLICY_APPROVED=1",
                        "MAVERICK_TUN_SERVICE_APPROVED=1",
                        "MAVERICK_TUN_LEAK_APPROVED=1",
                        "remote_residue=absent",
                        "approved_vm_tun_full_helper_smoke=ok",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(module.check_network_safety(repo_root), 2)

    def test_binary_cache_files_are_ignored(self) -> None:
        with fixture_repo() as repo_root:
            cache = repo_root / "scripts/__pycache__"
            cache.mkdir()
            (cache / "compiled.pyc").write_bytes(b"\x93route add")
            self.assertEqual(module.check_network_safety(repo_root), 2)


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        (root / "scripts").mkdir()
        (root / ".github/workflows").mkdir(parents=True)
        (root / "scripts/local-harness.sh").write_text(
            "#!/usr/bin/env bash\ncargo test --workspace\n",
            encoding="utf-8",
        )
        (root / ".github/workflows/ci.yml").write_text(
            "steps:\n  - run: ./scripts/local-harness.sh\n",
            encoding="utf-8",
        )
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
