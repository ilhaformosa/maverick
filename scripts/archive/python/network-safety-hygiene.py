#!/usr/bin/env python3
"""Scan automation files for host network mutation commands."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_SCAN_ROOTS = ("scripts", ".github/workflows", "crates")
EXCLUDED_FILES = {
    Path("crates/maverick-cli/src/main.rs"),
    Path("scripts/network-safety-hygiene.py"),
    Path("scripts/test-network-safety-hygiene.py"),
    Path("scripts/test-approved-vm-longhaul.py"),
    Path("scripts/test-approved-vm-s2-runners.py"),
    Path("scripts/approved-vm-tun-apply-smoke.sh"),
    Path("scripts/approved-vm-tun-runtime-smoke.sh"),
    Path("scripts/approved-vm-tun-policy-smoke.sh"),
    Path("scripts/approved-vm-tun-service-smoke.sh"),
    Path("scripts/approved-vm-tun-leak-coexistence-smoke.sh"),
    Path("scripts/approved-vm-tun-full-helper-smoke.sh"),
    Path("scripts/approved-vm-netem-impairment-smoke.sh"),
    Path("scripts/approved-vm-detached-tcp-longhaul.sh"),
    Path("scripts/approved-vm-failure-injection-smoke.sh"),
    Path("scripts/s2-evidence-cleanup.sh"),
}
APPROVED_VM_MUTATION_FILES = {
    Path("crates/maverick-cli/src/main.rs"),
    Path("scripts/approved-vm-tun-apply-smoke.sh"),
    Path("scripts/approved-vm-tun-runtime-smoke.sh"),
    Path("scripts/approved-vm-tun-policy-smoke.sh"),
    Path("scripts/approved-vm-tun-service-smoke.sh"),
    Path("scripts/approved-vm-tun-leak-coexistence-smoke.sh"),
    Path("scripts/approved-vm-tun-full-helper-smoke.sh"),
    Path("scripts/approved-vm-netem-impairment-smoke.sh"),
    Path("scripts/approved-vm-detached-tcp-longhaul.sh"),
    Path("scripts/approved-vm-failure-injection-smoke.sh"),
}
APPROVED_VM_MUTATION_REQUIRED_TOKENS = {
    Path("scripts/approved-vm-detached-tcp-longhaul.sh"): (
        "approved-host-guard.py",
        "MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL",
        'require_non_empty "server ssh host"',
        'ssh "$server_host"',
        "temporary firewall mode requires a port that is initially closed",
        '--timeout="${SERVER_TIMEOUT}s"',
        "detached_tcp_smoke=ok",
    ),
    Path("scripts/approved-vm-failure-injection-smoke.sh"): (
        "approved-host-guard.py",
        "MAVERICK_FAILURE_TEMP_FIREWALL",
        'require_non_empty "server ssh host"',
        'ssh "$server_host"',
        "trap cleanup EXIT",
        '--timeout="${TIMEOUT_SECS}s"',
        '--remove-port="$SERVER_PORT/tcp"',
        "post_cleanup_firewall=closed_or_disabled",
    ),
    Path("scripts/s2-evidence-cleanup.sh"): (
        "approved-host-guard.py",
        "MAVERICK_S2_CLEANUP_APPROVED",
        "refusing S2 cleanup against local host",
        "validate_runtime_dir",
        "require_owned_safe_mode",
        "refusing reused or unrelated pid",
        "refusing cleanup while netem namespace residue is present",
        "refusing firewall cleanup while test port is listening",
        "cleanup_status=ok",
    ),
    Path("scripts/approved-vm-netem-impairment-smoke.sh"): (
        "approved-host-guard.py",
        "MAVERICK_NETEM_IMPAIRMENT_APPROVED",
        'ssh -o BatchMode=yes "$client_host"',
        "refusing to run approved VM netem impairment smoke against local host",
        "trap 'cleanup || true' EXIT",
        "namespace_setup=ok",
        "default_route_unchanged: true",
        "global_dns_unchanged: true",
        "remote_residue=absent",
        "approved_vm_netem_impairment_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-apply-smoke.sh"): (
        "MAVERICK_TUN_APPLY_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN apply smoke against local host",
        "trap cleanup EXIT",
        "approved_vm_tun_apply_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-runtime-smoke.sh"): (
        "MAVERICK_TUN_RUNTIME_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN runtime smoke against local host",
        "trap cleanup EXIT",
        "namespace_veth_echo=ok",
        "default_route_unchanged: true",
        "global_dns_unchanged: true",
        "approved_vm_tun_runtime_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-policy-smoke.sh"): (
        "MAVERICK_TUN_POLICY_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN policy smoke against local host",
        "trap cleanup EXIT",
        "namespace_policy_default_route=ok",
        "namespace_policy_dns_route=ok",
        "namespace_policy_control_plane=ok",
        "default_route_unchanged: true",
        "global_dns_unchanged: true",
        "approved_vm_tun_policy_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-service-smoke.sh"): (
        "MAVERICK_TUN_SERVICE_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN service smoke against local host",
        "trap cleanup EXIT",
        "systemd_lifecycle_success=ok",
        "systemd_failure_cleanup=ok",
        "default_route_unchanged: true",
        "global_dns_unchanged: true",
        "approved_vm_tun_service_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-leak-coexistence-smoke.sh"): (
        "MAVERICK_TUN_LEAK_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN leak/coexistence smoke against local host",
        "trap cleanup EXIT",
        "namespace_default_probe_uses_tun=ok",
        "namespace_dns_probe_uses_tun=ok",
        "namespace_control_plane_uses_veth=ok",
        "host_listeners_unchanged: true",
        "default_route_unchanged: true",
        "global_dns_unchanged: true",
        "approved_vm_tun_leak_coexistence_smoke=ok",
    ),
    Path("scripts/approved-vm-tun-full-helper-smoke.sh"): (
        "MAVERICK_TUN_FULL_HELPER_APPROVED",
        'ssh -o BatchMode=yes "$host"',
        "refusing to run approved VM TUN full helper smoke against local host",
        "MAVERICK_TUN_RUNTIME_APPROVED=1",
        "MAVERICK_TUN_POLICY_APPROVED=1",
        "MAVERICK_TUN_SERVICE_APPROVED=1",
        "MAVERICK_TUN_LEAK_APPROVED=1",
        "remote_residue=absent",
        "approved_vm_tun_full_helper_smoke=ok",
    ),
    Path("crates/maverick-cli/src/main.rs"): (
        "TunHelperSmoke",
        "TunHelperPreflight",
        "TunHelperRollback",
        "MAVERICK_TUN_HELPER_APPROVED",
        "approved_host_label",
        "proxy_vpn_conflict_checked",
        "rollback_journal",
        'cfg!(target_os = "linux")',
        "validate_phase_a_documentation_route",
        "validate_phase_a_tun_addr",
        "default_route: not_touched",
        "global_dns: not_touched",
        "firewall: not_touched",
        "residue_check: ok",
    ),
}
TEXT_AUTOMATION_SUFFIXES = {".py", ".rs", ".sh", ".yaml", ".yml"}

DANGEROUS_PATTERNS = (
    (r"\bnetworksetup\b", "macOS networksetup"),
    (r"\bscutil\s+(--dns|--proxy|--nc|--set)\b", "macOS scutil network mutation"),
    (r"\broute\s+(add|delete|change|flush)\b", "route table mutation"),
    (r"\bip\s+route\s+(add|del|delete|replace|flush)\b", "Linux route mutation"),
    (r"\bpfctl\b", "macOS packet filter mutation"),
    (
        r"\biptables\b(?=.*\s(-A|-D|-F|-I|-R|-P|-N|-X|--append|--delete|--flush|--insert|--replace|--policy|--new-chain|--delete-chain)\b)",
        "iptables firewall mutation",
    ),
    (r"\bnft\s+(add|delete|flush|insert|replace)\b", "nftables firewall mutation"),
    (
        r"\bfirewall-cmd\b(?=.*\s--(?:add|remove|set|new|delete)-|.*\s--(?:reload|complete-reload|runtime-to-permanent|lockdown-on|lockdown-off)\b)",
        "firewalld mutation",
    ),
    (r"\bresolvectl\b", "system DNS mutation"),
    (r"\bsystemd-resolve\b", "system DNS mutation"),
    (r"\bwg-quick\b", "WireGuard interface mutation"),
    (r"\bwireguard-go\b", "WireGuard interface mutation"),
    (r"\blaunchctl\s+(load|unload|bootstrap|bootout|kickstart)\b", "launchctl service mutation"),
    (r"\bifconfig\s+\S+\s+(up|down|destroy|create)\b", "interface mutation"),
    (r'Command::new\("ip"\)', "Linux ip command"),
    (r'Command::new\("sudo"\)', "sudo command"),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    roots = tuple(args.paths) if args.paths else DEFAULT_SCAN_ROOTS
    count = check_network_safety(args.repo_root, roots)
    print(f"network safety hygiene OK: {count} files scanned")


def check_network_safety(repo_root: Path, roots: tuple[str, ...] = DEFAULT_SCAN_ROOTS) -> int:
    files = list(iter_scan_files(repo_root, roots))
    for path in files:
        check_file(repo_root, path)
    check_approved_vm_mutation_exceptions(repo_root)
    return len(files)


def iter_scan_files(repo_root: Path, roots: tuple[str, ...]):
    for raw_root in roots:
        root = repo_root / raw_root
        if not root.exists():
            continue
        if root.is_file():
            rel = root.relative_to(repo_root)
            if should_scan(rel):
                yield rel
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(repo_root)
            if should_scan(rel):
                yield rel


def should_scan(rel_path: Path) -> bool:
    return rel_path not in EXCLUDED_FILES and rel_path.suffix in TEXT_AUTOMATION_SUFFIXES


def check_file(repo_root: Path, rel_path: Path) -> None:
    content = (repo_root / rel_path).read_text(encoding="utf-8")
    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern, reason in DANGEROUS_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                raise AssertionError(f"{rel_path}:{line_number}: blocked {reason}")


def check_approved_vm_mutation_exceptions(repo_root: Path) -> None:
    for rel_path in APPROVED_VM_MUTATION_FILES:
        path = repo_root / rel_path
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        required_tokens = APPROVED_VM_MUTATION_REQUIRED_TOKENS[rel_path]
        for token in required_tokens:
            if token not in content:
                raise AssertionError(
                    f"{rel_path}: approved VM mutation exception missing {token!r}"
                )


if __name__ == "__main__":
    main()
