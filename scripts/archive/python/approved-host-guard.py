#!/usr/bin/env python3
"""Fail closed when an approved SSH target could resolve to this machine."""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import subprocess
from typing import NamedTuple


SAFE_SSH_TARGET = re.compile(r"^[A-Za-z0-9_.@%:-]+$")


class HostEvidence(NamedTuple):
    raw_host: str
    resolved_host: str
    resolved_addresses: frozenset[str]
    remote_hostname: str


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-bin", default="ssh")
    parser.add_argument("host")
    args = parser.parse_args()

    validate_host_syntax(args.host)
    local_names, local_addresses = local_identity()
    resolved_host = ssh_config_hostname(args.host, args.ssh_bin)
    evidence = HostEvidence(
        raw_host=args.host,
        resolved_host=resolved_host,
        resolved_addresses=frozenset(resolve_addresses(resolved_host)),
        remote_hostname=read_remote_hostname(args.host, args.ssh_bin),
    )
    validate_host_evidence(evidence, local_names, local_addresses)
    print("approved_host_guard=ok")


def validate_host_syntax(host: str) -> None:
    if not host or host.startswith("-") or not SAFE_SSH_TARGET.fullmatch(host):
        raise SystemExit("approved host guard refused an invalid target")


def ssh_config_hostname(host: str, ssh_bin: str = "ssh") -> str:
    result = subprocess.run(
        [ssh_bin, "-G", host],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("approved host guard could not resolve SSH configuration")
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key.lower() == "hostname" and value.strip():
            return value.strip()
    raise SystemExit("approved host guard could not resolve SSH hostname")


def resolve_addresses(host: str) -> set[str]:
    try:
        return {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SystemExit("approved host guard could not resolve target addresses") from exc


def read_remote_hostname(host: str, ssh_bin: str = "ssh") -> str:
    result = subprocess.run(
        [
            ssh_bin,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            host,
            "bash",
            "-s",
        ],
        input="hostname -f 2>/dev/null || hostname\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    hostname = result.stdout.strip().splitlines()
    if result.returncode != 0 or len(hostname) != 1 or not hostname[0]:
        raise SystemExit("approved host guard could not verify remote hostname")
    return hostname[0]


def local_identity() -> tuple[frozenset[str], frozenset[str]]:
    names = {"localhost", socket.gethostname(), socket.getfqdn()}
    names.update(name.split(".", 1)[0] for name in tuple(names) if name)
    addresses: set[str] = {"127.0.0.1", "::1"}
    for name in tuple(names):
        if not name:
            continue
        try:
            addresses.update(item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(name, None))
        except socket.gaierror:
            pass
    addresses.update(read_interface_addresses())
    return frozenset(normalize_name(name) for name in names if name), frozenset(addresses)


def read_interface_addresses() -> set[str]:
    addresses: set[str] = set()
    commands = (["ip", "-o", "addr", "show"], ["ifconfig"])
    for command in commands:
        try:
            result = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            continue
        if result.returncode != 0:
            continue
        for token in re.findall(r"(?<![A-Za-z0-9:])(?:[0-9a-fA-F:.]+)(?:/[0-9]+)?", result.stdout):
            candidate = token.split("/", 1)[0].split("%", 1)[0]
            try:
                addresses.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                pass
    return addresses


def validate_host_evidence(
    evidence: HostEvidence,
    local_names: frozenset[str],
    local_addresses: frozenset[str],
) -> None:
    names = {
        normalize_name(evidence.raw_host.rsplit("@", 1)[-1]),
        normalize_name(evidence.resolved_host),
        normalize_name(evidence.remote_hostname),
    }
    expanded_names = names | {name.split(".", 1)[0] for name in names}
    if expanded_names & set(local_names):
        raise SystemExit("approved host guard refused a local target")

    for address in evidence.resolved_addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise SystemExit("approved host guard received an invalid target address") from exc
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_link_local:
            raise SystemExit("approved host guard refused a local target")
        if str(parsed) in local_addresses:
            raise SystemExit("approved host guard refused a local target")


def normalize_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


if __name__ == "__main__":
    main()
