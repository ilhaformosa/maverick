#!/usr/bin/env python3
"""Unit tests for approved SSH target identity checks."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("approved-host-guard.py")
SPEC = importlib.util.spec_from_file_location("approved_host_guard", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ApprovedHostGuardTests(unittest.TestCase):
    local_names = frozenset({"local-machine", "local-machine.example", "localhost"})
    local_addresses = frozenset({"127.0.0.1", "::1", "192.0.2.10"})

    def evidence(
        self,
        raw: str = "approved-vm",
        resolved: str = "remote.example",
        addresses: tuple[str, ...] = ("198.51.100.20",),
        remote: str = "remote-vm.example",
    ):
        return module.HostEvidence(raw, resolved, frozenset(addresses), remote)

    def test_distinct_remote_target_is_allowed(self) -> None:
        module.validate_host_evidence(self.evidence(), self.local_names, self.local_addresses)

    def test_loopback_alias_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "local target"):
            module.validate_host_evidence(
                self.evidence(addresses=("127.0.0.1",)),
                self.local_names,
                self.local_addresses,
            )

    def test_local_interface_address_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "local target"):
            module.validate_host_evidence(
                self.evidence(addresses=("192.0.2.10",)),
                self.local_names,
                self.local_addresses,
            )

    def test_remote_hostname_matching_local_machine_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "local target"):
            module.validate_host_evidence(
                self.evidence(remote="local-machine.example"),
                self.local_names,
                self.local_addresses,
            )

    def test_error_does_not_reflect_private_alias(self) -> None:
        private_alias = "private-alias-value"
        with self.assertRaises(SystemExit) as raised:
            module.validate_host_evidence(
                self.evidence(raw=private_alias, addresses=("127.0.0.1",)),
                self.local_names,
                self.local_addresses,
            )
        self.assertNotIn(private_alias, str(raised.exception))

    def test_option_like_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "invalid target"):
            module.validate_host_syntax("-oProxyCommand=bad")


if __name__ == "__main__":
    unittest.main()
