#!/usr/bin/env python3
"""Unit tests for implementation registry policy checks."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_implementation_registry import check_registry


class ImplementationRegistryTests(unittest.TestCase):
    def test_valid_registry_counts_parser(self) -> None:
        with fixture_repo() as repo_root:
            result = check_registry(valid_registry(), repo_root)

        self.assertEqual(result["implementation_count"], 2)
        self.assertEqual(result["parser_count"], 1)

    def test_duplicate_ids_are_rejected(self) -> None:
        registry = valid_registry()
        registry["implementations"][1]["id"] = "maverick-rust"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "duplicate implementation id"):
                check_registry(registry, repo_root)

    def test_registry_requires_parser_verifier(self) -> None:
        registry = valid_registry()
        registry["implementations"] = [registry["implementations"][0]]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "parser/verifier"):
                check_registry(registry, repo_root)

    def test_parser_must_be_no_network(self) -> None:
        registry = valid_registry()
        parser = registry["implementations"][1]
        parser["opens_network"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "no-network"):
                check_registry(registry, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        registry = valid_registry()
        registry["implementations"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_registry(registry, repo_root)

    def test_normative_claims_are_rejected(self) -> None:
        registry = valid_registry()
        registry["implementations"][0]["normative"] = True
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "normative"):
                check_registry(registry, repo_root)


def valid_registry() -> dict:
    return {
        "version": 1,
        "spec_status": "draft",
        "standardization_claim": False,
        "notes": "Experimental registry.",
        "implementations": [
            {
                "id": "maverick-rust",
                "name": "Maverick Rust reference prototype",
                "kind": "client_server",
                "language": "Rust",
                "status": "passing",
                "network_behavior": "loopback_only_tests",
                "opens_network": True,
                "transports": ["h2_tls"],
                "feature_gates": [],
                "coverage": ["tcp_relay"],
                "evidence": ["evidence/rust.txt"],
                "normative": False,
            },
            {
                "id": "python-conformance-verifier",
                "name": "Python verifier",
                "kind": "read_only_parser",
                "language": "Python",
                "status": "passing",
                "network_behavior": "no_network",
                "opens_network": False,
                "transports": [],
                "feature_gates": [],
                "coverage": ["frame_headers"],
                "evidence": ["evidence/python.txt"],
                "normative": False,
            },
        ],
    }


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "rust.txt").write_text("rust evidence\n", encoding="utf-8")
        (evidence / "python.txt").write_text("python evidence\n", encoding="utf-8")
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
