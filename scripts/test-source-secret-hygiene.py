#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("source-secret-hygiene.py")
SPEC = importlib.util.spec_from_file_location("source_secret_hygiene", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceSecretHygieneTests(unittest.TestCase):
    def test_allows_only_canonical_secret_in_canonical_vector_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative = "conformance/vectors/auth_v1_client_hello.json"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(MODULE.CANONICAL_TEST_SECRET)
            self.assertEqual(MODULE.scan_paths(root, [relative]), [])

    def test_rejects_canonical_secret_in_another_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative = "config/private.yaml"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(MODULE.CANONICAL_TEST_SECRET)
            self.assertEqual(MODULE.scan_paths(root, [relative]), [(relative, 1)])

    def test_rejects_another_complete_secret_without_reflecting_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative = "notes.txt"
            token = ("mv1_" + "Z" * 43).encode()
            (root / relative).write_bytes(b"line one\n" + token)
            self.assertEqual(MODULE.scan_paths(root, [relative]), [(relative, 2)])


if __name__ == "__main__":
    unittest.main()
