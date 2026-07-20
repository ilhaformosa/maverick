#!/usr/bin/env python3
"""Unit tests for fuzz corpus synchronization path containment."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "fuzz" / "sync-corpus.py"
SPEC = importlib.util.spec_from_file_location("sync_corpus", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FuzzSyncCorpusTests(unittest.TestCase):
    def test_valid_seed_is_written_inside_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            fuzz = repo / "fuzz"
            fuzz.mkdir()
            manifest = {
                "version": 1,
                "targets": [{"target": "wire-frame", "seeds": [{"id": "case-1", "hex": "00ff"}]}],
            }

            self.assertEqual(module.sync_manifest(manifest, repo, fuzz), 1)
            self.assertEqual((fuzz / "corpus/wire-frame/case-1").read_bytes(), b"\x00\xff")

    def test_parent_target_is_rejected_without_writing_outside_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            fuzz = repo / "fuzz"
            fuzz.mkdir()
            manifest = {
                "version": 1,
                "targets": [{"target": "..", "seeds": [{"id": "escaped", "hex": "00"}]}],
            }

            with self.assertRaisesRegex(AssertionError, "filesystem-safe"):
                module.sync_manifest(manifest, repo, fuzz)
            self.assertFalse((fuzz / "escaped").exists())

    def test_parent_seed_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            fuzz = repo / "fuzz"
            fuzz.mkdir()
            manifest = {
                "version": 1,
                "targets": [{"target": "wire", "seeds": [{"id": "..", "hex": "00"}]}],
            }

            with self.assertRaisesRegex(AssertionError, "filesystem-safe"):
                module.sync_manifest(manifest, repo, fuzz)


if __name__ == "__main__":
    unittest.main()
