#!/usr/bin/env python3
"""Unit tests for fail-closed crypto vector imports."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("import-crypto-vector-subsets.py")
SPEC = importlib.util.spec_from_file_location("import_crypto_vectors", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CryptoVectorImportTests(unittest.TestCase):
    def test_matching_digest_is_parsed(self) -> None:
        raw = b'{"ok": true}'
        url = "https://example.invalid/vectors.json"
        with mock.patch.dict(
            module.EXPECTED_SHA256,
            {url: hashlib.sha256(raw).hexdigest()},
        ), mock.patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(raw)):
            returned, value = module.fetch_json(url)

        self.assertEqual(returned, raw)
        self.assertEqual(value, {"ok": True})

    def test_digest_mismatch_is_rejected_before_json_parsing(self) -> None:
        raw = b"not-json"
        url = "https://example.invalid/vectors.json"
        with mock.patch.dict(module.EXPECTED_SHA256, {url: "0" * 64}), mock.patch.object(
            module.urllib.request, "urlopen", return_value=io.BytesIO(raw)
        ):
            with self.assertRaisesRegex(AssertionError, "digest mismatch"):
                module.fetch_json(url)

    def test_unpinned_source_is_rejected(self) -> None:
        url = "https://example.invalid/unpinned.json"
        with mock.patch.object(
            module.urllib.request, "urlopen", return_value=io.BytesIO(b"{}")
        ):
            with self.assertRaisesRegex(AssertionError, "no pinned digest"):
                module.fetch_json(url)


if __name__ == "__main__":
    unittest.main()
