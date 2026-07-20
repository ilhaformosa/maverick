#!/usr/bin/env python3
"""Unit tests for the frozen conformance release policy checker."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import check_frozen_releases


class FrozenReleasePolicyTests(unittest.TestCase):
    def test_empty_policy_is_valid_before_first_frozen_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = {
                "version": 1,
                "status": "no-frozen-releases",
                "frozen_releases": [],
            }

            self.assertEqual(check_frozen_releases.check_policy(policy, root), 0)

    def test_frozen_release_validates_manifest_and_vector_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vector_path = root / "vectors" / "frame.json"
            vector_path.parent.mkdir()
            vector_path.write_bytes(b'{"id":"frame"}\n')
            manifest_path = root / "frozen-releases" / "v1" / "manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = {
                "release": "v1",
                "vectors": [
                    {
                        "path": "vectors/frame.json",
                        "sha256": check_frozen_releases.sha256(vector_path),
                    }
                ],
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            policy = {
                "version": 1,
                "status": "active",
                "frozen_releases": [
                    {
                        "release": "v1",
                        "manifest_path": "frozen-releases/v1/manifest.json",
                        "manifest_sha256": check_frozen_releases.sha256(manifest_path),
                    }
                ],
            }

            self.assertEqual(check_frozen_releases.check_policy(policy, root), 1)

    def test_changed_frozen_vector_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vector_path = root / "vectors" / "frame.json"
            vector_path.parent.mkdir()
            vector_path.write_bytes(b"old")
            manifest_path = root / "frozen-releases" / "v1" / "manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = {
                "release": "v1",
                "vectors": [
                    {
                        "path": "vectors/frame.json",
                        "sha256": check_frozen_releases.sha256(vector_path),
                    }
                ],
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            policy = {
                "version": 1,
                "status": "active",
                "frozen_releases": [
                    {
                        "release": "v1",
                        "manifest_path": "frozen-releases/v1/manifest.json",
                        "manifest_sha256": check_frozen_releases.sha256(manifest_path),
                    }
                ],
            }
            vector_path.write_bytes(b"new")

            with self.assertRaisesRegex(AssertionError, "frozen vector sha256 mismatch"):
                check_frozen_releases.check_policy(policy, root)

    def test_unsafe_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = {
                "version": 1,
                "status": "active",
                "frozen_releases": [
                    {
                        "release": "v1",
                        "manifest_path": "../manifest.json",
                        "manifest_sha256": "0" * 64,
                    }
                ],
            }

            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                check_frozen_releases.check_policy(policy, root)


if __name__ == "__main__":
    unittest.main()
