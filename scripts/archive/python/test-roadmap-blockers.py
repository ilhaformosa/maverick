#!/usr/bin/env python3
"""Unit tests for roadmap blocker registry checks."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-roadmap-blockers.py")
SPEC = importlib.util.spec_from_file_location("check_roadmap_blockers", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class RoadmapBlockerTests(unittest.TestCase):
    def test_valid_registry_counts_statuses(self) -> None:
        with fixture_repo() as repo_root:
            result = module.check_blockers(valid_registry(), repo_root)

        self.assertEqual(result["blocked_count"], 0)
        self.assertEqual(result["deferred_count"], 0)
        self.assertEqual(result["track_count"], 1)

    def test_legacy_blocked_registry_counts_statuses(self) -> None:
        with fixture_repo() as repo_root:
            result = module.check_blockers(blocked_registry(), repo_root)

        self.assertEqual(result["blocked_count"], 1)
        self.assertEqual(result["deferred_count"], 0)

    def test_no_active_status_rejects_blocker_entries(self) -> None:
        registry = valid_registry()
        registry["blockers"] = [
            blocker(
                "ech_handshake_integration",
                "v3",
                "upstream_and_approved_host_required",
                "blocked",
            )
        ]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "requires an empty blockers"):
                module.check_blockers(registry, repo_root)

    def test_duplicate_blocker_id_is_rejected(self) -> None:
        registry = blocked_registry()
        registry["blockers"].append(dict(registry["blockers"][0]))
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "duplicate blocker id"):
                module.check_blockers(registry, repo_root)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        registry = blocked_registry()
        registry["blockers"][0]["evidence"] = ["../outside"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "unsafe relative path"):
                module.check_blockers(registry, repo_root)

    def test_missing_evidence_file_is_rejected(self) -> None:
        registry = blocked_registry()
        registry["blockers"][0]["evidence"] = ["missing.md"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing evidence path"):
                module.check_blockers(registry, repo_root)

    def test_missing_non_blocking_track_evidence_is_rejected(self) -> None:
        registry = valid_registry()
        registry["non_blocking_tracks"][0]["evidence"] = ["missing.md"]
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "missing evidence path"):
                module.check_blockers(registry, repo_root)

    def test_no_active_status_requires_non_blocking_tracks(self) -> None:
        registry = valid_registry()
        registry["non_blocking_tracks"] = []
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "at least one non-blocking"):
                module.check_blockers(registry, repo_root)

    def test_runtime_required_blocker_cannot_be_deferred(self) -> None:
        registry = blocked_registry()
        registry["blockers"][0]["status"] = "deferred"
        with fixture_repo() as repo_root:
            with self.assertRaisesRegex(AssertionError, "must remain blocked"):
                module.check_blockers(registry, repo_root)

    def test_blocker_doc_must_cover_each_registry_entry(self) -> None:
        with fixture_repo() as repo_root:
            module.check_blocker_doc(
                valid_registry(), repo_root / "docs/ROADMAP_BLOCKERS.md"
            )

    def test_blocker_doc_rejects_missing_entry(self) -> None:
        registry = blocked_registry()
        with fixture_repo() as repo_root:
            doc_path = repo_root / "docs/ROADMAP_BLOCKERS.md"
            doc_path.write_text(
                "# Roadmap Blockers\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(AssertionError, "missing ech_handshake_integration"):
                module.check_blocker_doc(registry, doc_path)

    def test_blocker_doc_rejects_stale_state(self) -> None:
        registry = blocked_registry()
        with fixture_repo() as repo_root:
            doc_path = repo_root / "docs/ROADMAP_BLOCKERS.md"
            doc = doc_path.read_text(encoding="utf-8")
            doc = doc.replace(
                "`ech_handshake_integration` (v3, blocked)",
                "`ech_handshake_integration` (v4, blocked)",
            )
            doc_path.write_text(doc, encoding="utf-8")
            with self.assertRaisesRegex(
                AssertionError, "ech_handshake_integration as \\(v3, blocked\\)"
            ):
                module.check_blocker_doc(registry, doc_path)


def valid_registry() -> dict:
    return {
        "version": 1,
        "status": "no_active_roadmap_blockers",
        "notes": "No active roadmap blockers remain.",
        "resolution_plan": "docs/BLOCKER_RESOLUTION_PLAN.md",
        "blockers": [],
        "non_blocking_tracks": [
            {
                "id": "native_ech_upstream_dependency",
                "former_blocker": "ech_handshake_integration",
                "status": "tracked_upstream",
                "workaround": "cloudflare_fronted_websocket_carrier",
                "evidence": ["evidence.md"],
                "notes": "Native ECH remains tracked upstream with a workaround.",
            }
        ],
    }


def blocked_registry() -> dict:
    return {
        "version": 1,
        "status": "blocked_external",
        "notes": "External blockers remain.",
        "blockers": [
            blocker(
                "ech_handshake_integration",
                "v3",
                "upstream_and_approved_host_required",
                "blocked",
            ),
        ],
    }


def blocker(blocker_id: str, phase: str, kind: str, status: str) -> dict:
    return {
        "id": blocker_id,
        "phase": phase,
        "kind": kind,
        "status": status,
        "required_before": ["release_gate"],
        "evidence": ["evidence.md"],
        "notes": "Still requires external state.",
    }


class fixture_repo:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        (root / "evidence.md").write_text("evidence\n", encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs/BLOCKER_RESOLUTION_PLAN.md").write_text(
            "plan\n", encoding="utf-8"
        )
        (root / "docs/ROADMAP_BLOCKERS.md").write_text(
            blocker_doc(), encoding="utf-8"
        )
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


def blocker_doc() -> str:
    return "\n".join(
        [
            "# Roadmap Blockers",
            "",
            "- `ech_handshake_integration` (v3, blocked): upstream support.",
            "",
        ]
    )


if __name__ == "__main__":
    unittest.main()
