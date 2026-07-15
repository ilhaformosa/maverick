#!/usr/bin/env python3
"""Unit tests for private S2 evidence auditing."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts/s2-evidence-audit.py"


class S2EvidenceAuditTests(unittest.TestCase):
    def test_accepts_complete_longhaul_and_writes_verifiable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertEqual(audit["status"], "accepted")
            self.assertEqual(audit["kind"], "longhaul")
            self.assertEqual(audit["reasons"], [])
            self.assertEqual(
                audit["resource_evidence"]["client"]["coverage_secs"], 180
            )
            manifest = collection / "EVIDENCE_MANIFEST.sha256"
            self.assertTrue(manifest.is_file())
            verify = subprocess.run(
                ["shasum", "-a", "256", "-c", manifest.name],
                cwd=collection,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_unmarked_collection_is_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "unmarked")

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertEqual(audit["status"], "diagnostic_only")
            self.assertIn("remote marker is unmarked", audit["reasons"][0])

    def test_secret_finding_blocks_acceptance_without_echoing_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")
            secret = "mv1_" + "A" * 43
            (collection / "client-logs/logs/client-1.log").write_text(secret + "\n")

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit_text = (collection / "EVIDENCE_AUDIT.json").read_text()
            self.assertNotIn(secret, audit_text)
            audit = json.loads(audit_text)
            self.assertEqual(audit["secret_findings"][0]["pattern"], "maverick_secret")

    def test_missing_final_cleanup_record_blocks_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")
            (collection / "PRIVATE_FINAL_CLEANUP.log").unlink()

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertIn("missing final remote cleanup record", audit["reasons"])

    def test_incomplete_resource_sample_blocks_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")
            metrics = collection / "client-logs/resource-metrics.log"
            metrics.write_text(
                metrics.read_text().rsplit("sample_end\n", 1)[0], encoding="utf-8"
            )

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertIn(
                "client resource sample blocks are incomplete", audit["reasons"]
            )

    def test_excessive_resource_gap_blocks_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")
            (collection / "client-logs/resource-metrics.log").write_text(
                "sample_utc=2026-07-09T00:00:00Z\n"
                "sample_end\n"
                "sample_utc=2026-07-09T00:03:00Z\n"
                "sample_end\n",
                encoding="utf-8",
            )

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertIn(
                "client resource metrics contain an excessive time gap",
                audit["reasons"],
            )

    def test_declared_child_sampling_requires_maverick_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = longhaul_fixture(Path(tmp), "completed")
            summary = collection / "SUMMARY.md"
            summary.write_text(
                summary.read_text() + "- resource_process_children: enabled\n",
                encoding="utf-8",
            )

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertIn(
                "client resource metrics contain no Maverick child process rows",
                audit["reasons"],
            )

    def test_failure_summary_count_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collection = failure_fixture(Path(tmp))

            result = run_audit(collection, require_accepted=True)

            self.assertEqual(result.returncode, 1)
            audit = json.loads((collection / "EVIDENCE_AUDIT.json").read_text())
            self.assertIn("pass_results differs from event log", audit["reasons"])


def run_audit(
    collection: Path, *, require_accepted: bool
) -> subprocess.CompletedProcess[str]:
    command = [str(SCRIPT), str(collection)]
    if require_accepted:
        command.append("--require-accepted")
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def longhaul_fixture(root: Path, marker: str) -> Path:
    collection = root / "collection"
    client = collection / "client-logs"
    server = collection / "server-logs"
    logs = client / "logs"
    logs.mkdir(parents=True)
    server.mkdir(parents=True)
    (collection / "SUMMARY.md").write_text(
        "\n".join(
            [
                "# Maverick Detached Approved-Host TCP Long-Haul",
                "",
                "- started_utc: 2026-07-09T00:00:00Z",
                "- finished_utc: 2026-07-09T00:03:00Z",
                "- duration_secs: 180",
                "- interval_secs: 60",
                "- resource_interval_secs: 60",
                "- iterations: 1",
                "- passed: 1",
                "- failed: 0",
                "- client_log_count: 1",
                "- probe_log_count: 1",
                "- failure_log_count: 0",
                "- resource_samples: 4",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (collection / "events.log").write_text("PASS iteration=1\n", encoding="utf-8")
    (collection / "COLLECTION.md").write_text(
        f"# S2 Evidence Collection\n\n- remote_marker: {marker}\n",
        encoding="utf-8",
    )
    for role in (client, server):
        (role / "binary-version.log").write_text("maverick 1.0.0\n", encoding="utf-8")
        (role / "system-inventory.log").write_text(
            "binary_sha256=" + "a" * 64 + "\n", encoding="utf-8"
        )
        (role / "resource-metrics.log").write_text(
            "".join(
                f"sample_utc=2026-07-09T00:0{minute}:00Z\nsample_end\n"
                for minute in range(4)
            ),
            encoding="utf-8",
        )
    (logs / "client-1.log").write_text("client ok\n", encoding="utf-8")
    (logs / "probe-1.log").write_text("probe ok\n", encoding="utf-8")
    (collection / "PRIVATE_FINAL_CLEANUP.log").write_text(
        "cleanup_status=ok\n", encoding="utf-8"
    )
    return collection


def failure_fixture(root: Path) -> Path:
    collection = root / "failure"
    client = collection / "client-logs"
    server = collection / "server-logs"
    client.mkdir(parents=True)
    server.mkdir(parents=True)
    (collection / "SUMMARY.md").write_text(
        "\n".join(
            [
                "# Maverick Approved-Host Failure Injection Smoke",
                "",
                "- checks: 1",
                "- pass_results: 2",
                "- controlled_connect_failures: 0",
                "- controlled_stall_results: 0",
                "- controlled_fallback_failures: 0",
                "- client_resource_samples: 1",
                "- server_resource_samples: 1",
                "- post_cleanup_ports: free",
                "- post_cleanup_firewall: closed_or_disabled",
                "- post_cleanup_credentials: absent",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (collection / "events.log").write_text(
        "CHECK scenario=baseline result=pass\n", encoding="utf-8"
    )
    (collection / "COLLECTION.md").write_text(
        "# S2 Evidence Collection\n\n- remote_marker: completed\n", encoding="utf-8"
    )
    for role in (client, server):
        (role / "binary-version.log").write_text("maverick 1.0.0\n", encoding="utf-8")
        (role / "system-inventory.log").write_text(
            "binary_sha256=" + "b" * 64 + "\n", encoding="utf-8"
        )
        (role / "resource-metrics.log").write_text(
            "sample_utc=2026-07-09T00:00:00Z\nsample_end\n", encoding="utf-8"
        )
    (collection / "PRIVATE_FINAL_CLEANUP.log").write_text(
        "cleanup_status=ok\n", encoding="utf-8"
    )
    return collection


if __name__ == "__main__":
    unittest.main()
