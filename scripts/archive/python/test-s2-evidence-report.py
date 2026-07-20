#!/usr/bin/env python3
"""Unit tests for the S2 evidence report generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts/s2-evidence-report.py"
SPEC = importlib.util.spec_from_file_location("s2_evidence_report", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class S2EvidenceReportTests(unittest.TestCase):
    def test_generates_redacted_report_from_collected_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            longhaul = fixture_run(
                root,
                "longhaul",
                {
                    "run_id": "longhaul-20260706T000000Z",
                    "tested_commit": "long123",
                    "started_utc": "2026-07-06T00:00:00Z",
                    "finished_utc": "2026-07-07T00:00:00Z",
                    "duration_secs": "86400",
                    "interval_secs": "300",
                    "iterations": "288",
                    "passed": "288",
                    "failed": "0",
                },
                "PASS 1\nPASS 2\n",
            )
            netem = fixture_run(
                root,
                "netem",
                {
                    "run_id": "netem-20260706T000000Z",
                    "tested_commit": "netem123",
                    "scenario_profile": "8h-v2",
                    "iterations": "96",
                    "passed": "96",
                    "failed": "0",
                    "default_route_unchanged": "true",
                    "global_dns_unchanged": "true",
                },
                "PASS scenario=baseline\nPASS scenario=loss_1pct\nremote_residue=absent\n",
            )
            failure = fixture_run(
                root,
                "failure-injection",
                {
                    "run_id": "failure-20260706T000000Z",
                    "server_commit": "failure123",
                    "client_commit": "failure123",
                    "checks": "11",
                    "pass_results": "8",
                    "controlled_connect_failures": "2",
                    "controlled_stall_results": "1",
                    "controlled_fallback_failures": "1",
                },
                "\n".join(
                    [
                        "CHECK scenario=server_restart result=pass",
                        "CHECK scenario=server_restart result=connect_fail",
                        "CHECK scenario=upstream_stall_timeout result=stall_closed",
                    ]
                ),
            )
            output = root / "report.md"

            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--longhaul",
                    str(longhaul),
                    "--netem",
                    str(netem),
                    "--failure-injection",
                    str(failure),
                    "--output",
                    str(output),
                    "--date",
                    "2026-07-07",
                    "--commit",
                    "abc1234",
                    "--require-audited",
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = output.read_text(encoding="utf-8")
            self.assertIn("# S2 Independent Evidence - 2026-07-07", report)
            self.assertIn("- tested commits/builds: see per-run provenance below", report)
            self.assertIn("- longhaul: `long123`", report)
            self.assertIn("- netem: `netem123`", report)
            self.assertIn("- failure-injection: `failure123`", report)
            self.assertIn("- run_id: `longhaul-20260706T000000Z`", report)
            self.assertIn("- remote_residue: `absent`", report)
            self.assertIn("- controlled_fallback_failures: `1`", report)
            self.assertIn("| netem | 3 | 2 | 0 | 0 | 0 | 0 |", report)
            self.assertIn("| failure-injection | 3 | 1 | 0 | 1 | 1 | 0 |", report)

    def test_require_audited_refuses_stale_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs = {
                label: fixture_run(
                    root,
                    label,
                    {"run_id": label, "passed": "1", "failed": "0"},
                    "PASS 1\n",
                )
                for label in ("longhaul", "netem", "failure-injection")
            }
            (runs["longhaul"] / "events.log").write_text(
                "PASS 1\nPASS changed-after-audit\n", encoding="utf-8"
            )

            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--longhaul",
                    str(runs["longhaul"]),
                    "--netem",
                    str(runs["netem"]),
                    "--failure-injection",
                    str(runs["failure-injection"]),
                    "--output",
                    str(root / "report.md"),
                    "--require-audited",
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("manifest hash mismatch", result.stderr)

    def test_refuses_private_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            longhaul = fixture_run(
                root,
                "longhaul",
                {"run_id": "ok", "passed": "1", "failed": "0"},
                "PASS 1\n",
            )
            netem = fixture_run(
                root,
                "netem",
                {"run_id": "ok", "passed": "1", "failed": "0"},
                "PASS 1\n",
            )
            failure = fixture_run(
                root,
                "failure-injection",
                {"run_id": "ok", "passed": "1", "failed": "0"},
                "secret: " + "mv1_" + "this_secret_is_long_enough_to_fail_the_scan\n",
            )

            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--longhaul",
                    str(longhaul),
                    "--netem",
                    str(netem),
                    "--failure-injection",
                    str(failure),
                    "--output",
                    str(root / "report.md"),
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private pattern refused", result.stderr)
            self.assertNotIn("mv1_", result.stderr)

    def test_refuses_generic_private_paths_and_addresses_without_reflection(self) -> None:
        samples = (
            "/Users/example/private/file.log",
            "/home/operator/private/file.log",
            "host_address=203.0.113.25",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaises(SystemExit) as raised:
                    module.assert_public_safe(sample)
                self.assertNotIn(sample, str(raised.exception))

    def test_external_private_marker_is_refused_without_embedding_or_reflection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker_file = Path(tmp) / "markers.txt"
            marker = "private-host-marker.example"
            marker_file.write_text(marker + "\n", encoding="utf-8")
            old = os.environ.get("MAVERICK_PRIVATE_MARKERS_FILE")
            os.environ["MAVERICK_PRIVATE_MARKERS_FILE"] = str(marker_file)
            try:
                with self.assertRaises(SystemExit) as raised:
                    module.assert_public_safe(f"host={marker}")
            finally:
                if old is None:
                    os.environ.pop("MAVERICK_PRIVATE_MARKERS_FILE", None)
                else:
                    os.environ["MAVERICK_PRIVATE_MARKERS_FILE"] = old
            self.assertIn("external private marker", str(raised.exception))
            self.assertNotIn(marker, str(raised.exception))


def fixture_run(
    root: Path,
    label: str,
    values: dict[str, str],
    events: str,
) -> Path:
    path = root / label
    path.mkdir()
    lines = [f"- label: {label}"]
    lines.extend(f"- {key}: {value}" for key, value in values.items())
    (path / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (path / "events.log").write_text(events, encoding="utf-8")
    (path / "COLLECTION.md").write_text(
        f"# S2 Evidence Collection\n\n- label: {label}\n- remote_marker: completed\n",
        encoding="utf-8",
    )
    write_accepted_audit(path, label)
    return path


def write_accepted_audit(path: Path, label: str) -> None:
    (path / "EVIDENCE_AUDIT.json").write_text(
        json.dumps({"status": "accepted", "kind": label}) + "\n",
        encoding="utf-8",
    )
    entries = []
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        if item.name in {
            "EVIDENCE_AUDIT.json",
            "EVIDENCE_AUDIT.md",
            "EVIDENCE_MANIFEST.sha256",
        }:
            continue
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        entries.append(f"{digest}  {item.relative_to(path).as_posix()}\n")
    (path / "EVIDENCE_MANIFEST.sha256").write_text("".join(entries), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
