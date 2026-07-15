#!/usr/bin/env python3
"""Unit tests for the S2 evidence collector."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts/s2-evidence-collect.sh"


class S2EvidenceCollectTests(unittest.TestCase):
    def test_rejects_local_client_host_before_ssh(self) -> None:
        result = run_collect("localhost", "/tmp/maverick-run", "longhaul")

        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing S2 evidence collection from local host", result.stderr)

    def test_rejects_non_absolute_remote_dir(self) -> None:
        result = run_collect("approved-client", "relative/run", "longhaul")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote client dir must be an absolute path", result.stderr)

    def test_rejects_unsafe_label(self) -> None:
        result = run_collect("approved-client", "/tmp/maverick-run", "../bad")

        self.assertEqual(result.returncode, 2)
        self.assertIn("label may contain only", result.stderr)

    def test_fake_ssh_and_scp_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as output_root, fake_remote_tools() as tools:
            result = run_collect(
                "approved-client",
                "/tmp/maverick-run",
                "longhaul",
                {
                    "MAVERICK_S2_COLLECT_SSH_BIN": str(tools.ssh),
                    "MAVERICK_S2_COLLECT_SCP_BIN": str(tools.scp),
                    "MAVERICK_S2_COLLECTION_ROOT": output_root,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("s2_evidence_collection=ok", result.stdout)
            self.assertIn("remote_marker=completed", result.stdout)
            self.assertIn("audit_status=diagnostic_only", result.stdout)
            output_line = next(
                line for line in result.stdout.splitlines() if line.startswith("output_dir=")
            )
            output_dir = Path(output_line.split("=", 1)[1])
            self.assertEqual((output_dir / "SUMMARY.md").read_text(), "summary ok\n")
            self.assertEqual((output_dir / "events.log").read_text(), "PASS 1\n")
            self.assertEqual(
                (output_dir / "client-logs/logs/client-1.log").read_text(),
                "client log ok\n",
            )
            collection = (output_dir / "COLLECTION.md").read_text()
            self.assertIn("label: longhaul", collection)
            self.assertIn("approved_client: redacted-approved-client", collection)
            self.assertIn("remote_marker: completed", collection)
            private_collection = (output_dir / "PRIVATE_COLLECTION.md").read_text()
            self.assertIn("approved_client_host: approved-client", private_collection)
            self.assertTrue((output_dir / "EVIDENCE_AUDIT.json").is_file())
            self.assertTrue((output_dir / "EVIDENCE_AUDIT.md").is_file())
            self.assertTrue((output_dir / "EVIDENCE_MANIFEST.sha256").is_file())


def run_collect(
    host: str,
    remote_dir: str,
    label: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(SCRIPT), host, remote_dir, label],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class fake_remote_tools:
    def __enter__(self) -> "fake_remote_tools":
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.ssh = root / "ssh"
        self.scp = root / "scp"
        self.ssh.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import io
                import sys
                import tarfile

                args = sys.argv[1:]
                if args and args[0] == "-G":
                    print("hostname 198.51.100.20")
                    raise SystemExit(0)

                script = sys.stdin.read()
                if "hostname -f" in script:
                    print("approved-client-remote")
                    raise SystemExit(0)
                if "tar --null" in script:
                    data = io.BytesIO()
                    with tarfile.open(fileobj=data, mode="w:gz") as archive:
                        payload = b"client log ok\\n"
                        info = tarfile.TarInfo("logs/client-1.log")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    sys.stdout.buffer.write(data.getvalue())
                    raise SystemExit(0)
                if "test -d logs || find . -maxdepth 1 -type f -name '*.log' ! -name 'events.log'" in script:
                    raise SystemExit(0)
                if "test -f" in script and (
                    "orchestrator.log" in script or "run.log" in script
                ):
                    raise SystemExit(1)
                if "completed.marker" in script:
                    print("completed")
                raise SystemExit(0)
                """
            ),
            encoding="utf-8",
        )
        self.scp.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import pathlib
                import sys

                source = sys.argv[-2]
                destination = pathlib.Path(sys.argv[-1])
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.endswith("/SUMMARY.md"):
                    destination.write_text("summary ok\\n", encoding="utf-8")
                elif source.endswith("/events.log"):
                    destination.write_text("PASS 1\\n", encoding="utf-8")
                elif source.endswith("/logs"):
                    log_dir = destination / "logs"
                    log_dir.mkdir(parents=True, exist_ok=True)
                    (log_dir / "client-1.log").write_text("client log ok\\n", encoding="utf-8")
                else:
                    raise SystemExit(f"unexpected source: {source}")
                """
            ),
            encoding="utf-8",
        )
        self.ssh.chmod(self.ssh.stat().st_mode | stat.S_IXUSR)
        self.scp.chmod(self.scp.stat().st_mode | stat.S_IXUSR)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
