#!/usr/bin/env python3
"""Unit tests for the S2 evidence preflight wrapper."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts/s2-evidence-preflight.sh"


class S2EvidencePreflightTests(unittest.TestCase):
    def test_rejects_local_server_host_before_ssh(self) -> None:
        result = run_preflight("localhost")

        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing S2 preflight against local host", result.stderr)

    def test_requires_netem_approval_by_default(self) -> None:
        with fake_ssh() as ssh:
            result = run_preflight(
                "approved-server",
                {
                    "MAVERICK_S2_PREFLIGHT_SSH_BIN": str(ssh),
                    "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT": "1",
                },
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("MAVERICK_NETEM_IMPAIRMENT_APPROVED=1", result.stderr)

    def test_fake_ssh_happy_path(self) -> None:
        with fake_ssh() as ssh:
            result = run_preflight(
                "approved-server",
                {
                    "MAVERICK_S2_PREFLIGHT_SSH_BIN": str(ssh),
                    "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT": "1",
                    "MAVERICK_NETEM_IMPAIRMENT_APPROVED": "1",
                },
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("netem_check=ok", result.stdout)
        self.assertIn("s2_evidence_preflight=ok", result.stdout)

    def test_netem_can_be_skipped_explicitly(self) -> None:
        with fake_ssh() as ssh:
            result = run_preflight(
                "approved-server",
                {
                    "MAVERICK_S2_PREFLIGHT_SSH_BIN": str(ssh),
                    "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT": "1",
                    "MAVERICK_S2_PREFLIGHT_CHECK_NETEM": "0",
                },
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("netem_check=skipped", result.stdout)


def run_preflight(
    server_host: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR": "203.0.113.10",
            "MAVERICK_PUBLIC_SMOKE_SERVER_NAME": "example.invalid",
            "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST": "approved-client",
            "MAVERICK_PUBLIC_SMOKE_REMOTE_CERT": "/etc/example/fullchain.pem",
            "MAVERICK_PUBLIC_SMOKE_REMOTE_KEY": "/etc/example/privkey.pem",
        }
    )
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(SCRIPT), server_host],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class fake_ssh:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        path = Path(self._tmp.name) / "ssh"
        path.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import sys

                args = sys.argv[1:]
                if args and args[0] == "-G":
                    host = args[1]
                    if host == "approved-server":
                        print("hostname 198.51.100.20")
                    elif host == "approved-client":
                        print("hostname 198.51.100.21")
                    else:
                        print("hostname 198.51.100.22")
                    raise SystemExit(0)

                host = None
                idx = 0
                while idx < len(args):
                    arg = args[idx]
                    if arg in ("-o", "-p", "-l", "-i"):
                        idx += 2
                        continue
                    host = arg
                    break

                script = sys.stdin.read()
                if "hostname -f" in script:
                    if host == "approved-server":
                        print("approved-server-remote")
                    elif host == "approved-client":
                        print("approved-client-remote")
                    else:
                        print(f"{host}-remote")
                    raise SystemExit(0)

                raise SystemExit(0)
                """
            ),
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
