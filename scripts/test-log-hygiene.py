#!/usr/bin/env python3
"""Unit tests for the Maverick logging hygiene scanner."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_log_hygiene_module():
    script = Path(__file__).resolve().with_name("log-hygiene.py")
    spec = importlib.util.spec_from_file_location("log_hygiene", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LOG_HYGIENE = load_log_hygiene_module()


class LogHygieneTests(unittest.TestCase):
    def scan(self, source: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text(source, encoding="utf-8")
            findings: list[str] = []
            LOG_HYGIENE.scan_file(path, findings)
            return findings

    def test_safe_logging_has_no_findings(self) -> None:
        findings = self.scan(
            'tracing::info!(listen = %addr, "Maverick server listening");\n'
        )

        self.assertEqual(findings, [])

    def test_auth_tag_in_multiline_logging_macro_is_rejected(self) -> None:
        findings = self.scan(
            """tracing::debug!(
    auth_tag = ?hello.auth_tag,
    "auth failed"
);
"""
        )

        self.assertTrue(any("auth_tag" in item for item in findings))

    def test_credential_hint_in_logging_macro_is_rejected(self) -> None:
        findings = self.scan(
            'warn!(credential_hint = ?hello.credential_hint, "bad hint");\n'
        )

        self.assertTrue(any("credential_hint" in item for item in findings))

    def test_payload_in_logging_macro_is_rejected(self) -> None:
        findings = self.scan(
            'debug!(payload = ?frame.payload, "relay frame failed");\n'
        )

        self.assertTrue(any("payload" in item for item in findings))

    def test_secret_in_logging_macro_is_rejected(self) -> None:
        findings = self.scan(
            'error!(secret = %config.server.secret, "config failed");\n'
        )

        self.assertTrue(any("secret" in item for item in findings))

    def test_tracing_event_macro_is_rejected(self) -> None:
        findings = self.scan(
            'tracing::event!(tracing::Level::WARN, credential_id = %id, "bad credential");\n'
        )

        self.assertTrue(any("credential_id" in item for item in findings))

    def test_non_logging_auth_code_is_allowed(self) -> None:
        findings = self.scan(
            """let auth_tag = client_auth_tag(secret, transcript);
let credential_hint = hello.credential_hint.clone();
"""
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
