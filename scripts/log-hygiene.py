#!/usr/bin/env python3
"""Scan Rust logging macro blocks for sensitive Maverick auth material."""

from __future__ import annotations

from pathlib import Path


LOG_MACROS = (
    "event!",
    "trace!",
    "debug!",
    "info!",
    "warn!",
    "error!",
    "tracing::trace!",
    "tracing::debug!",
    "tracing::info!",
    "tracing::warn!",
    "tracing::error!",
    "tracing::event!",
    "log::trace!",
    "log::debug!",
    "log::info!",
    "log::warn!",
    "log::error!",
)

SENSITIVE_PATTERNS = (
    "expose_secret",
    "secret",
    "payload",
    "request_body",
    "body",
    "auth_tag",
    "server_auth_tag",
    "credential_hint",
    "credential_id",
    "client_nonce",
    "replay_key",
)


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    findings: list[str] = []
    for path in sorted((repo / "crates").rglob("*.rs")):
        scan_file(path, findings)
    if findings:
        raise SystemExit("\n".join(findings))
    print("log hygiene OK")


def scan_file(path: Path, findings: list[str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        macro = next((name for name in LOG_MACROS if name in line), None)
        if macro is None:
            idx += 1
            continue

        start = idx
        block = [line]
        balance = line.count("(") - line.count(")")
        idx += 1
        while balance > 0 and idx < len(lines):
            block.append(lines[idx])
            balance += lines[idx].count("(") - lines[idx].count(")")
            idx += 1

        text = "\n".join(block)
        for pattern in SENSITIVE_PATTERNS:
            if pattern in text:
                findings.append(f"{path}:{start + 1}: logging macro contains sensitive pattern `{pattern}`")


if __name__ == "__main__":
    main()
