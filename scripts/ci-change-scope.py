#!/usr/bin/env python3
"""Classify changed paths for the single-platform public PR gate."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable


SCOPES = ("core", "h3", "ech", "shape", "browser")
EXISTING_OPTIONAL_SCOPES = ("h3", "ech", "shape")


def classify(paths: Iterable[str]) -> dict[str, bool]:
    normalized = tuple(
        path.strip().removeprefix("./") for path in paths if path.strip()
    )
    if not normalized:
        return {scope: True for scope in SCOPES}

    result = {scope: False for scope in SCOPES}
    for path in normalized:
        if affects_core(path):
            result["core"] = True
        if affects_all_optional_jobs(path):
            for scope in EXISTING_OPTIONAL_SCOPES:
                result[scope] = True
        if affects_h3(path):
            result["h3"] = True
        if affects_ech(path):
            result["ech"] = True
        if affects_shape(path):
            result["shape"] = True
        if affects_browser(path):
            result["browser"] = True
    return result


def affects_core(path: str) -> bool:
    return not (
        path.endswith(".md")
        or path.startswith(".github/ISSUE_TEMPLATE/")
        or path == ".github/CODEOWNERS"
    )


def affects_all_optional_jobs(path: str) -> bool:
    return (
        path in {
            "Cargo.toml",
            "Cargo.lock",
            ".github/workflows/ci.yml",
            "scripts/ci-change-scope.py",
            "scripts/test-ci-change-scope.py",
            "crates/maverick-server/src/server.rs",
        }
        or path.endswith("/Cargo.toml")
        or path.startswith("crates/maverick-tests/")
        or path
        in {
            "crates/maverick-core/src/auth.rs",
            "crates/maverick-core/src/config.rs",
            "crates/maverick-core/src/frame.rs",
            "crates/maverick-core/src/grpc.rs",
        }
    )


def affects_h3(path: str) -> bool:
    return (
        path.startswith("crates/maverick-client/src/")
        or path
        in {
            "crates/maverick-core/src/padding.rs",
            "scripts/h3-harness.sh",
        }
        or path.startswith("crates/maverick-server/src/h3")
    )


def affects_ech(path: str) -> bool:
    return path in {
        "crates/maverick-core/src/diagnostics.rs",
        "crates/maverick-core/src/ech.rs",
        "crates/maverick-client/src/h2_transport.rs",
        "crates/maverick-client/src/transport.rs",
        "crates/maverick-client/src/ws_transport.rs",
        "crates/maverick-server/src/h2_acceptor.rs",
        "scripts/ech-harness.sh",
    }


def affects_shape(path: str) -> bool:
    return path in {
        "crates/maverick-core/src/metrics.rs",
        "crates/maverick-core/src/padding.rs",
        "crates/maverick-client/src/tunnel.rs",
        "scripts/shape-lab.sh",
    }


def affects_browser(path: str) -> bool:
    return (
        path in {
            "Cargo.toml",
            "Cargo.lock",
            ".github/workflows/ci.yml",
            "scripts/browser-tls-harness.sh",
            "scripts/check-browser-tls-baseline.py",
            "scripts/ci-change-scope.py",
            "scripts/test-browser-tls-baseline.py",
            "scripts/test-ci-change-scope.py",
            "scripts/fingerprint-lab.sh",
            "crates/maverick-core/src/auth.rs",
            "crates/maverick-core/src/config.rs",
            "crates/maverick-client/src/connection_manager.rs",
            "crates/maverick-client/src/h2_transport.rs",
            "crates/maverick-client/src/transport.rs",
            "crates/maverick-client/src/tunnel.rs",
            "crates/maverick-tests/src/fingerprint.rs",
            "crates/maverick-tests/src/bin/fingerprint-lab.rs",
            "crates/maverick-tests/tests/support/mod.rs",
            "crates/maverick-tests/tests/tcp_relay.rs",
        }
        or path.endswith("/Cargo.toml")
        or path.startswith("test-vectors/stealth/")
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="enable every PR job")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    if args.all:
        result = {scope: True for scope in SCOPES}
    else:
        paths = args.paths or tuple(sys.stdin.read().splitlines())
        result = classify(paths)

    for scope in SCOPES:
        print(f"{scope}={'true' if result[scope] else 'false'}")


if __name__ == "__main__":
    main()
