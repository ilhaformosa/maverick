#!/usr/bin/env python3
"""Unit checks for budget-aware CI path classification."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).with_name("ci-change-scope.py")
SPEC = importlib.util.spec_from_file_location("ci_change_scope", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load ci-change-scope.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    assert MODULE.classify(["README.md"]) == {
        "h3": False,
        "ech": False,
        "shape": False,
        "browser": False,
    }
    assert MODULE.classify(["scripts/h3-harness.sh"]) == {
        "h3": True,
        "ech": False,
        "shape": False,
        "browser": False,
    }
    assert MODULE.classify(["crates/maverick-core/src/ech.rs"]) == {
        "h3": False,
        "ech": True,
        "shape": False,
        "browser": False,
    }
    assert MODULE.classify(["scripts/shape-lab.sh"]) == {
        "h3": False,
        "ech": False,
        "shape": True,
        "browser": False,
    }
    assert MODULE.classify(["crates/maverick-client/src/tunnel.rs"]) == {
        "h3": True,
        "ech": False,
        "shape": True,
        "browser": True,
    }
    assert MODULE.classify(["Cargo.lock"]) == {
        "h3": True,
        "ech": True,
        "shape": True,
        "browser": True,
    }
    assert MODULE.classify([]) == {
        "h3": True,
        "ech": True,
        "shape": True,
        "browser": True,
    }
    assert MODULE.classify(["crates/maverick-client/src/h2_transport.rs"]) == {
        "h3": True,
        "ech": True,
        "shape": False,
        "browser": True,
    }
    assert MODULE.classify(["docs/STEALTH_MEASUREMENT.md"]) == {
        "h3": False,
        "ech": False,
        "shape": False,
        "browser": False,
    }
    assert MODULE.classify(["test-vectors/stealth/fingerprint-baseline.json"]) == {
        "h3": False,
        "ech": False,
        "shape": False,
        "browser": True,
    }
    print("ci change scope tests OK")


if __name__ == "__main__":
    main()
