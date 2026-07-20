#!/usr/bin/env python3
"""Unit checks for the pinned browser-TLS evidence validator."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-browser-tls-baseline.py")
BASELINE = SCRIPT.parent.parent / "test-vectors/stealth/browser-tls-chrome-150-macos-arm64.json"
SPEC = importlib.util.spec_from_file_location("check_browser_tls_baseline", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load check-browser-tls-baseline.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect_failure(callback) -> None:
    try:
        callback()
    except MODULE.BaselineError:
        return
    raise AssertionError("validator unexpectedly accepted invalid evidence")


def main() -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    passing = copy.deepcopy(baseline)
    for target in passing["supported_build_targets"]:
        target["status"] = "passed"
    MODULE.validate_baseline(passing)

    pending_target = copy.deepcopy(passing)
    pending_target["supported_build_targets"][0]["status"] = "pending_ci"
    expect_failure(lambda: MODULE.validate_baseline(pending_target))

    wrong_h2 = copy.deepcopy(passing)
    wrong_h2["comparison"]["h2_normalized_match"] = False
    expect_failure(lambda: MODULE.validate_baseline(wrong_h2))

    stronger_claim = copy.deepcopy(passing)
    stronger_claim["claims"]["browser_equivalence"] = True
    expect_failure(lambda: MODULE.validate_baseline(stronger_claim))

    mimic = passing["browser_mimic"]
    current = {
        "schema_version": 2,
        "profiles": [
            {
                "name": "browser_mimic",
                "status": "observed",
                "tls_channel_binding_available": True,
                "tls_normalized_set_sha256": mimic["tls_normalized_set_sha256"],
                "h2_normalized_sha256": mimic["h2_normalized_sha256"],
            }
        ],
    }
    MODULE.validate_current_summary(passing, current)
    current["profiles"][0]["tls_normalized_set_sha256"] = ["drifted"]
    expect_failure(lambda: MODULE.validate_current_summary(passing, current))
    print("browser TLS baseline tests OK")


if __name__ == "__main__":
    main()
