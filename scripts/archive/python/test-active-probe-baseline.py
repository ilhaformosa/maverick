#!/usr/bin/env python3
"""Unit checks for the active-probe evidence validator."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-active-probe-baseline.py")
BASELINE = SCRIPT.parent.parent / "test-vectors/stealth/active-probe-baseline.json"
SPEC = importlib.util.spec_from_file_location("check_active_probe_baseline", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load check-active-probe-baseline.py")
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
    MODULE.validate_evidence(baseline)

    failed_shape = copy.deepcopy(baseline)
    failed_shape["scenarios"][0]["equal_response_shape"] = False
    failed_shape["scenarios"][0]["differences"] = ["status"]
    expect_failure(lambda: MODULE.validate_evidence(failed_shape))

    stronger_claim = copy.deepcopy(baseline)
    stronger_claim["claims"]["perfect_origin_indistinguishability"] = True
    expect_failure(lambda: MODULE.validate_evidence(stronger_claim))

    hidden_residual = copy.deepcopy(baseline)
    hidden_residual["coverage"][4]["status"] = "measured"
    expect_failure(lambda: MODULE.validate_evidence(hidden_residual))

    timing_claim = copy.deepcopy(baseline)
    timing_claim["timing_distributions"][0]["parity_claim"] = True
    expect_failure(lambda: MODULE.validate_evidence(timing_claim))

    current = copy.deepcopy(baseline)
    current["generated_at_utc"] = "later"
    current["git_revision"] = "unknown"
    current["timing_distributions"][0]["reference"]["median_micros"] += 1
    MODULE.validate_current(baseline, current)
    expect_failure(lambda: MODULE.validate_evidence(current))

    missing_scenario = copy.deepcopy(baseline)
    missing_scenario["scenarios"].pop()
    expect_failure(lambda: MODULE.validate_evidence(missing_scenario))
    print("active-probe baseline tests OK")


if __name__ == "__main__":
    main()
