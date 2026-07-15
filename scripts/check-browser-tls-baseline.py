#!/usr/bin/env python3
"""Validate the pinned browser-TLS evidence and optional current lab summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


EXPECTED_TARGET = {
    "browser_family": "Google Chrome",
    "browser_version": "150.0.7871.115",
    "browser_mode": "headless",
    "platform": "macOS arm64",
}
EXPECTED_RESIDUALS = {
    "tls_extension_set",
    "tls_signature_algorithm_order_or_values",
}
EXPECTED_BUILD_TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
}


class BaselineError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} must contain a JSON object")
    return data


def validate_baseline(data: dict[str, Any]) -> None:
    require(data.get("schema_version") == 1, "unexpected baseline schema version")
    require(data.get("evidence_kind") == "browser_tls_reference", "wrong evidence kind")
    require(data.get("target") == EXPECTED_TARGET, "browser target drifted")
    require(
        data.get("safety_scope")
        == "loopback listeners and OS-assigned ephemeral ports only",
        "browser evidence is not loopback-scoped",
    )

    capture = data.get("capture", {})
    require(capture.get("kind") == "loopback_browser_process", "wrong capture kind")
    require(capture.get("sample_count", 0) >= 5, "fewer than five browser samples")
    for field in ("raw_capture_committed", "browser_path_committed", "sni_value_committed"):
        require(capture.get(field) is False, f"private capture field is not false: {field}")

    mimic = data.get("browser_mimic", {})
    reference = data.get("browser_reference", {})
    require(mimic.get("tls_channel_binding_available") is True, "channel binding unavailable")
    require(len(mimic.get("tls_normalized_set_sha256", [])) == 1, "mimic TLS is unstable")
    require(len(mimic.get("h2_normalized_sha256", [])) == 1, "mimic H2 is unstable")
    require(len(reference.get("tls_normalized_set_sha256", [])) == 1, "reference TLS is unstable")
    require(len(reference.get("h2_normalized_sha256", [])) == 1, "reference H2 is unstable")

    comparison = data.get("comparison", {})
    require(comparison.get("tls_normalized_set_match") is False, "TLS residuals disappeared without review")
    require(comparison.get("h2_normalized_match") is True, "H2 no longer matches the reference")
    residuals = comparison.get("residuals", [])
    residual_ids = {residual.get("id") for residual in residuals}
    require(residual_ids == EXPECTED_RESIDUALS, "browser TLS residual set drifted")
    require(
        all(
            residual.get("status") == "not_controllable_with_current_binding"
            and bool(residual.get("reason"))
            for residual in residuals
        ),
        "browser TLS residuals are not fully explained",
    )

    targets = data.get("supported_build_targets", [])
    require({target.get("target") for target in targets} == EXPECTED_BUILD_TARGETS, "build target set drifted")
    require(all(target.get("status") == "passed" for target in targets), "a supported build target has not passed")

    claims = data.get("claims", {})
    require(claims, "claims boundary is missing")
    require(all(value is False for value in claims.values()), "baseline contains a stronger unsupported claim")


def validate_current_summary(
    baseline: dict[str, Any], current: dict[str, Any]
) -> None:
    require(current.get("schema_version") == 2, "unexpected current summary schema")
    profiles = current.get("profiles", [])
    mimic = next(
        (profile for profile in profiles if profile.get("name") == "browser_mimic"),
        None,
    )
    require(mimic is not None, "current summary has no browser_mimic profile")
    require(mimic.get("status") == "observed", "browser_mimic was not observed")
    require(mimic.get("tls_channel_binding_available") is True, "current channel binding unavailable")
    expected = baseline["browser_mimic"]
    require(
        mimic.get("tls_normalized_set_sha256")
        == expected["tls_normalized_set_sha256"],
        "current browser-mimic TLS hash drifted",
    )
    require(
        mimic.get("h2_normalized_sha256") == expected["h2_normalized_sha256"],
        "current browser-mimic H2 hash drifted",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("test-vectors/stealth/browser-tls-chrome-150-macos-arm64.json"),
    )
    parser.add_argument("--current-summary", type=Path)
    args = parser.parse_args()

    baseline = read_json(args.baseline)
    validate_baseline(baseline)
    if args.current_summary is not None:
        validate_current_summary(baseline, read_json(args.current_summary))
    print("browser TLS baseline OK")


if __name__ == "__main__":
    main()
