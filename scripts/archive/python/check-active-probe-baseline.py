#!/usr/bin/env python3
"""Validate the pinned active-probe evidence and an optional current report."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


EXPECTED_SCENARIOS = {
    "static_malformed_matches_ordinary",
    "static_bad_auth_matches_ordinary",
    "reverse_proxy_ordinary_matches_origin",
    "reverse_proxy_get_path_query_headers_matches_origin",
    "reverse_proxy_head_matches_origin",
    "reverse_proxy_put_body_matches_origin",
    "reverse_proxy_patch_body_matches_origin",
    "reverse_proxy_delete_body_matches_origin",
    "reverse_proxy_options_matches_origin",
    "reverse_proxy_malformed_matches_origin",
    "reverse_proxy_bad_auth_matches_origin",
    "reverse_proxy_rate_limited_bad_auth_matches_first",
    "reverse_proxy_upstream_failure_is_generic_502",
}
EXPECTED_COVERAGE = {
    "H2 static fallback response shape": "measured",
    "H2 reverse-proxy response shape": "measured",
    "fallback admission exhaustion": "integration_regression",
    "TLS server fingerprint and ALPN parity": "measured_separately",
    "WebSocket fallback parity": "known_difference",
    "H3 fallback parity": "feature_gated_regression",
    "HTTPS reverse-proxy upstream": "unsupported_evaluated",
    "streaming bodies and trailers": "bounded_buffering_residual",
    "timing distribution parity": "measured_no_parity_claim",
}
TIMING_ID = "direct_origin_vs_maverick_reverse_proxy_loopback"


class BaselineError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} must contain a JSON object")
    return data


def index_unique(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    indexed = {item.get(key): item for item in items}
    require(None not in indexed, f"an item is missing {key}")
    require(len(indexed) == len(items), f"duplicate {key}")
    return indexed


def validate_timing(timing: dict[str, Any]) -> None:
    require(timing.get("id") == TIMING_ID, "unexpected timing comparison")
    require(timing.get("sample_count", 0) >= 12, "too few timing samples")
    require(timing.get("parity_claim") is False, "timing parity was claimed")
    for side in ("reference", "observed"):
        stats = timing.get(side, {})
        values = [
            stats.get("min_micros"),
            stats.get("median_micros"),
            stats.get("p95_micros"),
            stats.get("max_micros"),
        ]
        require(
            all(isinstance(value, int) and not isinstance(value, bool) for value in values),
            f"{side} timing stats are not integers",
        )
        require(
            0 < values[0] <= values[1] <= values[2] <= values[3],
            f"{side} timing stats are unordered",
        )


def validate_evidence(data: dict[str, Any], *, pinned_revision: bool = True) -> None:
    require(data.get("schema_version") == 2, "unexpected active-probe schema")
    require(
        data.get("safety_scope")
        == "loopback listeners and OS-assigned ephemeral ports only",
        "active-probe evidence is not loopback-scoped",
    )
    revision = data.get("git_revision", "")
    if pinned_revision:
        require(
            bool(re.fullmatch(r"[0-9a-f]{12}", revision)),
            "invalid implementation revision",
        )
    else:
        require(
            revision == "unknown" or bool(re.fullmatch(r"[0-9a-f]{12}", revision)),
            "invalid current implementation revision",
        )
    require(
        data.get("claims")
        == {
            "perfect_origin_indistinguishability": False,
            "censorship_resistance": False,
        },
        "active-probe non-claim boundary drifted",
    )

    scenarios = index_unique(data.get("scenarios", []), "id")
    require(set(scenarios) == EXPECTED_SCENARIOS, "active-probe scenario set drifted")
    require(
        all(
            scenario.get("equal_response_shape") is True
            and scenario.get("differences") == []
            and scenario.get("fallback_kind") in {"static", "reverse_proxy"}
            for scenario in scenarios.values()
        ),
        "an active-probe response-shape gate failed",
    )

    coverage = index_unique(data.get("coverage", []), "surface")
    require(set(coverage) == set(EXPECTED_COVERAGE), "active-probe coverage set drifted")
    require(
        all(
            coverage[surface].get("status") == status
            and bool(coverage[surface].get("reason"))
            for surface, status in EXPECTED_COVERAGE.items()
        ),
        "an active-probe coverage status or reason drifted",
    )

    timings = data.get("timing_distributions", [])
    require(len(timings) == 1, "unexpected timing distribution count")
    validate_timing(timings[0])


def validate_current(baseline: dict[str, Any], current: dict[str, Any]) -> None:
    validate_evidence(current, pinned_revision=False)
    require(current["claims"] == baseline["claims"], "current claims differ from baseline")
    require(current["scenarios"] == baseline["scenarios"], "current scenario outcomes drifted")
    require(current["coverage"] == baseline["coverage"], "current coverage boundaries drifted")
    baseline_timing = baseline["timing_distributions"][0]
    current_timing = current["timing_distributions"][0]
    for field in ("id", "sample_count", "parity_claim"):
        require(current_timing[field] == baseline_timing[field], f"current timing {field} drifted")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("test-vectors/stealth/active-probe-baseline.json"),
    )
    parser.add_argument("--current-summary", type=Path)
    args = parser.parse_args()

    baseline = read_json(args.baseline)
    validate_evidence(baseline)
    if args.current_summary is not None:
        validate_current(baseline, read_json(args.current_summary))
    print("active-probe baseline OK")


if __name__ == "__main__":
    main()
