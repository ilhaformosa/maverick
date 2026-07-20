#!/usr/bin/env python3
"""Validate the narrow Maverick production-readiness ledger."""

from __future__ import annotations

import argparse
import json
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


DIMENSIONS = (
    "code_complete",
    "evidence_complete",
    "audit_complete",
    "deployable",
    "production_ready",
)
RELEASES = ("v1.2.0-alpha.1", "v1.2.0-beta.1", "v1.2.0-rc.1", "v1.2.0")
FORMAL_PLATFORM = "Ubuntu 26.04 LTS"
REQUIRED_NON_CLAIMS = {
    "no_anonymity_guarantee",
    "no_browser_fingerprint_equivalence",
    "no_censorship_resistance_guarantee",
    "no_cross_platform_support",
    "no_h3_production_support",
    "no_ipv6_support",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RELEASE_IDENTITIES = {
    "v1.2.0-alpha.1": {
        "maverick_software": "1.2.0-alpha.1",
        "reference_software": "1.2.0-alpha.1",
        "debian_package": "1.2.0~alpha.1-1",
    },
    "v1.2.0-beta.1": {
        "maverick_software": "1.2.0-beta.1",
        "reference_software": "1.2.0-beta.1",
        "debian_package": "1.2.0~beta.1-1",
    },
    "v1.2.0-rc.1": {
        "maverick_software": "1.2.0-rc.1",
        "reference_software": "1.2.0-rc.1",
        "debian_package": "1.2.0~rc.1-1",
    },
    "v1.2.0": {
        "maverick_software": "1.2.0",
        "reference_software": "1.2.0",
        "debian_package": "1.2.0-1",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", nargs="?", default="production-readiness.json", type=Path)
    parser.add_argument("--expected-release-commit")
    parser.add_argument("--release-stage", choices=RELEASES)
    args = parser.parse_args()

    if bool(args.expected_release_commit) != bool(args.release_stage):
        parser.error("--expected-release-commit and --release-stage must be used together")

    ledger = load_json_strict(args.ledger)
    result = check_ledger(ledger, args.ledger.parent)
    if args.expected_release_commit and args.release_stage:
        check_release_candidate_request(
            ledger,
            args.expected_release_commit,
            args.release_stage,
        )
    print(
        "production readiness ledger OK: "
        f"{result['candidate_status']}, {result['decision']} "
        f"({result['complete_dimensions']}/{len(DIMENSIONS)} dimensions complete)"
    )


def check_ledger_file(ledger_path: Path) -> dict[str, int | str]:
    ledger = load_json_strict(ledger_path)
    return check_ledger(ledger, ledger_path.parent)


def load_json_strict(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=reject_duplicate_json_keys)


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def check_release_candidate_request(
    ledger: dict[str, Any], expected_release_commit: str, release_stage: str
) -> None:
    if not HEX40.fullmatch(expected_release_commit):
        raise AssertionError("release-candidate CI requires a full lowercase release commit")
    if release_stage not in RELEASES:
        raise AssertionError("release-candidate CI received an unknown release stage")

    candidate = require_mapping(ledger, "candidate")
    if candidate.get("status") != "frozen":
        raise AssertionError("release-candidate CI requires a frozen candidate")
    if candidate.get("maverick_release_commit") != expected_release_commit:
        raise AssertionError("release-candidate CI commit must match maverick_release_commit")

    versions = require_mapping(candidate, "versions")
    if versions.get("release_tag") != release_stage:
        raise AssertionError("release-candidate CI stage must match release_tag")
    for field, expected in RELEASE_IDENTITIES[release_stage].items():
        if versions.get(field) != expected:
            raise AssertionError(
                f"release-candidate CI {release_stage} requires {field} {expected!r}"
            )

    dimensions = require_mapping(ledger, "dimensions")
    complete = {
        name
        for name in DIMENSIONS
        if isinstance(dimensions.get(name), dict)
        and dimensions[name].get("status") == "complete"
    }
    audit = require_mapping(ledger, "audit")
    prerequisites = {
        "v1.2.0-alpha.1": "code_complete" in complete,
        "v1.2.0-beta.1": "evidence_complete" in complete,
        "v1.2.0-rc.1": {"audit_complete", "deployable"}.issubset(complete)
        and audit.get("remediation_complete") is True,
        # The stable candidate CI result is an input to the final GO decision,
        # so it must be runnable while production_ready is still blocked.
        "v1.2.0": {
            "code_complete",
            "evidence_complete",
            "audit_complete",
            "deployable",
        }.issubset(complete)
        and audit.get("remediation_complete") is True,
    }
    if not prerequisites[release_stage]:
        raise AssertionError(f"{release_stage}: release-candidate CI prerequisites are incomplete")

    release_gates = require_mapping(ledger, "release_gates")
    stage_index = RELEASES.index(release_stage)
    earlier = RELEASES[:stage_index]
    if any(release_gates.get(stage) != "pass" for stage in earlier):
        raise AssertionError("release-candidate CI requires every earlier release stage to pass")


def check_ledger(ledger: dict[str, Any], repo_root: Path) -> dict[str, int | str]:
    if ledger.get("schema_version") != 1:
        raise AssertionError("production readiness schema_version must be 1")

    candidate = require_mapping(ledger, "candidate")
    candidate_status = require_choice(candidate, "status", {"not_frozen", "frozen"})
    check_candidate(candidate, candidate_status, repo_root)

    scope = require_mapping(ledger, "scope")
    check_scope(scope, repo_root)

    claim_state = require_mapping(ledger, "current_claim_state")

    inputs = require_mapping(ledger, "phase_inputs")
    phase_3a = check_phase_input(inputs, "phase_3a", repo_root)
    phase_3b = check_phase_input(inputs, "phase_3b", repo_root)
    if candidate_status == "frozen":
        if phase_3b != "accepted":
            raise AssertionError("candidate freeze requires accepted Phase 3-B input")
        if candidate["sdk_pin_evidence_path"] not in inputs["phase_3b"]["public_summary_paths"]:
            raise AssertionError("SDK pin evidence must be part of the accepted Phase 3-B input")

    dimensions = require_mapping(ledger, "dimensions")
    complete = check_dimensions(dimensions, repo_root)

    audit = require_mapping(ledger, "audit")
    audit_complete = check_audit(audit, candidate_status)
    check_claim_state(claim_state, audit_complete, dimensions)

    releases = require_mapping(ledger, "release_gates")
    check_release_gates(releases, candidate_status, complete, audit["remediation_complete"])

    decision = require_mapping(ledger, "decision")
    decision_status = check_decision(decision, complete)

    if dimensions["code_complete"]["status"] == "complete" and candidate_status != "frozen":
        raise AssertionError("code_complete requires a frozen candidate")
    if dimensions["evidence_complete"]["status"] == "complete" and not (
        phase_3a == "accepted" and phase_3b == "accepted"
    ):
        raise AssertionError("evidence_complete requires accepted Phase 3-A and Phase 3-B inputs")
    if dimensions["audit_complete"]["status"] == "complete" and not audit_complete:
        raise AssertionError("audit_complete requires a completed independent audit record")

    upstream = {name for name in DIMENSIONS if name != "production_ready"}
    production_complete = dimensions["production_ready"]["status"] == "complete"
    if production_complete and not upstream.issubset(complete):
        raise AssertionError("production_ready requires every upstream dimension")
    if production_complete and not audit["remediation_complete"]:
        raise AssertionError("production_ready requires audit remediation closure")
    if production_complete != (decision_status == "GO"):
        raise AssertionError("GO must exactly match a complete production_ready dimension")
    if decision_status == "GO" and any(releases[release] != "pass" for release in RELEASES):
        raise AssertionError("GO requires every v1.2.0 release gate to pass")

    return {
        "candidate_status": candidate_status,
        "decision": decision_status,
        "complete_dimensions": len(complete),
    }


def check_candidate(candidate: dict[str, Any], status: str, repo_root: Path) -> None:
    versions = candidate.get("versions")
    if not isinstance(versions, dict):
        raise AssertionError("candidate versions must be an object")
    expected_versions = {
        "release_train": "1.2.0",
        "protocol": 1,
        "auth_v1": 1,
        "auth_v2": 2,
        "config": 1,
        "helper_ipc": 1,
        "recovery_journal": 2,
        "platform_plan": 3,
    }
    for key, value in expected_versions.items():
        if versions.get(key) != value:
            raise AssertionError(f"candidate version {key} must be {value!r}")
    identity_fields = {
        "release_tag",
        "maverick_software",
        "reference_software",
        "debian_package",
    }
    if set(versions) != {*expected_versions, *identity_fields}:
        raise AssertionError("candidate versions must list every required version separately")

    release_tag = versions["release_tag"]
    if release_tag not in RELEASES:
        raise AssertionError("candidate release_tag must name a v1.2.0 release stage")
    for key, value in RELEASE_IDENTITIES[release_tag].items():
        if versions[key] != value:
            raise AssertionError(
                f"candidate release identity {key} must be {value!r} for {release_tag}"
            )

    commits = (
        candidate.get("maverick_release_commit"),
        candidate.get("maverick_sdk_commit"),
        candidate.get("reference_client_commit"),
        candidate.get("reference_client_sdk_pin"),
    )
    package_hash = candidate.get("reference_package_sha256")
    if status == "not_frozen":
        if any(
            value is not None
            for value in (
                *commits,
                package_hash,
                candidate.get("sdk_pin_evidence_path"),
            )
        ):
            raise AssertionError(
                "an unfrozen candidate must not carry commits, hashes, or SDK evidence"
            )
        if candidate.get("sdk_pin_verified") is not False:
            raise AssertionError("an unfrozen candidate cannot claim SDK pin verification")
        return
    if not all(isinstance(value, str) and HEX40.fullmatch(value) for value in commits):
        raise AssertionError("a frozen candidate requires all full lowercase commit hashes")
    if candidate["reference_client_sdk_pin"] != candidate["maverick_sdk_commit"]:
        raise AssertionError("the reference-client SDK pin must match maverick_sdk_commit")
    if candidate.get("sdk_pin_verified") is not True:
        raise AssertionError("a frozen candidate requires verified SDK pin binding")
    sdk_pin_evidence = candidate.get("sdk_pin_evidence_path")
    check_paths([sdk_pin_evidence], "candidate.sdk_pin_evidence_path", repo_root, allow_empty=False)
    if not isinstance(package_hash, str) or not HEX64.fullmatch(package_hash):
        raise AssertionError("a frozen candidate requires the package SHA-256")


def check_scope(scope: dict[str, Any], repo_root: Path) -> None:
    expected = {
        "id": "maverick-linux-h2-ipv4-v1",
        "server_artifact": "maverick",
        "client_package": "maverick-reference-client",
        "package_format": "deb",
        "platform": FORMAL_PLATFORM,
        "architecture": "amd64",
        "address_family": "IPv4",
        "carrier": "TLS 1.3 + HTTP/2",
    }
    for key, value in expected.items():
        if scope.get(key) != value:
            raise AssertionError(f"scope {key} must be {value!r}")

    fixture = scope.get("formal_evidence_fixture")
    expected_fixture = {
        "kind": "disposable_vm",
        "platform": FORMAL_PLATFORM,
        "architecture": "amd64",
        "source_bound_required": True,
        "physical_host_substitution_allowed": False,
    }
    if fixture != expected_fixture:
        raise AssertionError("formal evidence must use the exact source-bound Ubuntu fixture policy")

    non_claims = scope.get("non_claims")
    if not isinstance(non_claims, list) or set(non_claims) != REQUIRED_NON_CLAIMS:
        raise AssertionError("scope non_claims must contain the complete canonical set")
    if len(non_claims) != len(set(non_claims)):
        raise AssertionError("scope non_claims must not contain duplicates")
    check_paths(scope.get("docs"), "scope.docs", repo_root, allow_empty=False)


def check_phase_input(inputs: dict[str, Any], name: str, repo_root: Path) -> str:
    value = inputs.get(name)
    if not isinstance(value, dict):
        raise AssertionError(f"phase_inputs.{name} must be an object")
    status = require_choice(value, "status", {"missing", "accepted"})
    manifest = value.get("accepted_manifest_sha256")
    paths = value.get("public_summary_paths")
    if status == "missing":
        if manifest is not None or paths != []:
            raise AssertionError(f"{name}: missing input must not carry accepted evidence")
        return status
    if not isinstance(manifest, str) or not HEX64.fullmatch(manifest):
        raise AssertionError(f"{name}: accepted input requires a manifest SHA-256")
    check_paths(paths, f"{name}.public_summary_paths", repo_root, allow_empty=False)
    return status


def check_dimensions(dimensions: dict[str, Any], repo_root: Path) -> set[str]:
    if set(dimensions) != set(DIMENSIONS):
        raise AssertionError("dimensions must contain exactly the five readiness questions")
    complete: set[str] = set()
    for name in DIMENSIONS:
        value = dimensions[name]
        if not isinstance(value, dict):
            raise AssertionError(f"dimensions.{name} must be an object")
        status = require_choice(value, "status", {"blocked", "complete"})
        reason = value.get("reason")
        paths = value.get("evidence_paths")
        if status == "blocked":
            if not isinstance(reason, str) or not reason or paths != []:
                raise AssertionError(f"{name}: blocked state requires a reason and no evidence paths")
        else:
            if reason is not None:
                raise AssertionError(f"{name}: complete state must clear its blocker reason")
            check_paths(paths, f"{name}.evidence_paths", repo_root, allow_empty=False)
            complete.add(name)
    return complete


def check_audit(audit: dict[str, Any], candidate_status: str) -> bool:
    status = require_choice(audit, "status", {"pre_freeze_preparation", "in_progress", "complete"})
    independent = audit.get("independent")
    if not isinstance(independent, bool):
        raise AssertionError("audit.independent must be a boolean")
    reviewer = audit.get("reviewer")
    report_hash = audit.get("report_sha256")
    remediation = audit.get("remediation_complete")
    if not isinstance(remediation, bool):
        raise AssertionError("audit.remediation_complete must be a boolean")

    if status == "pre_freeze_preparation":
        if any((independent, reviewer is not None, report_hash is not None, remediation)):
            raise AssertionError("pre-freeze audit preparation must not claim audit work or completion")
        return False
    if candidate_status != "frozen":
        raise AssertionError("an audit cannot start before candidate freeze")
    if status == "in_progress":
        if not independent or not isinstance(reviewer, str) or not reviewer:
            raise AssertionError("an in-progress audit requires an independent reviewer")
        if report_hash is not None or remediation:
            raise AssertionError("an in-progress audit must not carry completion fields")
        return False
    if not independent or not isinstance(reviewer, str) or not reviewer:
        raise AssertionError("a completed audit requires an independent reviewer")
    if not isinstance(report_hash, str) or not HEX64.fullmatch(report_hash):
        raise AssertionError("a completed audit requires a report SHA-256")
    return True


def check_claim_state(
    claim_state: dict[str, Any], audit_complete: bool, dimensions: dict[str, Any]
) -> None:
    if set(claim_state) != {"formal_audit", "production_readiness"}:
        raise AssertionError("current_claim_state must contain exactly two stateful claims")
    audit_claim = require_choice(claim_state, "formal_audit", {"not_completed", "completed"})
    production_claim = require_choice(
        claim_state, "production_readiness", {"not_approved", "approved"}
    )
    if (audit_claim == "completed") != audit_complete:
        raise AssertionError("formal_audit claim must exactly match audit completion")
    production_complete = dimensions["production_ready"]["status"] == "complete"
    if (production_claim == "approved") != production_complete:
        raise AssertionError("production_readiness claim must exactly match its dimension")


def check_release_gates(
    releases: dict[str, Any],
    candidate_status: str,
    complete: set[str],
    remediation_complete: bool,
) -> None:
    if set(releases) != set(RELEASES):
        raise AssertionError("release_gates must contain exactly the v1.2.0 release train")
    for release in RELEASES:
        if releases[release] not in {"blocked", "pass"}:
            raise AssertionError(f"invalid release gate status for {release}")
    prerequisites = {
        "v1.2.0-alpha.1": candidate_status == "frozen" and "code_complete" in complete,
        "v1.2.0-beta.1": "evidence_complete" in complete,
        "v1.2.0-rc.1": {"audit_complete", "deployable"}.issubset(complete)
        and remediation_complete,
        "v1.2.0": "production_ready" in complete,
    }
    for release, ready in prerequisites.items():
        if releases[release] == "pass" and not ready:
            raise AssertionError(f"{release} cannot pass before its prerequisite dimensions")
    seen_blocked = False
    for release in RELEASES:
        if releases[release] == "blocked":
            seen_blocked = True
        elif seen_blocked:
            raise AssertionError("release gates must pass in alpha, beta, RC, stable order")


def check_decision(decision: dict[str, Any], complete: set[str]) -> str:
    status = require_choice(decision, "status", {"GO", "NO_GO"})
    kind = require_choice(decision, "kind", {"current_blocker", "final"})
    decided_at = decision.get("decided_at")
    approver = decision.get("approver")
    reasons = decision.get("reason_codes")
    if status == "NO_GO":
        if kind == "current_blocker" and (decided_at is not None or approver is not None):
            raise AssertionError("current NO_GO blocker state must not look like a final decision")
        if kind == "final":
            if not isinstance(decided_at, str) or not decided_at.endswith("Z"):
                raise AssertionError("final NO_GO requires a UTC decided_at timestamp")
            if not isinstance(approver, str) or not approver:
                raise AssertionError("final NO_GO requires an approver")
        if not isinstance(reasons, list) or not reasons or not all(
            isinstance(value, str) and value for value in reasons
        ):
            raise AssertionError("NO_GO requires non-empty reason_codes")
        return status
    if kind != "final":
        raise AssertionError("GO must be a final decision")
    if "production_ready" not in complete:
        raise AssertionError("GO requires production_ready")
    if not isinstance(decided_at, str) or not decided_at.endswith("Z"):
        raise AssertionError("GO requires a UTC decided_at timestamp")
    if not isinstance(approver, str) or not approver:
        raise AssertionError("GO requires an approver")
    if reasons != []:
        raise AssertionError("GO must clear reason_codes")
    return status


def check_paths(raw_paths: Any, field: str, repo_root: Path, *, allow_empty: bool) -> None:
    if not isinstance(raw_paths, list) or (not allow_empty and not raw_paths):
        raise AssertionError(f"{field} must be a {'list' if allow_empty else 'non-empty list'}")
    if len(raw_paths) != len(set(raw_paths)):
        raise AssertionError(f"{field} must not contain duplicates")
    for raw_path in raw_paths:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{field} entries must be non-empty strings")
        path = PurePosixPath(raw_path)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise AssertionError(f"{field} contains unsafe path {raw_path!r}")
        actual = repo_root / path
        current = repo_root
        for part in path.parts:
            current /= part
            if current.is_symlink():
                raise AssertionError(f"{field} contains symlink path {raw_path!r}")
        try:
            mode = actual.lstat().st_mode
        except FileNotFoundError:
            raise AssertionError(f"{field} references missing file {raw_path!r}")
        if not stat.S_ISREG(mode):
            raise AssertionError(f"{field} must reference an actual regular file {raw_path!r}")
        try:
            actual.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
        except (OSError, ValueError):
            raise AssertionError(f"{field} resolves outside the repository {raw_path!r}")


def require_mapping(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise AssertionError(f"{key} must be an object")
    return value


def require_choice(mapping: dict[str, Any], key: str, choices: set[str]) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or value not in choices:
        raise AssertionError(f"{key} must be one of {sorted(choices)}")
    return value


if __name__ == "__main__":
    main()
