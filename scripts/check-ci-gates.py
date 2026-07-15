#!/usr/bin/env python3
"""Keep the public PR and release-candidate CI boundaries machine-checkable."""

from __future__ import annotations

from pathlib import Path


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    check_ci_design(repo)
    print("CI gate design OK: local preflight + public PR CI + release-candidate CI")


def check_ci_design(repo: Path) -> None:
    pr_path = repo / ".github" / "workflows" / "ci.yml"
    candidate_path = repo / ".github" / "workflows" / "release-candidate.yml"
    legacy_docs_path = repo / ".github" / "workflows" / "docs-hygiene.yml"
    local_harness_path = repo / "scripts" / "local-harness.sh"

    for path in (pr_path, candidate_path, local_harness_path):
        if not path.is_file():
            raise AssertionError(f"missing CI gate input: {path.relative_to(repo)}")
    if legacy_docs_path.exists():
        raise AssertionError("docs hygiene must be part of the single public PR gate")

    pr = pr_path.read_text(encoding="utf-8")
    candidate = candidate_path.read_text(encoding="utf-8")
    local_harness = local_harness_path.read_text(encoding="utf-8")

    require_all(
        pr,
        (
            "name: public-pr-ci",
            "pull_request:",
            "core: ${{ steps.scope.outputs.core }}",
            "MAVERICK_SKIP_DOCS_HYGIENE: \"1\"",
            "public-pr-gate:",
            "runs-on: ubuntu-24.04",
        ),
        "public PR CI",
    )
    reject_all(pr, ("workflow_dispatch:", "strategy:", "matrix:"), "public PR CI")
    if pr.count("./scripts/local-harness.sh") != 1:
        raise AssertionError("public PR CI must run the local harness exactly once")

    require_all(
        candidate,
        (
            "name: release-candidate-ci",
            "workflow_dispatch:",
            "candidate_sha:",
            "release_stage:",
            "runs-on: ubuntu-24.04",
            "control/production-readiness.json",
            "--expected-release-commit \"$CANDIDATE_SHA\"",
            "--release-stage \"$RELEASE_STAGE\"",
            "ref: ${{ inputs.candidate_sha }}",
            "persist-credentials: false",
            "./scripts/local-harness.sh",
            "./scripts/security-dependency-inventory.sh",
            "./scripts/release-artifacts.sh",
            "Publication: none",
        ),
        "release-candidate CI",
    )
    reject_all(
        candidate,
        (
            "strategy:",
            "matrix:",
            "maverick-reference-client",
            "secrets.",
            "git push",
            "git tag",
            "gh release",
            "upload-artifact",
        ),
        "release-candidate CI",
    )
    if candidate.count("./scripts/local-harness.sh") != 1:
        raise AssertionError("release-candidate CI must run the exact source gate once")
    if candidate.count("uses: actions/checkout@") != 2:
        raise AssertionError("release-candidate CI must separate control and release checkouts")

    require_all(
        local_harness,
        (
            "MAVERICK_SKIP_DOCS_HYGIENE",
            "scripts/test-ci-gates.py",
            "scripts/check-ci-gates.py",
        ),
        "local preflight",
    )


def require_all(text: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise AssertionError(f"{label} is missing required design tokens: {missing}")


def reject_all(text: str, tokens: tuple[str, ...], label: str) -> None:
    found = [token for token in tokens if token in text]
    if found:
        raise AssertionError(f"{label} contains forbidden design tokens: {found}")


if __name__ == "__main__":
    main()
