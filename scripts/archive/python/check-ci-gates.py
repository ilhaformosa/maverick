#!/usr/bin/env python3
"""Keep the public PR and release-candidate CI boundaries machine-checkable."""

from __future__ import annotations

import re
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
            'git show "${BASE_SHA}:scripts/ci-change-scope.py" >"$classifier"',
            "MAVERICK_SKIP_DOCS_HYGIENE: \"1\"",
            "public-pr-gate:",
            "H3_SELECTED: ${{ needs.change-scope.outputs.h3 }}",
            "ECH_SELECTED: ${{ needs.change-scope.outputs.ech }}",
            "SHAPE_SELECTED: ${{ needs.change-scope.outputs.shape }}",
            "BROWSER_SELECTED: ${{ needs.change-scope.outputs.browser }}",
            'require_success "docs-hygiene" "$DOCS_RESULT"',
            'require_success "core" "$CORE_RESULT"',
            'require_optional_result "h3-harness" "$H3_SELECTED" "$H3_RESULT"',
            'require_optional_result "ech-harness" "$ECH_SELECTED" "$ECH_RESULT"',
            'require_optional_result "shape-lab-smoke" "$SHAPE_SELECTED" "$SHAPE_RESULT"',
            'require_optional_result "browser-tls-harness" "$BROWSER_SELECTED" "$BROWSER_RESULT"',
            "runs-on: ubuntu-24.04",
        ),
        "public PR CI",
    )
    reject_all(
        pr,
        (
            "workflow_dispatch:",
            "strategy:",
            "matrix:",
            "if: needs.change-scope.outputs.core",
            "for result in",
        ),
        "public PR CI",
    )
    if pr.count("./scripts/local-harness.sh") != 1:
        raise AssertionError("public PR CI must run the local harness exactly once")
    for job_name in ("docs-hygiene", "core"):
        block = workflow_job(pr, job_name)
        if re.search(r"^    (?:if|needs):", block, flags=re.MULTILINE):
            raise AssertionError(f"public PR CI job {job_name} must be unconditional")

    require_all(
        candidate,
        (
            "name: release-candidate-ci",
            "workflow_dispatch:",
            "candidate_sha:",
            "release_stage:",
            "runs-on: ubuntu-24.04",
            "FORMAL_TARGET_PLATFORM: Ubuntu 26.04 LTS amd64",
            'echo "- CI runner (not formal target): \\`ubuntu-24.04\\`"',
            'echo "- Formal target: \\`$FORMAL_TARGET_PLATFORM\\`"',
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


def check_pr_gate_results(
    scope_result: str,
    docs_result: str,
    core_result: str,
    optional_results: dict[str, tuple[str, str]],
) -> None:
    for label, result in (
        ("change-scope", scope_result),
        ("docs-hygiene", docs_result),
        ("core", core_result),
    ):
        if result != "success":
            raise AssertionError(f"{label} must succeed, got {result!r}")

    for label, (selected, result) in optional_results.items():
        if selected == "true":
            expected = "success"
        elif selected == "false":
            expected = "skipped"
        else:
            raise AssertionError(f"{label} has invalid selected value {selected!r}")
        if result != expected:
            raise AssertionError(
                f"{label} selected={selected} requires {expected}, got {result}"
            )


def workflow_job(text: str, name: str) -> str:
    marker = f"\n  {name}:\n"
    if marker not in text:
        raise AssertionError(f"public PR CI is missing job {name}")
    remainder = text.split(marker, 1)[1]
    next_job = re.search(r"^  [a-zA-Z0-9_-]+:\n", remainder, flags=re.MULTILINE)
    return remainder[: next_job.start()] if next_job else remainder


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
