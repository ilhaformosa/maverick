#!/usr/bin/env python3
"""Require key non-claim disclaimers to remain present in docs."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Requirement:
    path: str
    phrase: str


REQUIREMENTS = (
    Requirement(
        "README.md",
        "Experimental Rust privacy proxy protocol; public main targets v1.2.0 and is not audited or production-ready",
    ),
    Requirement(
        "docs/PUBLIC_HISTORY_BOUNDARY.md",
        "Do not recreate an old tag on a different public commit.",
    ),
    Requirement("STATUS.md", "No formal independent security audit has been completed."),
    Requirement("STATUS.md", "Browser-like TLS fingerprinting is optional, not default."),
    Requirement("STATUS.md", "not a claim of exact browser equivalence."),
    Requirement("STATUS.md", "Real traffic-analysis resistance is not implemented."),
    Requirement("README.md", "does not claim browser-grade TLS fingerprint mimicry"),
    Requirement("README.md", "Strong traffic-analysis resistance or anonymity guarantees"),
    Requirement("SECURITY.md", "production security software"),
    Requirement("SECURITY.md", "Prior review input does not equal stable or production security sign-off."),
    Requirement("THREAT_MODEL.md", "Maverick v1 does not claim to defend against"),
    Requirement(
        "ROADMAP.md",
        "Only the narrow `maverick-tls-h2-cli-v1` scope is stable.",
    ),
    Requirement(
        "docs/CAPABILITY_REPORT.md",
        "None of these are strong traffic-analysis or anonymity protection claims.",
    ),
    Requirement(
        "docs/CONFORMANCE_SUITE.md",
        "it is not a production, formal-audit, anonymity, censorship-resistance",
    ),
    Requirement("docs/EXPERIMENTAL_TRACKS.md", "excluded from default security claims"),
    Requirement(
        "docs/ROADMAP_BLOCKERS.md",
        "It is not a stability, audit, production, or standardization claim.",
    ),
    Requirement("docs/SHAPE_LAB_BASELINE.md", "not an anonymity claim"),
    Requirement("docs/SHAPE_LAB_BASELINE.md", "does not prove traffic-analysis resistance"),
    Requirement(
        "docs/SPEC_FREEZE_PROCESS.md",
        "Only the narrow `maverick-tls-h2-cli-v1` scope is frozen for v1.0.0",
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    count = check_claim_hygiene(args.repo_root)
    print(f"claim hygiene OK: {count} required non-claims")


def check_claim_hygiene(repo_root: Path) -> int:
    for requirement in REQUIREMENTS:
        check_requirement(repo_root, requirement)
    return len(REQUIREMENTS)


def check_requirement(repo_root: Path, requirement: Requirement) -> None:
    path = repo_root / requirement.path
    if not path.exists():
        raise AssertionError(f"missing claim-hygiene document: {requirement.path}")

    content = path.read_text(encoding="utf-8")
    if normalize(requirement.phrase) not in normalize(content):
        raise AssertionError(
            f"{requirement.path} is missing required non-claim: {requirement.phrase!r}"
        )


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


if __name__ == "__main__":
    main()
