#!/usr/bin/env python3
"""Require public issue templates to preserve privacy and safety prompts."""

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
    Requirement(".github/ISSUE_TEMPLATE/config.yml", "blank_issues_enabled: false"),
    Requirement(".github/ISSUE_TEMPLATE/config.yml", "Do not file public issues for vulnerabilities"),
    Requirement(".github/ISSUE_TEMPLATE/bug_report.yml", "raw payload data"),
    Requirement(".github/ISSUE_TEMPLATE/bug_report.yml", "real server addresses"),
    Requirement(".github/ISSUE_TEMPLATE/bug_report.yml", "local private filesystem paths"),
    Requirement(".github/ISSUE_TEMPLATE/bug_report.yml", "system proxy, DNS, route table, firewall, VPN"),
    Requirement(".github/ISSUE_TEMPLATE/bug_report.yml", "working exploit details"),
    Requirement(".github/ISSUE_TEMPLATE/feature_request.yml", "Maverick is experimental"),
    Requirement(".github/ISSUE_TEMPLATE/feature_request.yml", "isolated approved-host plan"),
    Requirement(".github/ISSUE_TEMPLATE/feature_request.yml", "workstation system network mutation is out of scope"),
    Requirement(".github/ISSUE_TEMPLATE/docs_question.yml", "Safety confirmation"),
    Requirement(".github/ISSUE_TEMPLATE/docs_question.yml", "public vulnerability report"),
    Requirement("docs/PUBLIC_FEEDBACK_PROCESS.md", "`security-private`"),
    Requirement("docs/PUBLIC_FEEDBACK_PROCESS.md", "`release-blocker`"),
    Requirement("docs/PUBLIC_FEEDBACK_PROCESS.md", "`beta-candidate`"),
    Requirement("docs/PUBLIC_FEEDBACK_PROCESS.md", "`rc-candidate`"),
    Requirement("docs/PUBLIC_FEEDBACK_PROCESS.md", "`out-of-scope`"),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    count = check_issue_template_hygiene(args.repo_root)
    print(f"issue template hygiene OK: {count} required prompts")


def check_issue_template_hygiene(repo_root: Path) -> int:
    for requirement in REQUIREMENTS:
        check_requirement(repo_root, requirement)
    return len(REQUIREMENTS)


def check_requirement(repo_root: Path, requirement: Requirement) -> None:
    path = repo_root / requirement.path
    if not path.exists():
        raise AssertionError(f"missing issue-template hygiene document: {requirement.path}")

    content = path.read_text(encoding="utf-8")
    if normalize(requirement.phrase) not in normalize(content):
        raise AssertionError(
            f"{requirement.path} is missing required prompt: {requirement.phrase!r}"
        )


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


if __name__ == "__main__":
    main()
