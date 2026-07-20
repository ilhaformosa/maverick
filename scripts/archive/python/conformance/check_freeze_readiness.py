#!/usr/bin/env python3
"""Verify Maverick spec-freeze readiness policy metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_TOP_LEVEL_STATUSES = {"blocked", "ready"}
VALID_LEVELS = {"candidate", "frozen"}
VALID_CRITERION_STATUSES = {"satisfied", "partial", "blocked", "not_applicable"}
BLOCKING_STATUSES = {"partial", "blocked"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("readiness", type=Path)
    args = parser.parse_args()

    result = check_readiness_file(args.readiness)
    print(
        "freeze readiness OK: "
        f"{result['status']} "
        f"({result['blocking_count']} blocking criteria, "
        f"{result['criteria_count']} total criteria)"
    )


def check_readiness_file(readiness_path: Path) -> dict[str, int | str]:
    with readiness_path.open("r", encoding="utf-8") as handle:
        readiness = json.load(handle)

    repo_root = readiness_path.parent.parent
    return check_readiness(readiness, repo_root)


def check_readiness(readiness: dict[str, Any], repo_root: Path) -> dict[str, int | str]:
    if readiness.get("version") != 1:
        raise AssertionError("freeze readiness version must be 1")

    status = require_string(readiness, "status")
    if status not in VALID_TOP_LEVEL_STATUSES:
        raise AssertionError(f"invalid freeze readiness status: {status!r}")

    target = require_string(readiness, "target")
    if target not in VALID_LEVELS:
        raise AssertionError(f"invalid freeze readiness target: {target!r}")

    criteria = readiness.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        raise AssertionError("criteria must be a non-empty list")

    seen: set[str] = set()
    blocking_count = 0
    for item in criteria:
        if not isinstance(item, dict):
            raise AssertionError("each criterion must be an object")
        criterion_status = check_criterion(item, repo_root, seen)
        if criterion_status in BLOCKING_STATUSES:
            blocking_count += 1

    if status == "ready" and blocking_count:
        raise AssertionError("ready status cannot contain partial or blocked criteria")
    if status == "blocked" and blocking_count == 0:
        raise AssertionError("blocked status must contain at least one partial or blocked criterion")

    return {
        "status": status,
        "criteria_count": len(criteria),
        "blocking_count": blocking_count,
    }


def check_criterion(
    criterion: dict[str, Any], repo_root: Path, seen: set[str]
) -> str:
    criterion_id = require_string(criterion, "id")
    if criterion_id in seen:
        raise AssertionError(f"duplicate freeze criterion: {criterion_id}")
    seen.add(criterion_id)

    level = require_string(criterion, "level")
    if level not in VALID_LEVELS:
        raise AssertionError(f"{criterion_id}: invalid level {level!r}")

    status = require_string(criterion, "status")
    if status not in VALID_CRITERION_STATUSES:
        raise AssertionError(f"{criterion_id}: invalid status {status!r}")

    evidence = criterion.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError(f"{criterion_id}: evidence must be a non-empty list")
    for raw_path in evidence:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{criterion_id}: evidence path must be a non-empty string")
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{criterion_id}: missing evidence path {raw_path}")

    notes = require_string(criterion, "notes")
    if "Mosaic" in notes:
        raise AssertionError(f"{criterion_id}: notes contain a legacy project name")

    return status


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


if __name__ == "__main__":
    main()
