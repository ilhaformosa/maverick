#!/usr/bin/env python3
"""Require immutable action revisions and exact Rust tool versions in workflows."""

from __future__ import annotations

import re
import shlex
from pathlib import Path


ACTION = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
FULL_REVISION = re.compile(r"^[0-9a-f]{40}$")


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    paths = sorted((repo / ".github/workflows").glob("*.yml"))
    paths.extend(sorted((repo / ".github/workflows").glob("*.yaml")))
    check_workflows(paths)
    print(f"workflow pins OK: {len(paths)} files")


def check_workflows(paths: list[Path]) -> None:
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            action = ACTION.match(line)
            if action and not FULL_REVISION.fullmatch(action.group(2)):
                raise AssertionError(
                    f"{path}:{line_number}: action {action.group(1)} must use a full revision"
                )
            stripped = line.strip()
            if "run: cargo install " not in stripped:
                continue
            command = stripped.split("run:", 1)[1].strip()
            tokens = shlex.split(command)
            if "--locked" not in tokens or "--version" not in tokens:
                raise AssertionError(
                    f"{path}:{line_number}: cargo install must use --version and --locked"
                )
            version_index = tokens.index("--version")
            if version_index + 1 >= len(tokens) or not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+", tokens[version_index + 1]
            ):
                raise AssertionError(f"{path}:{line_number}: cargo install version must be exact")


if __name__ == "__main__":
    main()
