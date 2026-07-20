#!/usr/bin/env python3
"""Check that Maverick wire-format docs match parser-visible frame types."""

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path


RUST_FRAME_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*0x([0-9A-Fa-f]{2}),")
WIRE_FRAME_RE = re.compile(r"^0x([0-9A-Fa-f]{2})\s+([A-Z0-9_]+)\s*$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_root", type=Path)
    args = parser.parse_args()

    count = check_repo(args.repo_root)
    print(f"spec/wire alignment OK: {count} frame types")


def check_repo(repo_root: Path) -> int:
    rust_frames = parse_rust_frame_types(repo_root / "crates/maverick-core/src/frame.rs")
    wire_frames = parse_wire_format_table(repo_root / "WIRE_FORMAT.md")
    python_frames = parse_python_frame_types(repo_root / "conformance/runner/python_verify.py")

    if rust_frames != wire_frames:
        raise AssertionError(
            "WIRE_FORMAT.md frame table differs from Rust FrameType enum: "
            f"rust={rust_frames} wire={wire_frames}"
        )
    if rust_frames != python_frames:
        raise AssertionError(
            "python verifier FRAME_TYPES differs from Rust FrameType enum: "
            f"rust={rust_frames} python={python_frames}"
        )

    for rel_path in ["SPEC.md", "WIRE_FORMAT.md"]:
        text = (repo_root / rel_path).read_text(encoding="utf-8")
        if "Mosaic" in text:
            raise AssertionError(f"{rel_path} contains a legacy project name")
        if "production-ready" in text and "not production-ready" not in text:
            raise AssertionError(f"{rel_path} contains an unsupported production claim")

    return len(rust_frames)


def parse_rust_frame_types(path: Path) -> dict[str, int]:
    frames: dict[str, int] = {}
    in_enum = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "pub enum FrameType {":
            in_enum = True
            continue
        if in_enum and line.strip() == "}":
            break
        if not in_enum:
            continue
        match = RUST_FRAME_RE.match(line)
        if match:
            frames[pascal_to_snake(match.group(1))] = int(match.group(2), 16)
    if not frames:
        raise AssertionError(f"no Rust frame types parsed from {path}")
    return frames


def parse_wire_format_table(path: Path) -> dict[str, int]:
    frames: dict[str, int] = {}
    in_block = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "```text":
            in_block = True
            continue
        if in_block and line.strip() == "```":
            if frames:
                break
            in_block = False
            continue
        if not in_block:
            continue
        match = WIRE_FRAME_RE.match(line.strip())
        if match:
            frames[match.group(2).lower()] = int(match.group(1), 16)
    if not frames:
        raise AssertionError(f"no wire-format frame types parsed from {path}")
    return frames


def parse_python_frame_types(path: Path) -> dict[str, int]:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FRAME_TYPES":
                    value = ast.literal_eval(node.value)
                    if not isinstance(value, dict) or not value:
                        raise AssertionError("FRAME_TYPES must be a non-empty dict")
                    return {str(key): int(raw) for key, raw in value.items()}
    raise AssertionError(f"FRAME_TYPES not found in {path}")


def pascal_to_snake(value: str) -> str:
    out = []
    for idx, char in enumerate(value):
        if char.isupper() and idx > 0:
            out.append("_")
        out.append(char.lower())
    return "".join(out)


if __name__ == "__main__":
    main()
