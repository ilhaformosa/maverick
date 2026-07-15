#!/usr/bin/env python3
"""Materialize cargo-fuzz corpus seeds from the checked-in seed manifest."""

from __future__ import annotations

import binascii
import json
import re
from pathlib import Path
from typing import Any


SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def main() -> None:
    fuzz_root = Path(__file__).resolve().parent
    repo_root = fuzz_root.parent
    manifest_path = fuzz_root / "seed-manifest.json"
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    count = sync_manifest(manifest, repo_root, fuzz_root)
    print(f"synced fuzz corpus: {count} seeds")


def sync_manifest(manifest: dict[str, Any], repo_root: Path, fuzz_root: Path) -> int:
    if manifest.get("version") != 1:
        raise AssertionError("fuzz seed manifest version must be 1")

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise AssertionError("fuzz seed manifest must list targets")

    corpus_root = (fuzz_root / "corpus").resolve()
    count = 0
    seen_outputs: set[Path] = set()
    for target in targets:
        target_name = require_safe_name(target, "target")
        seeds = target.get("seeds")
        if not isinstance(seeds, list) or not seeds:
            raise AssertionError(f"{target_name}: target must list seeds")

        output_dir = (corpus_root / target_name).resolve()
        require_contained_path(output_dir, corpus_root, "fuzz target output")
        output_dir.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            seed_id = require_safe_name(seed, "id")
            seed_bytes = read_seed_bytes(seed, repo_root, fuzz_root)
            output_path = (output_dir / seed_id).resolve()
            require_contained_path(output_path, output_dir, "fuzz seed output")
            if output_path in seen_outputs:
                raise AssertionError(f"duplicate fuzz seed output: {output_path}")
            seen_outputs.add(output_path)
            output_path.write_bytes(seed_bytes)
            count += 1

    return count


def read_seed_bytes(seed: dict[str, Any], repo_root: Path, fuzz_root: Path) -> bytes:
    if "hex" in seed:
        seed_hex = require_string(seed, "hex")
    else:
        source = require_string(seed, "source")
        source_path = resolve_repo_path(source, repo_root, fuzz_root)
        field = require_string(seed, "field")
        with source_path.open("r", encoding="utf-8") as handle:
            source_doc = json.load(handle)
        seed_hex = source_doc.get(field)
        if not isinstance(seed_hex, str):
            raise AssertionError(f"{source}: missing string field {field}")

    compact_hex = "".join(seed_hex.split())
    if len(compact_hex) % 2 != 0:
        raise AssertionError("fuzz seed hex must have an even length")
    try:
        return binascii.unhexlify(compact_hex)
    except binascii.Error as exc:
        raise AssertionError(f"invalid fuzz seed hex: {exc}") from exc


def resolve_repo_path(raw_path: str, repo_root: Path, fuzz_root: Path) -> Path:
    path = (fuzz_root / raw_path).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise AssertionError(f"fuzz seed source escapes repo: {raw_path}") from exc
    if not path.is_file():
        raise AssertionError(f"missing fuzz seed source: {raw_path}")
    return path


def require_safe_name(mapping: dict[str, Any], key: str) -> str:
    value = require_string(mapping, key)
    if value in {".", ".."} or not SAFE_NAME.fullmatch(value):
        raise AssertionError(f"{key} must be filesystem-safe")
    return value


def require_contained_path(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise AssertionError(f"{label} escapes its root") from exc


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


if __name__ == "__main__":
    main()
