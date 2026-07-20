#!/usr/bin/env python3
"""Verify Maverick implementation registry metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_SPEC_STATUSES = {"draft", "candidate", "frozen"}
VALID_IMPLEMENTATION_KINDS = {"client_server", "read_only_parser", "sdk_wrapper"}
VALID_IMPLEMENTATION_STATUSES = {"passing", "partial", "planned", "blocked"}
VALID_NETWORK_BEHAVIORS = {"loopback_only_tests", "no_network", "external_required"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", type=Path)
    args = parser.parse_args()

    result = check_registry_file(args.registry)
    print(
        "implementation registry OK: "
        f"{result['implementation_count']} implementations, "
        f"{result['parser_count']} no-network parser/verifiers"
    )


def check_registry_file(registry_path: Path) -> dict[str, int]:
    with registry_path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)

    repo_root = registry_path.parent.parent
    return check_registry(registry, repo_root)


def check_registry(registry: dict[str, Any], repo_root: Path) -> dict[str, int]:
    if registry.get("version") != 1:
        raise AssertionError("implementation registry version must be 1")

    spec_status = require_string(registry, "spec_status")
    if spec_status not in VALID_SPEC_STATUSES:
        raise AssertionError(f"invalid spec_status: {spec_status!r}")

    if registry.get("standardization_claim") is not False:
        raise AssertionError("implementation registry must not claim standardization")

    notes = require_string(registry, "notes")
    reject_legacy_name("notes", notes)

    implementations = registry.get("implementations")
    if not isinstance(implementations, list) or not implementations:
        raise AssertionError("implementations must be a non-empty list")

    seen: set[str] = set()
    client_server_count = 0
    parser_count = 0
    for item in implementations:
        if not isinstance(item, dict):
            raise AssertionError("each implementation must be an object")
        kind = check_implementation(item, repo_root, seen, spec_status)
        if kind == "client_server":
            client_server_count += 1
        if kind == "read_only_parser":
            parser_count += 1

    if client_server_count == 0:
        raise AssertionError("registry must include at least one client/server implementation")
    if parser_count == 0:
        raise AssertionError("registry must include at least one no-network parser/verifier")

    return {
        "implementation_count": len(implementations),
        "parser_count": parser_count,
    }


def check_implementation(
    item: dict[str, Any], repo_root: Path, seen: set[str], spec_status: str
) -> str:
    implementation_id = require_string(item, "id")
    reject_legacy_name(f"{implementation_id}.id", implementation_id)
    if implementation_id in seen:
        raise AssertionError(f"duplicate implementation id: {implementation_id}")
    seen.add(implementation_id)

    for field in ("name", "language"):
        reject_legacy_name(f"{implementation_id}.{field}", require_string(item, field))

    kind = require_string(item, "kind")
    if kind not in VALID_IMPLEMENTATION_KINDS:
        raise AssertionError(f"{implementation_id}: invalid kind {kind!r}")

    status = require_string(item, "status")
    if status not in VALID_IMPLEMENTATION_STATUSES:
        raise AssertionError(f"{implementation_id}: invalid status {status!r}")

    network_behavior = require_string(item, "network_behavior")
    if network_behavior not in VALID_NETWORK_BEHAVIORS:
        raise AssertionError(f"{implementation_id}: invalid network_behavior {network_behavior!r}")

    opens_network = item.get("opens_network")
    if not isinstance(opens_network, bool):
        raise AssertionError(f"{implementation_id}: opens_network must be a boolean")
    if kind == "read_only_parser":
        if network_behavior != "no_network" or opens_network:
            raise AssertionError(f"{implementation_id}: parser/verifier must be no-network")
        if item.get("transports") != []:
            raise AssertionError(f"{implementation_id}: parser/verifier must not declare transports")

    if item.get("normative") is not False:
        raise AssertionError(f"{implementation_id}: implementation must not be normative")
    if spec_status == "draft" and item.get("normative"):
        raise AssertionError(f"{implementation_id}: draft spec cannot have normative implementations")

    check_string_list(item, "coverage", implementation_id, required=status == "passing")
    check_string_list(item, "transports", implementation_id, required=False)
    check_string_list(item, "feature_gates", implementation_id, required=False)

    evidence = item.get("evidence")
    if not isinstance(evidence, list) or (status == "passing" and not evidence):
        raise AssertionError(f"{implementation_id}: passing implementation requires evidence")
    for raw_path in evidence:
        if not isinstance(raw_path, str) or not raw_path:
            raise AssertionError(f"{implementation_id}: evidence path must be a non-empty string")
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{implementation_id}: missing evidence path {raw_path}")

    return kind


def check_string_list(
    item: dict[str, Any], field: str, implementation_id: str, *, required: bool
) -> list[str]:
    value = item.get(field)
    if not isinstance(value, list) or (required and not value):
        raise AssertionError(f"{implementation_id}: {field} must be a list")
    seen: set[str] = set()
    result: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise AssertionError(f"{implementation_id}: {field} entries must be non-empty strings")
        reject_legacy_name(f"{implementation_id}.{field}", entry)
        if entry in seen:
            raise AssertionError(f"{implementation_id}: duplicate {field} entry {entry!r}")
        seen.add(entry)
        result.append(entry)
    return result


def require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"{key} must be a non-empty string")
    return value


def reject_legacy_name(field: str, value: str) -> None:
    if "Mosaic" in value:
        raise AssertionError(f"{field} contains a legacy project name")


def safe_relative_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe relative path: {raw_path!r}")
    return path


if __name__ == "__main__":
    main()
