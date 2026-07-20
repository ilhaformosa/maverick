#!/usr/bin/env python3
"""Validate Maverick roadmap blocker metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any


VALID_TOP_STATUSES = {"blocked_external", "no_active_roadmap_blockers"}
VALID_BLOCKER_STATUSES = {"blocked", "deferred"}
VALID_TRACK_STATUSES = {
    "tracked_upstream",
    "moved_to_app_project",
    "release_note_gate",
    "optional_interop_track",
}
VALID_KINDS = {
    "external_review",
    "approved_host_required",
    "upstream_and_approved_host_required",
    "runtime_review_required",
    "reviewed_implementation_required",
    "product_runtime_deferred",
    "post_candidate_deferred",
}
REQUIRED_BLOCKERS: set[str] = set()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", nargs="?", default="roadmap-blockers.json", type=Path)
    args = parser.parse_args()

    result = check_blocker_file(args.registry)
    print(
        "roadmap blockers OK: "
        f"{result['blocked_count']} blocked, {result['deferred_count']} deferred"
    )


def check_blocker_file(registry_path: Path) -> dict[str, int]:
    with registry_path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    repo_root = registry_path.parent
    result = check_blockers(registry, repo_root)
    check_blocker_doc(registry, repo_root / "docs/ROADMAP_BLOCKERS.md")
    return result


def check_blockers(registry: dict[str, Any], repo_root: Path) -> dict[str, int]:
    if registry.get("version") != 1:
        raise AssertionError("roadmap blocker registry version must be 1")

    status = require_string(registry, "status")
    if status not in VALID_TOP_STATUSES:
        raise AssertionError(f"invalid roadmap blocker registry status: {status!r}")

    reject_legacy_name("notes", require_string(registry, "notes"))

    resolution_plan = registry.get("resolution_plan")
    if resolution_plan is not None:
        rel_path = safe_relative_path(require_string(registry, "resolution_plan"))
        if not (repo_root / rel_path).exists():
            raise AssertionError(f"missing resolution plan path {resolution_plan}")

    blockers = registry.get("blockers")
    if not isinstance(blockers, list):
        raise AssertionError("blockers must be a list")
    if status == "blocked_external" and not blockers:
        raise AssertionError("blocked_external status requires at least one blocker")
    if status == "no_active_roadmap_blockers" and blockers:
        raise AssertionError("no_active_roadmap_blockers status requires an empty blockers list")

    seen: set[str] = set()
    status_counts = {"blocked": 0, "deferred": 0}
    must_remain_blocked = {"ech_handshake_integration"} & {item.get("id") for item in blockers}
    for item in blockers:
        if not isinstance(item, dict):
            raise AssertionError("each blocker must be an object")
        blocker_id, blocker_status = check_blocker(item, repo_root, seen)
        if blocker_id in must_remain_blocked and blocker_status != "blocked":
            raise AssertionError(f"{blocker_id}: required blocker must remain blocked")
        status_counts[blocker_status] += 1

    missing = sorted(REQUIRED_BLOCKERS - seen)
    if missing:
        raise AssertionError(f"missing required blockers: {missing}")

    if status == "blocked_external" and status_counts["blocked"] == 0:
        raise AssertionError("registry must include at least one blocked item")

    track_count = check_non_blocking_tracks(registry, repo_root)
    if status == "no_active_roadmap_blockers" and track_count == 0:
        raise AssertionError(
            "no_active_roadmap_blockers status requires at least one non-blocking track"
        )

    return {
        "blocked_count": status_counts["blocked"],
        "deferred_count": status_counts["deferred"],
        "track_count": track_count,
    }


def check_blocker_doc(registry: dict[str, Any], doc_path: Path) -> None:
    if not doc_path.exists():
        raise AssertionError(f"missing blocker doc: {doc_path}")

    doc = doc_path.read_text(encoding="utf-8")
    reject_legacy_name("docs/ROADMAP_BLOCKERS.md", doc)

    blockers = registry.get("blockers")
    if not isinstance(blockers, list):
        raise AssertionError("blockers must be a list before doc coverage checks")

    for item in blockers:
        if not isinstance(item, dict):
            raise AssertionError("each blocker must be an object before doc coverage checks")
        blocker_id = require_string(item, "id")
        phase = require_string(item, "phase")
        status = require_string(item, "status")
        expected_token = f"`{blocker_id}`"
        matching_lines = [line for line in doc.splitlines() if expected_token in line]
        if not matching_lines:
            raise AssertionError(f"docs/ROADMAP_BLOCKERS.md missing {blocker_id}")
        expected_state = f"({phase}, {status})"
        if not any(expected_state in line for line in matching_lines):
            raise AssertionError(
                f"docs/ROADMAP_BLOCKERS.md must document {blocker_id} as {expected_state}"
            )


def check_blocker(
    item: dict[str, Any], repo_root: Path, seen: set[str]
) -> tuple[str, str]:
    blocker_id = require_string(item, "id")
    reject_legacy_name(f"{blocker_id}.id", blocker_id)
    if blocker_id in seen:
        raise AssertionError(f"duplicate blocker id: {blocker_id}")
    seen.add(blocker_id)

    phase = require_string(item, "phase")
    if not phase.startswith("v"):
        raise AssertionError(f"{blocker_id}: phase must start with v")

    kind = require_string(item, "kind")
    if kind not in VALID_KINDS:
        raise AssertionError(f"{blocker_id}: invalid kind {kind!r}")

    status = require_string(item, "status")
    if status not in VALID_BLOCKER_STATUSES:
        raise AssertionError(f"{blocker_id}: invalid status {status!r}")

    check_string_list(item, "required_before", blocker_id, required=True)
    evidence = check_string_list(item, "evidence", blocker_id, required=True)
    for raw_path in evidence:
        rel_path = safe_relative_path(raw_path)
        actual_path = repo_root / rel_path
        if not actual_path.exists():
            raise AssertionError(f"{blocker_id}: missing evidence path {raw_path}")

    notes = require_string(item, "notes")
    reject_legacy_name(f"{blocker_id}.notes", notes)

    return blocker_id, status


def check_non_blocking_tracks(registry: dict[str, Any], repo_root: Path) -> int:
    tracks = registry.get("non_blocking_tracks", [])
    if not isinstance(tracks, list):
        raise AssertionError("non_blocking_tracks must be a list")

    seen_ids: set[str] = set()
    seen_former_blockers: set[str] = set()
    for item in tracks:
        if not isinstance(item, dict):
            raise AssertionError("each non-blocking track must be an object")

        track_id = require_string(item, "id")
        reject_legacy_name(f"{track_id}.id", track_id)
        if track_id in seen_ids:
            raise AssertionError(f"duplicate non-blocking track id: {track_id}")
        seen_ids.add(track_id)

        former_blocker = require_string(item, "former_blocker")
        reject_legacy_name(f"{track_id}.former_blocker", former_blocker)
        if former_blocker in seen_former_blockers:
            raise AssertionError(f"duplicate former blocker: {former_blocker}")
        seen_former_blockers.add(former_blocker)

        track_status = require_string(item, "status")
        if track_status not in VALID_TRACK_STATUSES:
            raise AssertionError(f"{track_id}: invalid non-blocking status {track_status!r}")

        if "workaround" in item:
            reject_legacy_name(f"{track_id}.workaround", require_string(item, "workaround"))

        evidence = check_string_list(item, "evidence", track_id, required=True)
        for raw_path in evidence:
            rel_path = safe_relative_path(raw_path)
            if not (repo_root / rel_path).exists():
                raise AssertionError(f"{track_id}: missing evidence path {raw_path}")

        notes = require_string(item, "notes")
        reject_legacy_name(f"{track_id}.notes", notes)

    return len(tracks)


def check_string_list(
    item: dict[str, Any], field: str, blocker_id: str, *, required: bool
) -> list[str]:
    value = item.get(field)
    if not isinstance(value, list) or (required and not value):
        raise AssertionError(f"{blocker_id}: {field} must be a list")
    seen: set[str] = set()
    result: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise AssertionError(f"{blocker_id}: {field} entries must be non-empty strings")
        reject_legacy_name(f"{blocker_id}.{field}", entry)
        if entry in seen:
            raise AssertionError(f"{blocker_id}: duplicate {field} entry {entry!r}")
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
