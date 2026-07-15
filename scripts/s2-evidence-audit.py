#!/usr/bin/env python3
"""Audit one private S2 evidence collection without exposing host details."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


GENERATED_NAMES = {
    "EVIDENCE_AUDIT.json",
    "EVIDENCE_AUDIT.md",
    "EVIDENCE_MANIFEST.sha256",
}
SECRET_PATTERNS = (
    ("maverick_secret", re.compile(rb"\bmv1_[A-Za-z0-9_-]{20,}\b")),
    ("private_key", re.compile(rb"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY")),
    ("bearer_token", re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/-]{16,}")),
    ("github_token", re.compile(rb"\bgh[opsu]_[A-Za-z0-9_]{20,}\b")),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("collection", type=Path)
    parser.add_argument("--require-accepted", action="store_true")
    args = parser.parse_args()

    result = audit_collection(args.collection)
    write_outputs(args.collection, result)
    print(f"s2_evidence_audit={result['status']}")
    print(f"s2_evidence_kind={result['kind']}")
    print(f"s2_evidence_files={result['manifest_file_count']}")
    if args.require_accepted and result["status"] != "accepted":
        raise SystemExit(1)


def audit_collection(collection: Path) -> dict[str, object]:
    if not collection.is_dir():
        raise SystemExit(f"missing collection directory: {collection}")

    summary_path = collection / "SUMMARY.md"
    events_path = collection / "events.log"
    collection_path = collection / "COLLECTION.md"
    for path in (summary_path, events_path, collection_path):
        if not path.is_file():
            raise SystemExit(f"missing required evidence file: {path.name}")

    summary_text = summary_path.read_text(encoding="utf-8", errors="replace")
    events_text = events_path.read_text(encoding="utf-8", errors="replace")
    collection_text = collection_path.read_text(encoding="utf-8", errors="replace")
    summary = parse_values(summary_text)
    collection_values = parse_values(collection_text)
    kind = infer_kind(summary_text)
    marker = collection_values.get("remote_marker", "unknown")
    reasons: list[str] = []

    if marker != "completed":
        reasons.append(f"remote marker is {marker}, not completed")

    manifest_entries = build_manifest(collection)
    secret_findings = scan_secrets(collection, manifest_entries)
    if secret_findings:
        reasons.append("secret-like material found in collected files")

    verify_binary_provenance(collection, summary, reasons)
    verify_final_cleanup(collection, kind, reasons)
    resource_evidence: dict[str, dict[str, object]] = {}
    if kind == "longhaul":
        resource_evidence = audit_longhaul(collection, summary, events_text, reasons)
    elif kind == "netem":
        resource_evidence = audit_netem(collection, summary, events_text, reasons)
    elif kind == "failure-injection":
        resource_evidence = audit_failure(collection, summary, events_text, reasons)
    else:
        reasons.append("unrecognized S2 summary type")

    return {
        "schema_version": 2,
        "status": "accepted" if not reasons else "diagnostic_only",
        "kind": kind,
        "remote_marker": marker,
        "manifest_file_count": len(manifest_entries),
        "manifest": manifest_entries,
        "secret_findings": secret_findings,
        "resource_evidence": resource_evidence,
        "checks": {
            "summary_present": True,
            "events_present": True,
            "collection_present": True,
            "binary_provenance_checked": True,
            "final_cleanup_checked": True,
            "resource_timing_checked": True,
        },
        "reasons": reasons,
    }


def parse_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        match = re.match(r"^-?\s*([A-Za-z0-9_. -]+):\s*(.+)$", raw_line.strip())
        if match:
            key = match.group(1).lower().replace("-", "_").replace(" ", "_")
            values[key] = match.group(2).strip("` ")
    return values


def infer_kind(summary_text: str) -> str:
    if "Long-Haul" in summary_text:
        return "longhaul"
    if "Netem Impairment" in summary_text:
        return "netem"
    if "Failure Injection" in summary_text:
        return "failure-injection"
    return "unknown"


def build_manifest(collection: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(p for p in collection.rglob("*") if p.is_file()):
        if path.name in GENERATED_NAMES:
            continue
        data = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(collection).as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return entries


def scan_secrets(
    collection: Path, manifest: list[dict[str, object]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for entry in manifest:
        relative = str(entry["path"])
        data = (collection / relative).read_bytes()
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                findings.append({"path": relative, "pattern": label})
    return findings


def verify_binary_provenance(
    collection: Path, summary: dict[str, str], reasons: list[str]
) -> None:
    inventories = sorted(collection.glob("*-logs/system-inventory.log"))
    versions = sorted(collection.glob("*-logs/binary-version.log"))
    if len(inventories) != 2:
        reasons.append("expected client and server system inventory logs")
    else:
        hashes = []
        for path in inventories:
            match = re.search(
                r"^binary_sha256=([a-f0-9]{64})$",
                path.read_text(encoding="utf-8", errors="replace"),
                re.MULTILINE,
            )
            if not match:
                reasons.append(f"missing binary hash in {path.parent.name}")
            else:
                hashes.append(match.group(1))
        if len(hashes) == 2 and len(set(hashes)) != 1:
            reasons.append("client and server binary hashes differ")
        if len(hashes) == 2:
            for key in ("server_binary_sha256", "client_binary_sha256"):
                if key in summary and summary[key] != hashes[0]:
                    reasons.append(f"{key} differs from inventory hash")

    if len(versions) != 2:
        reasons.append("expected client and server binary version logs")
    else:
        values = [path.read_text(encoding="utf-8", errors="replace").strip() for path in versions]
        if len(set(values)) != 1:
            reasons.append("client and server binary versions differ")
        if len(set(values)) == 1:
            for key in ("server_binary_version", "client_binary_version"):
                if key in summary and summary[key] != values[0]:
                    reasons.append(f"{key} differs from version log")


def verify_final_cleanup(
    collection: Path, kind: str, reasons: list[str]
) -> None:
    records = sorted(
        path
        for path in collection.iterdir()
        if path.is_file() and "cleanup" in path.name.lower() and path.suffix == ".log"
    )
    if not records:
        reasons.append("missing final remote cleanup record")
        return
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in records
    )
    if "cleanup_status=ok" in text:
        return

    legacy_markers = {
        "longhaul": ("server_residue=absent", "client_residue=absent"),
        "netem": ("server_residue=absent", "client_directory_residue=absent"),
        "failure-injection": (
            "process_residue=absent",
            "client_process_residue=absent",
        ),
    }
    required = legacy_markers.get(kind, ())
    if not required or any(marker not in text for marker in required):
        reasons.append("final remote cleanup record is not successful")


def audit_longhaul(
    collection: Path,
    summary: dict[str, str],
    events: str,
    reasons: list[str],
) -> dict[str, dict[str, object]]:
    duration_secs = int_value(summary, "duration_secs", reasons)
    interval_secs = int_value(summary, "interval_secs", reasons)
    resource_interval_secs = int_value(summary, "resource_interval_secs", reasons)
    iterations = int_value(summary, "iterations", reasons)
    passed = int_value(summary, "passed", reasons)
    failed = int_value(summary, "failed", reasons)
    if None not in (iterations, passed, failed) and passed + failed != iterations:
        reasons.append("long-haul summary counts do not add up")

    event_pass = sum(line.startswith("PASS ") for line in events.splitlines())
    event_fail = sum(line.startswith("FAIL ") for line in events.splitlines())
    if passed is not None and event_pass != passed:
        reasons.append("long-haul PASS event count differs from summary")
    if failed is not None and event_fail != failed:
        reasons.append("long-haul FAIL event count differs from summary")

    expected_logs = {
        "client_log_count": len(list(collection.glob("client-logs/logs/client-*.log"))),
        "probe_log_count": len(list(collection.glob("client-logs/logs/probe-*.log"))),
        "failure_log_count": len(list(collection.glob("client-logs/logs/failure-*.log"))),
    }
    for key, actual in expected_logs.items():
        expected = int_value(summary, key, reasons)
        if expected is not None and expected != actual:
            reasons.append(f"{key} differs from collected files")
    verify_longhaul_window(summary, duration_secs, interval_secs, reasons)
    timing = None
    if None not in (duration_secs, interval_secs, resource_interval_secs):
        timing = (duration_secs, interval_secs, resource_interval_secs)
    evidence = require_resource_samples(
        collection, summary, reasons, continuous_timing=timing
    )
    require_process_child_evidence("longhaul", summary, evidence, reasons)
    return evidence


def audit_netem(
    collection: Path,
    summary: dict[str, str],
    events: str,
    reasons: list[str],
) -> dict[str, dict[str, object]]:
    compare_event_counts(summary, events, reasons)
    require_value(summary, "default_route_unchanged", "true", reasons)
    require_value(summary, "global_dns_unchanged", "true", reasons)
    require_value(summary, "remote_residue", "absent", reasons)
    require_value(summary, "iptables_residue", "absent", reasons)
    require_value(summary, "ip_forward_restored", "true", reasons)
    evidence = require_resource_samples(collection, summary, reasons)
    require_process_child_evidence("netem", summary, evidence, reasons)
    return evidence


def audit_failure(
    collection: Path,
    summary: dict[str, str],
    events: str,
    reasons: list[str],
) -> dict[str, dict[str, object]]:
    checks = int_value(summary, "checks", reasons)
    event_checks = sum(line.startswith("CHECK ") for line in events.splitlines())
    if checks is not None and checks != event_checks:
        reasons.append("failure-injection CHECK count differs from summary")
    expected_counts = {
        "pass_results": events.count("result=pass"),
        "controlled_connect_failures": events.count("result=connect_fail"),
        "controlled_stall_results": len(re.findall(r"result=stall_(?:timeout|closed)", events)),
        "controlled_fallback_failures": events.count("result=fallback_unavailable"),
    }
    for key, actual in expected_counts.items():
        declared = int_value(summary, key, reasons)
        if declared is not None and declared != actual:
            reasons.append(f"{key} differs from event log")
    if checks is not None and sum(expected_counts.values()) != checks:
        reasons.append("failure-injection result categories do not add up to checks")
    require_value(summary, "post_cleanup_ports", "free", reasons)
    require_value(summary, "post_cleanup_firewall", "closed_or_disabled", reasons)
    require_value(summary, "post_cleanup_credentials", "absent", reasons)
    evidence = require_resource_samples(collection, summary, reasons)
    require_process_child_evidence("failure-injection", summary, evidence, reasons)
    return evidence


def compare_event_counts(
    summary: dict[str, str], events: str, reasons: list[str]
) -> None:
    passed = int_value(summary, "passed", reasons)
    failed = int_value(summary, "failed", reasons)
    event_pass = sum(line.startswith("PASS ") for line in events.splitlines())
    event_fail = sum(line.startswith("FAIL ") for line in events.splitlines())
    if passed is not None and passed != event_pass:
        reasons.append("PASS event count differs from summary")
    if failed is not None and failed != event_fail:
        reasons.append("FAIL event count differs from summary")


def require_resource_samples(
    collection: Path,
    summary: dict[str, str],
    reasons: list[str],
    *,
    continuous_timing: tuple[int, int, int] | None = None,
) -> dict[str, dict[str, object]]:
    client_path = collection / "client-logs/resource-metrics.log"
    server_path = collection / "server-logs/resource-metrics.log"
    observed: dict[str, int] = {}
    evidence: dict[str, dict[str, object]] = {}
    for role, path in (("client", client_path), ("server", server_path)):
        if not path.is_file():
            reasons.append(f"missing {role} resource metrics")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        raw_timestamps = [
            line.removeprefix("sample_utc=")
            for line in lines
            if line.startswith("sample_utc=")
        ]
        count = len(raw_timestamps)
        completed = sum(line == "sample_end" for line in lines)
        observed[role] = count
        if count == 0:
            reasons.append(f"{role} resource metrics contain no samples")
        if completed != count:
            reasons.append(f"{role} resource sample blocks are incomplete")

        timestamps: list[datetime] = []
        invalid_timestamp = False
        for value in raw_timestamps:
            parsed = parse_utc_timestamp(value)
            if parsed is None:
                invalid_timestamp = True
            else:
                timestamps.append(parsed)
        if invalid_timestamp:
            reasons.append(f"{role} resource metrics contain invalid timestamps")

        gaps = [
            int((current - previous).total_seconds())
            for previous, current in zip(timestamps, timestamps[1:])
        ]
        if any(gap < 0 for gap in gaps):
            reasons.append(f"{role} resource timestamps are not monotonic")
        nonnegative_gaps = [gap for gap in gaps if gap >= 0]
        coverage_secs = (
            int((timestamps[-1] - timestamps[0]).total_seconds())
            if timestamps
            else 0
        )
        evidence[role] = {
            "sample_count": count,
            "complete_sample_count": completed,
            "first_sample_utc": raw_timestamps[0] if raw_timestamps else None,
            "last_sample_utc": raw_timestamps[-1] if raw_timestamps else None,
            "coverage_secs": coverage_secs,
            "max_gap_secs": max(nonnegative_gaps, default=0),
            "maverick_process_rows": sum(
                re.search(r"\bmaverick\s*$", line) is not None for line in lines
            ),
        }

    declared = summary.get("resource_samples")
    if declared and declared.isdigit() and client_path.is_file():
        actual = sum(
            line.startswith("sample_utc=")
            for line in client_path.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if int(declared) != actual:
            reasons.append("client resource sample count differs from summary")
    elif declared:
        reasons.append("resource_samples is not an integer")

    for role in ("client", "server"):
        key = f"{role}_resource_samples"
        if key in summary:
            if not summary[key].isdigit():
                reasons.append(f"{key} is not an integer")
            elif role in observed and int(summary[key]) != observed[role]:
                reasons.append(f"{key} differs from collected metrics")

    if continuous_timing is not None:
        duration_secs, client_interval_secs, server_interval_secs = continuous_timing
        for role, interval_secs in (
            ("client", client_interval_secs),
            ("server", server_interval_secs),
        ):
            details = evidence.get(role)
            if details is None:
                continue
            coverage_tolerance = max(interval_secs * 2, 120)
            minimum_coverage = max(0, duration_secs - coverage_tolerance)
            if int(details["coverage_secs"]) < minimum_coverage:
                reasons.append(f"{role} resource metrics do not cover the long-haul window")
            maximum_gap = max(interval_secs + 45, (interval_secs * 3) // 2)
            if int(details["max_gap_secs"]) > maximum_gap:
                reasons.append(f"{role} resource metrics contain an excessive time gap")

    return evidence


def parse_utc_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def verify_longhaul_window(
    summary: dict[str, str],
    duration_secs: int | None,
    interval_secs: int | None,
    reasons: list[str],
) -> None:
    started = parse_utc_timestamp(summary.get("started_utc", ""))
    finished = parse_utc_timestamp(summary.get("finished_utc", ""))
    if started is None or finished is None:
        reasons.append("long-haul summary has invalid start or finish timestamp")
        return
    if duration_secs is None or interval_secs is None:
        return
    elapsed_secs = int((finished - started).total_seconds())
    if elapsed_secs < duration_secs - 5:
        reasons.append("long-haul summary duration is shorter than declared")
    if elapsed_secs > duration_secs + max(interval_secs, 300):
        reasons.append("long-haul summary duration is unexpectedly long")


def require_process_child_evidence(
    kind: str,
    summary: dict[str, str],
    evidence: dict[str, dict[str, object]],
    reasons: list[str],
) -> None:
    if summary.get("resource_process_children") != "enabled":
        return
    required_roles = ("server",) if kind == "netem" else ("client", "server")
    for role in required_roles:
        details = evidence.get(role, {})
        if int(details.get("maverick_process_rows", 0)) == 0:
            reasons.append(f"{role} resource metrics contain no Maverick child process rows")


def int_value(
    values: dict[str, str], key: str, reasons: list[str]
) -> int | None:
    value = values.get(key)
    if value is None or not value.isdigit():
        reasons.append(f"missing or invalid integer field: {key}")
        return None
    return int(value)


def require_value(
    values: dict[str, str], key: str, expected: str, reasons: list[str]
) -> None:
    if values.get(key) != expected:
        reasons.append(f"{key} is not {expected}")


def write_outputs(collection: Path, result: dict[str, object]) -> None:
    manifest = result["manifest"]
    assert isinstance(manifest, list)
    manifest_text = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in manifest
    )
    (collection / "EVIDENCE_MANIFEST.sha256").write_text(
        manifest_text, encoding="utf-8"
    )

    serializable = dict(result)
    serializable.pop("manifest", None)
    (collection / "EVIDENCE_AUDIT.json").write_text(
        json.dumps(serializable, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    reasons = result["reasons"]
    assert isinstance(reasons, list)
    lines = [
        "# S2 Evidence Audit",
        "",
        f"- status: {result['status']}",
        f"- kind: {result['kind']}",
        f"- remote_marker: {result['remote_marker']}",
        f"- manifest_file_count: {result['manifest_file_count']}",
        f"- secret_findings: {len(result['secret_findings'])}",
        "",
        "## Reasons",
        "",
    ]
    lines.extend(f"- {reason}" for reason in reasons)
    if not reasons:
        lines.append("- none")
    resource_evidence = result["resource_evidence"]
    assert isinstance(resource_evidence, dict)
    lines.extend(["", "## Resource Evidence", ""])
    for role in ("client", "server"):
        details = resource_evidence.get(role)
        if not isinstance(details, dict):
            lines.append(f"- {role}: unavailable")
            continue
        lines.append(
            f"- {role}: samples={details['sample_count']}, "
            f"complete={details['complete_sample_count']}, "
            f"coverage_secs={details['coverage_secs']}, "
            f"max_gap_secs={details['max_gap_secs']}, "
            f"maverick_process_rows={details['maverick_process_rows']}"
        )
    lines.extend(
        [
            "",
            "The SHA-256 manifest covers every collected source file except the",
            "generated audit and manifest files themselves.",
            "",
        ]
    )
    (collection / "EVIDENCE_AUDIT.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
