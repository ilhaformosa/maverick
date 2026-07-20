#!/usr/bin/env python3
"""Generate a redacted S2 evidence report draft from collected run outputs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path


PRIVATE_PATTERNS = (
    ("unix user home path", re.compile(r"/(?:Users|home)/[^/\s]+/")),
    ("Windows user home path", re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s]+\\")),
    (
        "IPv4 address",
        re.compile(
            r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
            r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
        ),
    ),
    ("bearer authorization", re.compile(r"\bBearer\s+\S+", re.IGNORECASE)),
    ("GitHub token", re.compile(r"\bgh[opusr]_[A-Za-z0-9_]+\b")),
    ("API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("API key environment name", re.compile(r"\b[A-Z0-9]+_API_KEY\b")),
    ("Maverick secret", re.compile(r"(?<![A-Za-z0-9_-])mv1_[A-Za-z0-9_-]{43,}(?![A-Za-z0-9_-])")),
    ("private key", re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY")),
)

LABELS = ("longhaul", "netem", "failure-injection")
AUDIT_GENERATED_NAMES = {
    "EVIDENCE_AUDIT.json",
    "EVIDENCE_AUDIT.md",
    "EVIDENCE_MANIFEST.sha256",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--longhaul", required=True, type=Path)
    parser.add_argument("--netem", required=True, type=Path)
    parser.add_argument("--failure-injection", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("runtime-evidence/s2-independent-evidence-draft.md"),
    )
    parser.add_argument(
        "--date",
        default=dt.datetime.now(dt.UTC).strftime("%Y-%m-%d"),
        help="Evidence date used in the report heading.",
    )
    parser.add_argument(
        "--commit",
        default="REPLACE_WITH_TESTED_COMMIT",
        help="Fallback tested commit or tagged build identifier.",
    )
    parser.add_argument(
        "--require-audited",
        action="store_true",
        help="Require an accepted EVIDENCE_AUDIT.json in every collection.",
    )
    args = parser.parse_args()

    runs = {
        "longhaul": load_run(args.longhaul, "longhaul", args.require_audited),
        "netem": load_run(args.netem, "netem", args.require_audited),
        "failure-injection": load_run(
            args.failure_injection, "failure-injection", args.require_audited
        ),
    }
    report = render_report(runs, args.date, args.commit)
    assert_public_safe(report)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"s2_evidence_report={args.output}")


def load_run(
    path: Path, expected_label: str, require_audited: bool = False
) -> dict[str, object]:
    summary_path = path / "SUMMARY.md"
    events_path = path / "events.log"
    collection_path = path / "COLLECTION.md"
    if not summary_path.is_file():
        raise SystemExit(f"missing {summary_path}")
    if not events_path.is_file():
        raise SystemExit(f"missing {events_path}")
    if collection_path.exists():
        assert_public_safe(collection_path.read_text(encoding="utf-8"))
    if require_audited:
        audit_path = path / "EVIDENCE_AUDIT.json"
        if not audit_path.is_file():
            raise SystemExit(f"missing accepted evidence audit: {audit_path}")
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        if audit.get("status") != "accepted":
            raise SystemExit(f"evidence audit is not accepted: {audit_path}")
        if audit.get("kind") != expected_label:
            raise SystemExit(f"evidence audit kind mismatch: {audit_path}")
        verify_manifest(path)

    summary_text = summary_path.read_text(encoding="utf-8")
    events_text = events_path.read_text(encoding="utf-8")
    assert_public_safe(summary_text)
    assert_public_safe(events_text)

    summary = parse_summary(summary_text)
    event_values = parse_event_values(events_text)
    for key, value in event_values.items():
        summary.setdefault(key, value)
    label = str(summary.get("label", expected_label))
    if label not in (expected_label, f"s2-{expected_label}"):
        raise SystemExit(f"{summary_path} does not look like {expected_label} evidence")

    return {
        "path": path,
        "summary": summary,
        "events": events_text,
        "stats": event_stats(events_text),
    }


def verify_manifest(path: Path) -> None:
    manifest_path = path / "EVIDENCE_MANIFEST.sha256"
    if not manifest_path.is_file():
        raise SystemExit(f"missing evidence manifest: {manifest_path}")

    declared: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([^\r\n]+)", line)
        if not match:
            raise SystemExit(f"invalid evidence manifest line: {manifest_path}")
        digest, relative = match.groups()
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise SystemExit(f"unsafe evidence manifest path: {relative}")
        declared[relative] = digest

    expected = {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
        if item.is_file() and item.name not in AUDIT_GENERATED_NAMES
    }
    if set(declared) != expected:
        raise SystemExit(f"stale evidence manifest file set: {manifest_path}")

    for relative, expected_digest in declared.items():
        actual = hashlib.sha256((path / relative).read_bytes()).hexdigest()
        if actual != expected_digest:
            raise SystemExit(f"evidence manifest hash mismatch: {relative}")


def parse_summary(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.match(r"^-?\s*([A-Za-z0-9_. -]+):\s*(.+)$", line)
        if not match:
            continue
        key = normalize_key(match.group(1))
        values[key] = match.group(2).strip("` ")
    return values


def parse_event_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.match(r"^([A-Za-z0-9_. -]+):\s*(.+)$", line)
        if not match:
            match = re.match(r"^([A-Za-z0-9_.-]+)=(.+)$", line)
        if not match:
            continue
        key = normalize_key(match.group(1))
        values[key] = match.group(2).strip("` ")
    return values


def normalize_key(key: str) -> str:
    return key.lower().strip().replace(" ", "_").replace("-", "_")


def event_stats(text: str) -> dict[str, int]:
    lines = [line for line in text.splitlines() if line.strip()]
    return {
        "lines": len(lines),
        "pass": sum(1 for line in lines if "PASS" in line or "result=pass" in line),
        "fail": sum(1 for line in lines if "FAIL" in line or "result=probe_failed" in line),
        "connect_fail": sum(1 for line in lines if "result=connect_fail" in line),
        "stall": sum(1 for line in lines if "result=stall_" in line),
        "fallback_fail": sum(1 for line in lines if "result=fallback_unavailable" in line),
    }


def render_report(runs: dict[str, dict[str, object]], date: str, commit: str) -> str:
    longhaul = runs["longhaul"]
    netem = runs["netem"]
    failure = runs["failure-injection"]
    return "\n".join(
        [
            f"# S2 Independent Evidence - {date}",
            "",
            "Status: evidence report for the `v0.1.0-beta.2` S2 gate.",
            "This is engineering evidence only. It is not a production-readiness,",
            "formal security-audit, anonymity, or censorship-resistance claim.",
            "",
            "Private hostnames, IP addresses, SSH aliases, usernames, provider",
            "resource names, certificate paths, generated secrets, and raw logs are",
            "intentionally omitted from this public report.",
            "",
            "## Scope",
            "",
            "- stable target: `maverick-tls-h2-cli-v1`",
            "- tested commits/builds: see per-run provenance below",
            "- server role: approved remote server VM",
            "- client role: second approved remote client VM",
            "- local workstation role: SSH orchestration and evidence collection only",
            "- transport: TLS 1.3 + HTTP/2",
            "- relay path: SOCKS5 TCP echo through Maverick",
            "",
            "The S2 runs did not change the developer workstation's system proxy, DNS,",
            "route table, firewall, VPN, or other network-service settings.",
            "",
            "## Run Provenance",
            "",
            render_run_provenance(runs, commit),
            "",
            "## Long-Haul Result",
            "",
            render_key_summary(
                longhaul,
                [
                    "run_id",
                    "tested_commit",
                    "started_utc",
                    "finished_utc",
                    "duration_secs",
                    "interval_secs",
                    "iterations",
                    "passed",
                    "failed",
                ],
            ),
            "",
            "## Network Impairment Result",
            "",
            render_key_summary(
                netem,
                [
                    "run_id",
                    "tested_commit",
                    "started_utc",
                    "finished_utc",
                    "scenario_profile",
                    "duration_secs",
                    "interval_secs",
                    "iterations",
                    "passed",
                    "failed",
                    "default_route_unchanged",
                    "global_dns_unchanged",
                    "remote_residue",
                    "iptables_residue",
                    "ip_forward_restored",
                    "resource_samples",
                ],
            ),
            "",
            "## Failure-Injection Result",
            "",
            render_key_summary(
                failure,
                [
                    "run_id",
                    "finished_utc",
                    "server_commit",
                    "client_commit",
                    "server_binary_version",
                    "client_binary_version",
                    "server_binary_sha256",
                    "client_binary_sha256",
                    "checks",
                    "pass_results",
                    "controlled_connect_failures",
                    "controlled_stall_results",
                    "controlled_fallback_failures",
                    "server_resource_samples",
                    "client_resource_samples",
                    "post_cleanup_ports",
                    "post_cleanup_firewall",
                    "post_cleanup_credentials",
                ],
            ),
            "",
            "## Event Log Counts",
            "",
            "| Run | Lines | PASS/result=pass | FAIL/probe_failed | Controlled connect failures | Controlled stall results | Controlled fallback failures |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            event_count_row("longhaul", longhaul),
            event_count_row("netem", netem),
            event_count_row("failure-injection", failure),
            "",
            "## Interpretation",
            "",
            "This report can support `v0.1.0-beta.2` only after the reviewed counts",
            "show zero unexpected failures for the claimed profiles and the remote",
            "evidence confirms the client host is distinct from the developer machine.",
            "",
            "It does not prove production readiness, anonymity, censorship resistance,",
            "native server-side ECH, GUI/App behavior, H3/QUIC stability, or behavior",
            "outside the recorded latency/loss profiles.",
            "",
            "## Reproduction Shape",
            "",
            "```sh",
            "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=REPLACE_WITH_APPROVED_SERVER_ADDRESS \\",
            "MAVERICK_PUBLIC_SMOKE_SERVER_NAME=REPLACE_WITH_APPROVED_SERVER_NAME \\",
            "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \\",
            "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT=1 \\",
            "MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 \\",
            "./scripts/s2-evidence-preflight.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST",
            "",
            "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \\",
            "MAVERICK_LONGHAUL_DURATION_SECS=86400 \\",
            "./scripts/approved-vm-detached-tcp-longhaul.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST",
            "",
            "MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 \\",
            "MAVERICK_NETEM_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \\",
            "./scripts/approved-vm-netem-impairment-smoke.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST",
            "",
            "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \\",
            "./scripts/approved-vm-failure-injection-smoke.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST",
            "```",
            "",
        ]
    )


def render_run_provenance(runs: dict[str, dict[str, object]], fallback: str) -> str:
    return "\n".join(
        f"- {label}: `{run_commit_value(run, fallback)}`"
        for label, run in runs.items()
    )


def run_commit_value(run: dict[str, object], fallback: str) -> str:
    summary = run["summary"]
    assert isinstance(summary, dict)

    tested = summary.get("tested_commit")
    if tested:
        return str(tested)

    server = summary.get("server_commit")
    client = summary.get("client_commit")
    if server and client:
        if server == client:
            return str(server)
        return f"server={server}, client={client}"
    if server:
        return f"server={server}"
    if client:
        return f"client={client}"
    return fallback


def render_key_summary(run: dict[str, object], keys: list[str]) -> str:
    summary = run["summary"]
    assert isinstance(summary, dict)
    lines = []
    for key in keys:
        if key in summary:
            lines.append(f"- {key}: `{summary[key]}`")
    if not lines:
        stats = run["stats"]
        assert isinstance(stats, dict)
        lines.append(f"- reviewed event lines: `{stats['lines']}`")
    return "\n".join(lines)


def event_count_row(label: str, run: dict[str, object]) -> str:
    stats = run["stats"]
    assert isinstance(stats, dict)
    return (
        f"| {label} | {stats['lines']} | {stats['pass']} | {stats['fail']} | "
        f"{stats['connect_fail']} | {stats['stall']} | {stats['fallback_fail']} |"
    )


def assert_public_safe(text: str) -> None:
    for label, pattern in private_patterns():
        match = pattern.search(text)
        if match:
            raise SystemExit(f"private pattern refused in S2 evidence: {label}")


def private_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    patterns = list(PRIVATE_PATTERNS)
    marker_path = os.environ.get("MAVERICK_PRIVATE_MARKERS_FILE")
    if not marker_path:
        return tuple(patterns)

    try:
        marker_file = Path(marker_path)
        if not marker_file.is_file() or marker_file.is_symlink():
            raise OSError
        markers = marker_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SystemExit("private marker file could not be read safely") from exc

    for raw_marker in markers:
        marker = raw_marker.strip()
        if not marker or marker.startswith("#"):
            continue
        patterns.append(("external private marker", re.compile(re.escape(marker), re.IGNORECASE)))
    return tuple(patterns)


if __name__ == "__main__":
    main()
