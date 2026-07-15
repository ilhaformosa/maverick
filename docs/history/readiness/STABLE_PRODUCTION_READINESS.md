# Stable And Production Readiness

Status: superseded pre-publication readiness assessment. Its initial
publication conclusion did not include the later complete history audit. See
`docs/OPEN_SOURCE_PHASE1_GO_NO_GO_2026_07_15.md` for the current source
publication decision.

At the time of this assessment, Maverick was considered ready for an
experimental as-is source snapshot. It was not a stable or production-ready
protocol release.

This document defines how to get there.

## Direct Answer

If formal security audit is ignored, Maverick has enough evidence for a public
alpha or pre-stable source snapshot and is moving toward a narrow stable-scope
candidate. A 24-hour approved-host TCP/H2 baseline now exists for the narrow
stable-scope runtime path, process-level failure-injection evidence now exists
for server restart, client restart, upstream target failure, and upstream stall
or timeout, and a diagnostic approved-host netem rerun passed for the tested
TCP/H2 latency/loss profiles. Maverick should still not be called
production-ready until production-scoped network-impairment evidence and
operator rollout evidence exist for the exact deployment scope being claimed.

The project can become stable for a narrow documented scope before it becomes
production-ready. For example, a stable scope could be:

- CLI-managed client/server;
- TLS 1.3 + HTTP/2 only;
- TCP relay, DNS relay, and explicitly documented UDP relay behavior;
- no native ECH claim;
- no strong anonymity or censorship-resistance claim;
- no GUI/App packaging claim.

## Stable-Scope Candidate Status

The first candidate scope is defined in `docs/STABLE_SCOPE_CANDIDATE.md` as
`maverick-tls-h2-cli-v1`.

| Item | Status | Evidence |
| --- | --- | --- |
| Named protocol scope and exclusions | Ready for candidate | `docs/STABLE_SCOPE_CANDIDATE.md`, `docs/SPEC_FREEZE_PROCESS.md` |
| Compatibility and migration policy | Ready for candidate | `COMPATIBILITY.md`, `MIGRATIONS.md`, migration tests |
| Local harness and conformance coverage | Ready for candidate | `./scripts/local-harness.sh`, `./scripts/conformance.sh` |
| Approved-host long-haul evidence | 24-hour baseline complete for TCP/H2 stable-scope runtime path | `docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_01.md`, `docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_03.md`, `./scripts/approved-vm-detached-tcp-longhaul.sh` |
| Approved-host failure injection | Process-level pack complete for server restart, client restart, upstream target failure, and upstream stall or timeout | `docs/history/evidence/APPROVED_HOST_FAILURE_INJECTION_EVIDENCE_2026_07_03.md`, `./scripts/approved-vm-failure-injection-smoke.sh` |
| Approved-host network impairment | Diagnostic 8-hour rerun passed for the tested TCP/H2 latency/loss profiles | `docs/history/evidence/APPROVED_HOST_NETEM_IMPAIRMENT_EVIDENCE_2026_07_04.md`, `./scripts/approved-vm-netem-impairment-smoke.sh` |
| Release artifacts and checksums | Ready for candidate | `./scripts/release-artifacts.sh`, `docs/RELEASE_ARTIFACTS.md` |
| Operator documentation | Ready for candidate | `docs/OPERATIONS.md`, `examples/systemd/` |
| Support and breaking-change policy | Ready for candidate | `SUPPORT.md`, `docs/RELEASE_TAGGING.md` |
| Dependency advisory and first-party unsafe inventory | Ready for candidate | `./scripts/security-dependency-inventory.sh` |

## What Blocks Production Status

Production status requires more than stable protocol behavior:

- Network-impairment tests under realistic latency and packet-loss conditions.
  A 24-hour approved-host TCP/H2 baseline and process-level failure-injection
  pack have passed; a diagnostic approved-host netem rerun passed 96/96
  iterations for the tested TCP/H2 latency/loss profiles on 2026-07-04.
  Broader production claims still need evidence for the exact operating
  conditions, duration, topology, and rollout model being claimed.
- Abuse and denial-of-service controls, including auth-attempt pacing or
  rate-limiting, connection caps, memory bounds, and fallback load behavior.
- Operational observability with redacted metrics and logs.
- Hardened deployment profiles for Linux services, certificates, permissions,
  user isolation, and rollback.
- Backup and rotation procedures for secrets and credentials.
- Clear incident response and vulnerability handling process.
- Community or independent security review for any stronger security claims.

Native server-side ECH is not mandatory for a production TLS/H2 proxy scope if
the release clearly says there is no native ECH support. It is mandatory only
for a release that claims native Maverick ECH.

## Recommended Implementation Path

### Phase 1: Public Alpha

Goal: make the repo public without overclaiming.

- Tag `v0.1.0-alpha.1`.
- Publish release notes from `docs/history/release/RELEASE_NOTES_v0.1.0-alpha.1.md`.
- Keep every experimental feature default-off or gated.
- Accept community feedback and issue reports.

### Phase 2: Stability Candidate

Goal: freeze a narrow, useful protocol scope.

- Declare the stable target scope in `SPEC.md`.
- Add frozen conformance vector snapshots for the target scope.
- Add compatibility tests for old example configs.
- Require `./scripts/local-harness.sh`,
  `./scripts/security-dependency-inventory.sh`, and H2/H3 targeted harnesses
  before every candidate tag.
- Keep the 24-hour approved-host long-haul smoke evidence current before a
  stable tag, especially if runtime crates or stable-scope behavior change.
  Use `./scripts/approved-vm-detached-tcp-longhaul.sh` when the local developer
  machine may restart during the run.

### Phase 3: Operational Hardening

Goal: make self-hosted deployments predictable.

- Keep systemd service examples and rollback instructions current.
- Keep deployment docs for certificate renewal, config permissions, logging, and
  metrics current.
- Maintain auth-attempt rate limiting and connection/memory pressure tests.
- Add failure injection tests for server restart, client reconnect, upstream
  timeout, fallback target failure, and packet loss. The process-level pack is
  complete; keep packet loss and latency impairment separate from host-level
  network settings unless an isolated approved test host is available. The
  2026-07-04 diagnostic approved-host netem rerun passed cleanly for the tested
  TCP/H2 profiles.

### Phase 4: Production Scope Decision

Goal: decide what "production" means for Maverick.

Options:

- Source-only production scope: documented build and deploy process, no binary
  packaging claim.
- Linux server production scope: packaged service, systemd, hardening profile,
  upgrade/rollback, monitoring.
- Product/client production scope: separate macOS app or other client runtime,
  signed/notarized app, Packet Tunnel or equivalent platform integration.

Each scope needs separate verification and release notes.

## Non-Goals For Initial Stable Scope

These should not block a narrow stable TLS/H2 release unless the release claims
them:

- native server-side ECH;
- post-quantum hybrid handshakes;
- GUI/App packaging;
- strong anonymity or traffic-analysis resistance guarantees.

They remain useful future tracks, but they are not required for a carefully
scoped stable release.
