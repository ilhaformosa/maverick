# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Planning Input Rule

Design drafts and reconciliation notes are non-authoritative planning inputs.
When they conflict, `STATUS.md` alone controls current truth and authorization,
while `ROADMAP.md` controls execution order. Only a minimal slice placed here
enters execution; every other proposal remains deferred, neither automatically
adopted nor automatically rejected.

## Current Repository-Local Queue

The current authorization boundary is recorded in `STATUS.md`. The owner
accepted OD-01 through OD-09 in `docs/V1_3_CONVERGENCE_ADR.md` on 2026-08-12.
Together they place the ordered recovery and architecture work below in the
queue. They do not authorize merging the cumulative experimental tree, skipping
a task gate, releasing, tagging, running a field test, creating a server,
changing a provider or host network, spending, or making a Stable claim.

### G-001 through G-004 — v1.3 recovery and convergence governance

**User result.** Preserve the cumulative experiment so useful work cannot be
lost, obtain an independent exact-head quality baseline, classify every commit,
and freeze the owner decisions before new architecture code is written.

**Scope.** Five immutable remote archive branches; one Draft `DO NOT MERGE` CI
baseline; the one-time merge manifest; the single convergence ADR; this queue.
Do not delete or rewrite an old branch, merge the cumulative tree, turn the
manifest into a registry, or promote recovery activity in `STATUS.md` into a
product result.

**Acceptance.** Each archive ref resolves to its recorded SHA and rejects
update/deletion; all 77 commits have one preliminary recovery destination; the
Draft baseline records every exact-head remote result without a rerun; OD-01
through OD-09 are explicit; the working tree is privacy-safe and reviewable.

**Stop conditions.** Stop on SHA drift, an unprotected archive ref, a PR head
change, an attempt to merge or mark the baseline ready, a private string, or a
need for another coordination framework.

### D-001 through D-003 — Datagram contract, private prototype, and proof

**User result.** Prove, without timing luck, that a target datagram can still be
received while one send remains blocked. This replaces the next scheduling
micro-patch with the owner-approved association ownership direction.

**Scope.** First review the D-001 contract in
`docs/DATAGRAM_SEMANTIC_CONTRACT.md`. Establish the deterministic old-worker
D-003 RED before writing the smallest D-002 test/private actor; then use that
same D-003 proof as the GREEN. Use explicit barriers and bounded queues/bytes.
A send command must have a carrier-specific completion point. Preserve one
terminal owner and fixed privacy-safe errors.

**Non-goals.** No existing public API change; no production TUN/SOCKS/server or
carrier migration; no H2/H3 adapter; no CONNECT-UDP, QUIC DATAGRAM, config,
auth, wire, Auto, fallback, release, or real-network behavior; no public
test-support symbol.

**Acceptance.** The old worker deterministically demonstrates the blocked-send
gap; the private actor delivers receive `B` before blocked send `A` completes;
`A` is neither canceled nor duplicated; barrier release completes it exactly
once; cancel/close releases all fake owners, tasks, queues, bytes, and completion
signals. No wall-clock sleep or probabilistic timeout is causal evidence.

**Stop conditions.** Stop if the proof needs a public API, dependency or wire
change, `Arc<Mutex<transport>>`, a per-packet task, an unbounded resource, a
sleep-based order, hidden retry/replay, or a real-carrier claim from fake data.

### B-001 and B-002 — capture-only backend bakeoff and fork audit

**User result.** Give the owner comparable evidence for Quinn, quiche, or
neither without adding features to make either candidate look better.

**Scope.** Freeze one common local-only workload and observation method;
compare TLS/QUIC/H3 behavior, exporter/capability facts, weak-network behavior,
maintenance cost, and supply-chain cost. Audit each quiche patch for necessity,
owner, upstream path, mechanical rebase test, security-update budget, and
independent delta review. Raw captures and key material remain outside git;
committed results must be normalized and privacy-safe.

**Non-goals.** No backend feature development, product selection, third backend,
vendor expansion, public API, real-network capture, system route/firewall/DNS
change, or claim of browser identity.

**Acceptance.** Both candidates are measured with the same method and workload;
each dimension is PASS/FAIL/UNKNOWN; B-002 either satisfies the complete fork
budget or remains red; a later B-003 asks the owner to select exactly one of
Quinn, quiche, or neither.

**Stop conditions.** Stop if common observation is impossible, a candidate
requires product/vendor patches to compete, a stable important fingerprint
difference is unexplained, a patch lacks an owner/upstream/rebase path, a
resource is unbounded, or output would expose private capture material.

### Train A planning — v1.2 H2 RC/Stable release contract

**User result.** Keep the better-proven Beta H2 path moving independently
without mistaking Beta.4 or old field/audit evidence for an exact Stable
candidate.

**Scope.** First obtain owner decisions on the supported H2 TrustRoute,
RC/Stable GitHub Release classification, Beta.4 rollback pair, and exact-RC
security-review meaning. Only then define a separate RED/GREEN release-tooling
slice. No tag, release, publication, server, field run, or Stable claim is
authorized here.

**Acceptance.** The approved release contract makes Beta, RC, and Stable tag
and release behavior unambiguous and fail-closed; exact-candidate field,
security, compatibility, rollback, and publication gates remain visibly
uncompleted until separately authorized and performed.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Close G-001 through G-004.** Preserve and classify first; never merge the
   cumulative tree.
2. **Run D-001/D-002/D-003 and B-001/B-002 in parallel.** The Datagram
   prototype is private; the backend work is measurement-only.
3. **Prepare the v1.2 release contract independently.** It does not wait for
   H3, but implementation waits for its named owner decisions.
4. **Rebuild small stacked slices.** Auth core/spec, config convergence, direct
   H2 proof, the chosen H3 backend/session, Datagram adapters, consumers, and
   only then standard CONNECT-UDP/QUIC DATAGRAM.
5. **Keep stronger supply-chain claims deferred.** Provenance and attestation
   need an explicit identity and remote-permission design; signatures need a
   trust-root and key-custody decision; reproducible builds need a separate
   byte-for-byte build experiment. An SBOM is not any of those things.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work without a reproduced Beta need and an explicit
  compatibility and security decision.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No rustls fork or vendored unmerged server-ECH patch in the current execution
  plan.
- No remote, paid, privileged, or host-network action outside the current
  authorization recorded in `STATUS.md`.
- No T025g-style scheduling micro-patch, long-term dual H3 product backend,
  permanent policy-only Product Config v2, giant 77-commit merge, or H3 in Auto.

## Failure-Driven Follow-Up

Use the shortest failure-driven next step:

- install failed -> simplify the artifact;
- daily use failed -> fix reliability/usability;
- TLS fingerprint was blocked -> improve the default TLS/handshake path;
- active probe distinguished the server -> harden handshake/fallback behavior;
- Beta baseline passed -> accept privacy-safe feedback, but do not recruit
  another user or widen platform, protocol, packaging, or governance scope
  without a separate owner decision.

The Maverick protocol version, config version, and stored-profile schema
version remain `1` in the published Beta.4 release; existing authentication and
frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
