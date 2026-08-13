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
accepted OD-01 through OD-09 in `docs/V1_3_CONVERGENCE_ADR.md` and delegated
the remaining project decisions in this thread to Codex on 2026-08-12. Codex
therefore places and decides the smallest playbook slices without returning
technical choices to the owner. This delegation does not authorize merging the
cumulative experimental tree, skipping a task gate, or treating a later
release, field run, provider resource, paid action, destructive action, or
Stable claim as completed before its own recorded prerequisites pass.

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

### B-001 through B-003 — quiche qualification, fork audit, and fixed direction

**User result.** Determine whether the owner's single selected H3/UDP backend,
quiche, can satisfy the same objective product gates without keeping a second
Quinn product stack.

**Scope.** B-003's direction is recorded: quiche is the only intended H3/UDP
product backend, and a failed gate leaves H3 disabled rather than reviving
Quinn. B-001 observes one subject, quiche, against a neutral Chrome reference
using one fixed local-only workload and objective matrix. It records
PASS/FAIL/UNKNOWN for TLS/QUIC/H3 behavior, exporter/capability facts,
weak-network behavior, maintenance cost, platform buildability, and
supply-chain cost. B-002 audits each preserved quiche patch for necessity,
named owner, upstream path, mechanical rebase test, security-update budget,
and independent delta review. Raw captures and key material remain outside
git; committed results must be normalized and privacy-safe.

**Non-goals.** No Quinn workload adapter or product implementation; no backend
feature work to improve a qualification result; no third backend, vendor
expansion, public API, real-network capture, system route/firewall/DNS change,
or claim of browser identity. The stopped Quinn-specific B-001 relay and D-004
work-in-progress are not submission candidates.

**Acceptance.** Quiche and the Chrome reference use the same observer and
workload where comparison is technically meaningful; every objective dimension
is PASS/FAIL/UNKNOWN. Any retained private quiche delta must satisfy the
complete fork budget. A pure-upstream candidate instead needs an explicit,
evidence-backed `DROP / not required` disposition for every old patch plus the
resolved security gates and proof, for the real H3 product feature on every
supported release target, of one Boring 5.x dependency/link closure, target
SBOM, and final artifact. Quinn removal is a separate, small, reviewable,
reversible code slice; it is not mixed into this
decision-only work. B-003 direction alone is not B-001/B-002, product,
security, fingerprint, native-Datagram, release, or real-network evidence.

**Stop conditions.** Stop if common observation is impossible, quiche requires
product/vendor patches to compete, a stable important fingerprint difference
is unexplained, a patch lacks an owner, required upstream route or still-valid
written cannot-upstream exception, or rebase path, a resource is
unbounded, or output would expose private capture material. On a failed gate,
keep H3 outside the product and Auto; do not fall back to Quinn.

**B-002 closure order.** S1 freezes the contract in
`docs/QUICHE_FORK_MAINTENANCE_POLICY.md` while keeping B-002 RED. After S1 is on
current main, S2 may add only the narrow byte-only verifier and synthetic
self-tests. S3 separately reconstructs historical patched source and accounts
for curated bytes, then a later narrow run replays the exact selected candidate.
Executable qualification and independent review remain separate and bind to
that exact candidate and replay. Outside S3-2B's exact-lock crates.io candidate
preparation, no slice may fetch source; no slice may contact upstream
implicitly, edit vendor or product/runtime Cargo code, or advance PR-4 merely
because the preceding document or tool exists. The sole S2 tooling exception
is one verifier target in the unpublished `maverick-tests` package, exact
tool-only `rustix`/`flate2` pins, exact `signal-hook 0.4.4` with default
features disabled, and a corresponding lockfile closure that S2 must still
prove. Only `signal-hook`'s safe high-level flag API may drive one `SeqCst`
`ACTIVE`/`SIGNALLED`/`COMMITTED` atomic; direct registry or signal-handler code,
first-party `unsafe`, timers, yields, and sentinel signals are forbidden; only
safe unregistration by returned registration ID is allowed. Exact
`INT`/`TERM`/`HUP` tests must cover deterministic barriers before final
manifest verification and after cleanup but before the sole success
compare-exchange. That compare-exchange is the result linearization point: a
signal ordered first makes the result RED, while a later signal cannot revoke
an already committed result. Signal-bearing tests run only in disposable child
processes that exit immediately after safe unregistration; no shared process
continues with altered signal disposition. It may build and self-test before
replay, but the already-built mechanical verifier must not invoke Cargo or
execute input code. Each old patch still needs its own evidence-backed `DROP`
or complete `RETAIN` result.

S3-2B adds no new queue step; it only permits a later separate default-off
`maverick-tests` `quiche-candidate` target with exact quiche 0.29.3/no quiche
features, direct exact Boring 5.1.0 and locked log 0.4.33 pins, the single
Boring closure, exact lockfile, and focused GNU/Linux/Apple public-PR steps.
The maximum implementation allowlist is `Cargo.lock`, the
test manifest, one integration test, `ci.yml`, and `STATUS.md`; root
`Cargo.toml` is not required and needs separate review if genuinely forced. Exact crates.io
preparation, including the inherited `boring-sys` packaged local Git
patch, stays outside Cargo-free mechanical replay; any source override or
clone/fetch/submodule path stops. Any typed/raw Boring bridge,
`unsafe`, Boring 4.x/second `links`, qlog/quiche feature, vendor/private patch,
or product/default CLI/SBOM/pilot/release/artifact leak stops. PASS remains
evaluation only, never disposition, replay, qualification, adoption, or H3.

S3-2D also adds no new queue step. It permits exactly one later slice to change
only the existing candidate test, the existing GNU/Linux/Apple candidate steps,
and `STATUS.md`. That slice must exercise the candidate-bound P3 mechanism with
`STATIC_MAX_LEVEL` fixed at Debug, a hostile logger and formatting counter,
both H3 roles, bidirectional HEADERS/QPACK literals/DATA, SETTINGS/control,
request `PRIORITY_UPDATE`, GOAWAY, and the existing in-memory QUIC pump under
fixed bounds. Its review must bind the exact upstream H3 logging-source surface
and call-site count. Both host steps must prove exactly one log 0.4.33,
`max_level_debug` present, and `max_level_trace`, `release_max_level_trace`, and
every other trace-widening feature absent; ordinary `default` and `std` are not
forbidden. Existing quiche/qlog/Boring and product isolation cannot change. No
manifest, lockfile, target, dependency, feature, P1, or P2 change is authorized.

A focused PASS remains mechanism/evaluation evidence only. P3 stays
`UNRESOLVED`; product/application and outer-QUIC logging, qlog, real product H3,
artifacts, replay, and qualification remain missing. P2 must wait for a
separately authorized, hash-fixed rebased P1 candidate: an `E0603` error or an
empty pure-upstream helper result is not its required unique proof. Any scope,
graph, source, bound, privacy, product, or claim drift stops; B-002 remains
**PARTIAL / RED**.

### Train A contract — v1.2 H2 RC/Stable

**User result.** Keep the better-proven Beta H2 path moving independently
without mistaking Beta.4 or old field/audit evidence for an exact Stable
candidate.

**Scope.** The owner approved R1 through R4 on 2026-08-12. The first Stable
support claim is Direct H2 only; provider-fronted H2 remains Beta. RC is a
prerelease and non-Latest; Stable is a non-prerelease and Latest. Immutable
`v1.2.0-beta.4` is the rollback partner. The exact RC requires an independent
security review, supply-chain checks, and no unresolved Critical or High
finding; a new paid third-party formal audit is optional. The complete policy
is frozen in `docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`.

RLC-001 and RLC-001b are merged bounded tooling. The tag verifier accepts
canonical positive Beta/RC tags while Stable remains a tested rejection. The
artifact verifier accepts the same canonical positive Beta/RC version line,
keeps Stable and malformed or foreign versions fail-closed, verifies the RC
fixture statically and natively on the current host, and statically locks the
unchanged publication workflow's single prerelease/non-Latest create command
behind final tag, exact six-file, checksum, digest, and release-note rechecks.
Independent exact-hash and privacy review, exact-head public checks, and merge
passed for those bounded tools only; they do not form a complete RC pipeline.

The next bounded v1.2 work is preparation of exact local RC inputs only after
their objective prerequisites are recorded and pass. It does not create a tag
or publication. No exact-RC package version, release note, archive, SBOM, tag,
or publication input currently exists; candidate preparation, security,
supply-chain, compatibility, Beta.4 rollback, field, artifact, and publication
gates remain RED. Only after every exact-RC gate passes may Codex record a
go/no-go decision for RLC-002 to add Stable non-prerelease/Latest
classification. No tag, release, publication, server, field run, spending,
paid audit, or Stable claim follows from either merged tooling slice.

**Acceptance.** The release contract makes Beta, RC, and Stable tag and release
behavior unambiguous and fail-closed. Exact-candidate Direct H2 field,
independent-security-review, supply-chain, compatibility, Beta.4 rollback,
artifact, and publication gates remain uncompleted until separately authorized
and performed. Beta.4 field/audit evidence is not inherited by a new RC.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

### QRET-1/QRET-2 — tombstone first, delete Quinn separately

QRET-1 is merged: it keeps the config-v1 field and default `false`, but makes
`true` fail closed with one fixed pre-I/O error while preserving H2. QRET-2
separately deletes current-tree Quinn product code, features, dependencies, and
the local loopback oracle. Neither slice adds quiche, Config v2, wire, Auto,
fallback, or UDP product work. A quiche product route may
begin only after its qualification and fork/supply-chain gates pass, through a
complete, runnable, migratable Product Config v2.

## Execution Order

1. **Close G-001 through G-004.** Preserve and classify first; never merge the
   cumulative tree.
2. **Run D-001/D-002/D-003 and B-001/B-002 in parallel.** The Datagram
   prototype is private. B-001 now qualifies only quiche against the neutral
   reference; B-002 must resolve the old private patches before quiche adoption.
   Do not submit the stopped Quinn-specific B-001 or D-004 work.
3. **Keep merged RLC-001 and RLC-001b as current truth and continue the
   remaining exact-RC gates.** Stable remains fail-closed until those gates pass
   and Codex records the RLC-002 go/no-go decision. This train does not wait for
   H3; tags, releases, field work, and Stable publication remain separate gated
   tasks.
4. **Keep QRET-1's tombstone and QRET-2's deletion as separate current-truth
   slices, then rebuild small stacked slices.** Auth core/spec, config
   convergence, direct H2 proof, gated quiche foundation/vendor and persistent
   session, Datagram adapters, consumers, and only then standard
   CONNECT-UDP/QUIC DATAGRAM. Keep the reversible Quinn deletion independent
   from quiche adoption.
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
- No new Quinn H3/UDP implementation, adapter, capture subject, or production
  D-004 work. QRET-2 removes current Quinn code and dependencies; immutable Git
  and archives remain provenance and a semantic oracle only.

## Failure-Driven Follow-Up

Use the shortest failure-driven next step:

- install failed -> simplify the artifact;
- daily use failed -> fix reliability/usability;
- TLS fingerprint was blocked -> improve the default TLS/handshake path;
- active probe distinguished the server -> harden handshake/fallback behavior;
- Beta baseline passed -> accept privacy-safe feedback, but do not recruit
  another user or widen platform, protocol, packaging, or governance scope
  without a recorded compatibility, safety, and evidence-based decision.

The Maverick protocol version, config version, and stored-profile schema
version remain `1` in the published Beta.4 release; existing authentication and
frame wire formats are unchanged. Any future version or wire-format change
requires a recorded compatibility decision based on observed user need.
