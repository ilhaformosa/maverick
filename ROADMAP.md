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

### T026b-2 — gate vendored quiche H3 trace logging before auth runtime

- **User result:** Before Maverick creates either role of an H3 connection or
  performs H3 I/O, its private shared quiche foundation enables a reviewed,
  connection-local, fail-closed privacy gate. For that connection, quiche H3
  and QPACK trace calls are not reached, so trace formatting cannot expose peer
  or local header names and values, encoded header blocks, or H3 stream and
  connection identifiers. This closes one foundation blocker only; it does not
  complete T026c or any product H3 runtime.
- **Scope:** Change only this queue, the private client quiche foundation, its
  existing strict-push integration proof, the three vendored H3 sources that
  contain trace calls, the one maintained T026b-2 patch, and vendor provenance.
  Add one clearly named H3 `Config` boolean and setter that default to `false`,
  copy the value into each H3 connection, and suppress every H3/QPACK trace
  before its arguments are formatted. The foundation unconditionally enables
  both the new privacy gate and the independent T026b-1 peer-push gate. Keep
  exact quiche 0.29.3, one `boring`/`boring-sys` 4.22.0 graph, and the current
  Cargo, lock, manifest, API, config, version, protocol, and unsafe boundaries.
- **Acceptance:** First reproduce with a real in-memory or `127.0.0.1` H3
  request that the current foundation emits QPACK literal header material to a
  trace logger. Then use the same real request/response path, SETTINGS/QPACK,
  and fragmented DATA handling to prove the gate yields zero records for all
  `quiche::h3` and QPACK trace targets, while default `false` still emits an H3
  sentinel and neutral synthetic peer markers. Prove both foundation roles use
  the shared builder by behavior, retain all fourteen strict-push controls and
  their empty `0x105` rejection, and rebuild the three final vendor source bytes
  by replaying the maintained patch against the accepted T026b-1 tree. All
  focused, package, formatting, lint, rustdoc, smoke, harness, dependency,
  exact-file, privacy, and `STATUS.md` gates must pass before one local commit.
- **Runtime and truth boundary:** Default `false` preserves quiche 0.29.3 trace
  behavior outside Maverick's foundation. The gate covers vendored H3 log
  records only. qlog is disabled and absent from the current dependency graph;
  explicitly enabling it later would reopen a separate review boundary. Outer
  QUIC transport logging is also separate. Public H3 header or event values may
  still be inspected by their caller, so later Maverick runtime must not log
  peer events with `Debug`. This queue is execution order, not a completion
  ledger; `STATUS.md` remains the only current product truth and authorization.
- **Out of scope:** T026c auth-v3 runtime, auth POST state, CONNECT or Extended
  CONNECT, authority/target/DNS/egress, UDP, relay or user data, fallback,
  public API/config/schema/version work, qlog, QUIC/TLS core changes, product or
  release claims, CI, push, PR, tag, publication, remote, deployment,
  real-network, and system-network work remain deferred. T026c restarts only
  after this prerequisite is accepted.
- **Stop conditions:** Stop if complete pre-format suppression needs a fourth
  vendored source, Cargo/dependency/public API/config/version/unsafe work, qlog,
  a QUIC transport redesign, real network or private data; if default
  compatibility, the independent T026b-1 gate, or any full local gate regresses;
  or if the maintained patch cannot reconstruct the exact authorized three-file
  vendored delta.

This slice is not tied to a release version, does not define v1.3 release scope,
and does not authorize CI, publication, push, deployment, or real-network work.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Wait for a concrete input.** Accept privacy-safe Beta feedback, a
   reproduced failure, or an explicit owner-defined minimal task. Do not infer
   a new product, release, deployment, or real-network authorization.
2. **Define one smallest slice.** Before implementation, put its user result,
   file scope, acceptance checks, out-of-scope boundary, and stop conditions in
   this queue. Preserve `STATUS.md` as the sole current-truth and authorization
   source.
3. **Keep stronger supply-chain claims deferred.** Provenance and attestation
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
