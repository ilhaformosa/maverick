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

### T027b-2b0 — server-owned native-quiche connection state

- **User result:** `maverick-server` can privately own and synchronously advance
  one real native-quiche server connection and its H3 state without depending
  on `maverick-client`. This is only an ownership seam; it is not a product H3
  path or user-visible transport result.
- **Scope:** Add one private, non-default `quiche-foundation` server feature that
  reuses the workspace-pinned quiche and Boring dependencies. Add one private
  connection-local engine with fixed packet and resource limits, TLS 1.3 and
  H3 ALPN checks, disabled 0-RTT, synchronous packet/timer driving, fixed safe
  errors, pre-authentication application-activity rejection, and local-only
  in-memory tests.
- **Acceptance:** Retain focused red-to-green evidence. Prove a synthetic
  client and the server-owned engine reach an established H3 connection, reject
  application activity before authentication, close explicitly, and release
  the owned connection state. Default, legacy H3, client quiche-foundation,
  strict-push, T023b/T026/T027, lint, dependency-tree, and local product gates
  remain green. The dependency graph remains acyclic with one version each of
  quiche, boring, and boring-sys.
- **Out of scope:** No UDP listener, registry, CID demultiplexer, async task,
  authentication runtime or policy, parser caller, target address, egress,
  DNS, connect, opener, TCP stream, relay, metrics, data plane, public API,
  config, protocol, frame, wire, schema, version, `STATUS.md`, CI, remote,
  deployment, release, or system-network change. The existing Quinn H3 runtime
  is unchanged.
- **Stop conditions:** Stop on a sixth changed file, a root-manifest or
  server-to-client product dependency, any public third-party type, a need for
  listener/demux/auth/parser/target/relay work, an unbounded queue or task, an
  async or unbounded connection engine, a default or legacy-H3 behavior change,
  a second quiche/Boring version, or any required regression failure.

This ownership seam is not a listener, authenticated runtime, parser caller,
target connection, data plane, product H3 result, or publication authorization.

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
