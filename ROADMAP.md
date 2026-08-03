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

### T027b-2c2 — whole-attempt target-open deadline and typed metrics contract

- **User result:** A future private direct-v3 target-open attempt can consume
  one absolute deadline across hostname resolution and every TCP connect
  attempt. Resolution cannot spend most of the budget and then silently grant
  connect a fresh full timeout. Fixed aggregate resolution/connect failure
  counters are recorded accurately once, without retaining a target or backend
  error.
- **Scope:** Add one crate-private direct-v3 opener API in `relay.rs` whose
  production entry accepts a structured target, port, the T027b-2c1 absolute
  attempt deadline, frozen egress policy, and the existing
  `TargetOpenMetricSinks`. Keep the old H2 public and crate-private openers
  unchanged. Use a private generic resolver/connector seam for paused-time,
  socket-free tests; discard lower-level errors at the new typed boundary and
  keep the existing `ServerRuntimeMetrics` owner and sink wiring unchanged.
- **Acceptance:** Reject an already expired deadline before invoking either
  seam; give connect only the time left after resolution; classify resolution
  timeout/failure, egress rejection, and connect timeout/failure with fixed,
  bounded, source-free errors; apply egress policy after resolution and before
  connect; increment exactly one existing failure counter for each timeout or
  backend failure and none for egress rejection; return a neutral synthetic
  success before the deadline; retain existing resolution/connect latency
  sinks; preserve every old H2 opener signature, two-stage timeout meaning,
  error meaning, and regression; and keep quiche endpoint/runtime production
  source free of any call to the new opener.
- **Out of scope:** No quiche actor integration, real target test, retained,
  transferred, or discarded real `TcpStream`, response, user DATA, relay,
  fallback, flow recovery or reset, slot reuse, public API, schema, wire or
  version change, new metrics owner or sink, `runtime_metrics.rs`, `server.rs`,
  quiche endpoint/runtime, core/config, manifest, lockfile, dependency, vendor,
  registry, client, SDK, CLI, `STATUS.md`, CI, remote, deployment, release,
  real-network, credential, infrastructure, or system-network work.
- **Stop conditions:** Stop before a fourth changed file; any need to change an
  existing H2 signature or timeout/error behavior, reset or extend the absolute
  deadline, call the opener from quiche production code, create a second metric
  owner or default sink, perform real target I/O in a test, retain a real target
  socket, emit target/policy/backend values, add a dependency, expose a public
  API, or change `STATUS.md` or any file outside the three-file allowlist.

This remains repository-local private opener API foundation only. Synthetic
tests and local loopback evidence are not a sandbox, H3 target-connectivity
result, product runtime, release result, or product result.

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
