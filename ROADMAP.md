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

### T027b-2c1 — actor-owned bounded target-open dispatch lifecycle

- **User result:** Each private direct-v3 H3 connection actor owns one fixed,
  cancellable collection of at most eight directly polled target-open dispatch
  futures. Slow synthetic work cannot block that actor's UDP, QUIC timer, or
  bounded flush progress. Ordinary actor termination and forced parent abort
  both synchronously drop the collection to zero before the parent task is
  joined and its registry capacity can be reclaimed.
- **Scope:** Keep admitted, in-flight, and waiting-next-stage work inside the
  existing eight `PendingClassicConnect` slots; add one-shot dispatch state and
  an owned, value-free-Debug token containing the structured target, port,
  stream, generation, frozen read-only egress facts, and one absolute attempt
  deadline. Derive that deadline once as the checked minimum of the T027b-2c0
  public config-v3 `target_open` timeout and the authenticated generation's
  hard deadline. Give each connection actor a private `FuturesUnordered`
  collection capped at eight and a minimal injectable synthetic future seam;
  create no per-dispatch Tokio task, and keep the non-test path unavailable and
  fail closed.
- **Acceptance:** Dispatch an admitted stream exactly once; recheck the same
  active, unrevoked generation plus strict admission and hard bounds before
  dispatch; retain all eight slots while their futures are active; keep actor
  protocol work moving while eight synthetic attempts block; process ready
  completions in bounded rounds; recheck generation, revocation, hard expiry,
  and the absolute attempt deadline before accepting a completion; catch a
  future error or panic at the actor-owned polling boundary, fail the
  generation, and synchronously drop siblings. Drop every dispatch future on
  endpoint cancel, inbox close, hard expiry, revocation, peer or local close,
  actor failure, ordinary endpoint shutdown, and shutdown-budget forced parent
  abort. Observe the parent task join only after those drops, then reclaim its
  registry entry. Errors, Debug, and panic text remain fixed and contain no
  target, port, address, policy, credential, backend error, or other private
  value.
- **Out of scope:** No DNS, address resolution, TCP target connection, real
  opener, target socket or listener, success response, user DATA, relay,
  fallback, flow-local recovery or reset, slot reuse, public runtime API,
  manifest, lockfile, dependency, vendor, registry, relay/runtime-metrics,
  core/config, client, SDK, CLI, `STATUS.md`, CI, remote, deployment, release,
  real-network, credential, infrastructure, or system-network work. T027b-2c0's
  public config policy already exists; this slice is private feature-gated
  lifecycle foundation and still provides no runtime opener or target I/O.
- **Stop conditions:** Stop before a fourth changed file; any need for real
  target I/O, an increase above eight, a detached task, global registry,
  unbounded queue or collection, shared mutable `ServerConnection`, policy
  inference, staged deadline reset, success response, user DATA retention,
  relay/fallback call, slot reuse, public API, or change to `STATUS.md`,
  manifests, dependencies, vendor, registry, core/config, client, SDK, or CLI.

This remains repository-local private lifecycle foundation only. Synthetic
tests and local loopback evidence are not a sandbox, product runtime, target
connectivity result, release result, or product result.

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
