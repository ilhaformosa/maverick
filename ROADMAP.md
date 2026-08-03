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

### T027b-2d4a — terminal lifecycle and generation-bound slot identity

- **User result:** A private Classic CONNECT drops its original target socket
  only after request FIN and every buffered upload have reached target write-half
  shutdown, while target EOF, every buffered download byte, and response FIN
  have reached local quiche acceptance. The fixed slot then remains an
  unreusable tombstone carrying the old generation and stream identity; late
  readiness or transport state cannot be mistaken for another flow.
- **Scope:** Keep exactly eight fixed slots, one unsplit target socket owner per
  active slot, the existing independent 16 KiB buffers, and the shared
  four-operation/64-KiB rotating I/O round. Freeze generation, H3 stream, slot,
  and direction in every externally returned target-readiness signal, and bind
  each target-open completion token to its exact slot. Model application
  terminal state separately from quiche transport collection. A known opened
  stream may record transport collection before target upload finishes only
  after request `Finished`, local response-FIN acceptance, exact live identity,
  and exact `InvalidStreamState` all agree. It retains the socket and can finish
  only its existing bounded upload/write/shutdown work. The small pre-poll
  exception that lets an already queued H3 `Finished` become visible is followed
  in the same H3 drive by a non-deferred transport check.
- **Acceptance:** Prove with real loopback transport that an unacknowledged
  response FIN leaves the old stream present, a real pre-collection
  `STOP_SENDING` returns `StreamStopped` and closes the generation, and a fully
  acknowledged known stream becomes exact `InvalidStreamState`. Preserve the
  valid target-EOF/response-FIN-before-request-FIN order: record narrowly
  confirmed transport collection, finish the exact upload and target shutdown,
  then drop the socket once and retain a collection-confirmed tombstone. Prove a
  STOP arriving in the deferred-`Finished` window is rejected before target I/O.
  Prove every other premature `InvalidStreamState` fails closed. Prove wrong or
  stale generation, stream, slot, direction, out-of-range slot, duplicate signal,
  non-active early return, and wrong/out-of-order target-open completion reject
  before cursor, H3, socket, buffer, or state mutation. Eight terminal tombstones
  remain bounded, still reject a ninth flow, and cannot poison another active
  slot's readiness. Preserve all T027b-2d0 through T027b-2d3, T027b-2c4/2c5,
  direct-v3 auth, actor, EOF, flush, join, teardown, opener, privacy, and
  source-shape gates.
- **Out of scope:** T027b-2d4b slot reclaim/reuse remains a later independent
  candidate and may use only an application-terminal, collection-confirmed
  tombstone. This slice never clears or reallocates a terminal slot. Domain DNS,
  a product caller, runtime readiness, new timers, polling, tasks, channels,
  registries, maps, epochs, schedulers, metrics, socket splitting or a second
  owner, vendor changes, public API, config, schema, wire or version changes,
  dependencies, manifests, lockfiles, core, client, SDK, CLI, `STATUS.md`, CI,
  remote, deployment, release, real-network, credential, infrastructure, and
  system-network work remain deferred.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if public quiche
  facts cannot keep normal collection distinct from observable `STOP_SENDING`;
  if an identity mismatch can reach an early success, cursor movement, H3 or
  socket I/O, or state mutation; if target cleanup requires a second operation
  budget or owner; if this slice requires slot reuse, a timer, polling sleep,
  saved future, task, channel, growing registry, unsafe code, vendor patch,
  dependency, public surface, fourth file, or `STATUS.md` change.

This remains repository-local, private, feature-gated, and temporarily limited
to IP-literal production target opening. It is a local bidirectional foundation
slice, not a product runtime, readiness result, real-user result, release
authorization, or complete tunnel.

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
