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

### T027b-2d4b — bounded terminal slot reclaim and same-generation reuse

- **User result:** A private Classic CONNECT returns its fixed slot only after
  both the application work and the exact quiche stream collection are
  complete. Another stream on the same authenticated generation can then reuse
  that slot, while an old readiness signal, target-open completion, or stream ID
  can never act on the new flow.
- **Scope:** Preserve exactly eight fixed live slots, one unsplit target socket
  owner per active slot, the two independent 16 KiB buffers, the existing
  16-position fairness cursor, and the shared four-operation/64-KiB I/O round.
  Use one synchronous reclaim helper for both legal terminal orderings. Before
  `take()` of the exact slot, revalidate the active capability, generation,
  stream, frame limit, unique live identity, request FIN, target write-half
  shutdown, response-FIN acceptance, absent target socket, zeroed buffers, and
  exact `InvalidStreamState(stream_id)`. `StreamStopped` and every other result
  fail closed. Add a checked scalar lifetime budget of 128 successful Classic
  CONNECT admissions per generation. Separately freeze the current peer
  unidirectional H3 footprint to its first four monotonically numbered stream
  IDs (control, two QPACK streams, and quiche GREASE); reject a higher peer-uni
  ordinal from transport readability before H3 can silently drain and collect
  it. Together these rules bound quiche's collected-stream set. Failed Classic
  insertion does not consume its counter and generation cleanup resets it. Do
  not add a retired-ID map, registry, epoch, timer, task, channel, or second
  socket owner.
- **Acceptance:** Keep an application-terminal stream in its slot until exact
  collection, so a real late `STOP_SENDING` still closes the generation. Prove
  both orderings: application terminal followed by collection, and transport
  collection followed by the final bounded upload/shutdown work. Prove exact
  collection reclaims in the same synchronous call. With real loopback H3,
  occupy all eight slots and reject a ninth, collect all eight, reclaim them,
  then admit eight different stream IDs on the same generation into the same
  fixed slot indexes. Every old ID remains `InvalidStreamState`. Prove stale
  readiness and a duplicated old target-open token reject before cursor, H3,
  socket, buffer, or new-slot mutation. Prove the lifetime counter's failed
  insertion, 127-to-128 success, 129th rejection, checked arithmetic, and reset
  on generation cleanup. Prove the first peer uni stream above the frozen H3
  footprint is accepted by the QUIC concurrency window but rejected before H3
  drain/collection, without consuming a Classic admission. Preserve the fixed
  memory/I/O budgets and all T027b-2d0 through T027b-2d4a, T027b-2c4/2c5,
  direct-v3 auth, actor, EOF, flush, join, teardown, opener, privacy, and
  source-shape gates.
- **Out of scope:** This slice does not promise unbounded sequential streams;
  reaching the fixed lifetime budget closes further Classic CONNECT admission
  for that generation. Unknown peer-uni extension streams above the frozen
  footprint are intentionally not an extension mechanism in this strict
  private foundation. Domain DNS, a product caller, runtime readiness, peer
  receipt proof, new timers, polling sleeps, tasks, channels, registries, maps,
  epochs, schedulers, metrics, socket splitting or a second owner, vendor
  changes, public API, config, schema, wire or version changes, dependencies,
  manifests, lockfiles, core, client, SDK, CLI, `STATUS.md`, CI, remote,
  deployment, release, real-network, credential, infrastructure, and
  system-network work remain deferred.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if exact
  `InvalidStreamState` cannot be rechecked immediately before reclaim; if an
  application-terminal but uncollected slot must be reused; if quiche can
  recreate a collected stream ID; if stale identity can reach cursor, H3,
  socket, buffer, or state mutation; if cleanup or reuse requires another
  operation budget, owner, dynamic registry, epoch, timer, polling sleep, saved
  future, task, channel, unsafe code, vendor patch, dependency, public surface,
  fourth file, or `STATUS.md` change.

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
