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

### T027b-2d3 — request FIN to original-slot target write-half shutdown

- **User result:** After one Classic CONNECT request's H3 `Finished` is
  accepted, every client DATA byte already received for that stream is written
  byte-for-byte to its original fixed slot's one target `TcpStream` before the
  server closes only that socket's write half. The target read half stays open,
  so a delayed reply still returns on the same H3 response stream through the
  T027b-2d1 path.
- **Scope:** Keep exactly eight slots, their independent 16 KiB upload and
  download buffers, the original unsplit socket owner, and the one rotating
  `(slot, direction)` cursor. `peer_write_half_closed` records the first request
  FIN. Upload dispatch separately moves through idle, H3 receive-pending, exact
  write-pending suffix, target-shutdown-pending, and target-write-half-closed.
  FIN before local 200 acceptance is recorded but cannot touch the target.
  Shutdown waits behind every buffered suffix and the final `recv_body` `Done`,
  then calls Tokio write-half shutdown on the original socket. That zero-byte
  state transition consumes one operation in the existing shared four-operation
  and 64-KiB round; it is not payload progress and has no second budget.
- **Acceptance:** Prove a real small-buffer target reaches `WouldBlock`, sees no
  EOF before the exact final marker, then sees marker followed by EOF after its
  receive side drains; it can send a delayed reply which reaches the client
  before response FIN. Prove empty-body FIN, FIN before 200, target EOF before
  request FIN, and response FIN before a legal final upload. Prove eight
  shutdown-pending slots close in two shared zero-byte rounds without starving
  exact download readiness. Prove the existing actor continuation completes a
  shutdown without another test packet or socket waiter while cancel, timer,
  and inbox remain biased first. A narrow test-only shutdown-failure seam must
  close the generation, clear both buffers, drop the socket, and return only the
  fixed value-free error. Duplicate `Finished`, DATA after FIN, RESET,
  STOP_SENDING, send or target failure, hard expiry, revocation, cancellation,
  and connection close remain generation-wide fail-closed. Request FIN never
  creates response FIN, and response FIN never shuts down the target write half.
  Preserve all T027b-2d2, T027b-2d1, T027b-2d0, T027b-2c4/2c5, direct-v3 auth,
  EOF, flush, join, teardown, opener, privacy, and source-shape gates.
- **Out of scope:** Slot reclaim or reuse and per-flow graceful completion are
  later independent candidates. Domain DNS, a product caller, and runtime-
  readiness remain deferred. No trailer, new stream, fallback or error response,
  registry or metrics change, task, saved future, channel, collection, socket
  split or second owner, timer, scheduler, public API, config, schema, wire or
  version change, dependency, manifest, lockfile, vendor, core, client, SDK,
  CLI, `STATUS.md`, CI, remote, deployment, release, real-network, credential,
  infrastructure, or system-network work.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if the original
  `TcpStream` must move, split, clone, share, use raw descriptors, or gain a
  second owner; if shutdown cannot use the shared four-operation budget or can
  remain pending; if buffered DATA cannot be proven complete before target EOF;
  if real loopback cannot prove DATA, EOF, and delayed reply ordering; if slot
  reclaim is required; if RESET, response-FIN, or generation fail-closed
  semantics must change; or if a task, channel, saved future, timer, polling
  sleep, general scheduler, unsafe code, dependency, public surface, fourth
  file, or `STATUS.md` change is needed.

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
