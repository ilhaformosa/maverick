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

### T027b-2d2 — bounded original-slot client-to-target DATA

- **User result:** Only after the original fixed slot's exact `:status = 200`
  response is accepted by the server's local quiche queue, bounded request DATA
  can be consumed through H3 and written byte-for-byte to that slot's one target
  `TcpStream`. The T027b-2d1 target-to-client path remains active on the same H3
  stream. Local H3 consumption and socket write acceptance do not prove that the
  target application read the bytes.
- **Scope:** Keep exactly eight slots. Each independently owns its existing
  fixed 16 KiB download buffer and a new fixed 16 KiB upload buffer, for a
  256 KiB fixed application-payload ceiling across all slots. A DATA event may
  enter upload receive-pending only after local 200 acceptance. `h3.recv_body`
  consumes at most 16 KiB per operation; a nonempty result becomes one exact
  write-pending suffix, which `try_write` advances without another receive.
  After the suffix completes, receive-pending continues draining that same DATA
  event until `Done` rearms it. Read and write readiness borrow the original
  unsplit socket with independent wakers. One rotating `(slot, direction)`
  cursor shares at most four I/O/API operations and 64 KiB of operation progress
  per actor round across both directions. An exact readiness signal goes first;
  without one, at most one rotating target-socket probe is attempted.
- **Acceptance:** Prove pre-200 DATA still closes the generation and never
  reaches the target; post-200 DATA reaches the original target while a target
  reply returns on the same stream; payloads larger than 16 KiB and multiple H3
  chunks drain through `Done` without rearm deadlock; a real loopback target with
  a small TCP send buffer reaches `WouldBlock`, preserves the exact unsent suffix
  without another receive, then resumes on writable readiness; a blocked
  download QUIC window does not block upload; request FIN recorded while the
  target is blocked waits behind all DATA and does not shut down the target write
  half; and eight bidirectionally ready slots rotate both directions within the
  shared four-operation/64-KiB ceiling. RESET, target write failure, hard expiry,
  revocation, and cancellation clear both fixed buffers, release the socket, and
  return fixed privacy-safe errors; post-reset bytes never leak. Under sustained
  real QUIC inbox traffic, one inbound turn is followed by a bounded target-write
  probe that distinguishes a `WouldBlock` attempt from progress, while cancel
  and timer keep biased priority. Preserve every T027b-2d1, T027b-2d0,
  T027b-2c4/2c5, direct-v3 auth, EOF, flush, join, teardown, opener, privacy, and
  source-shape gate.
- **Out of scope:** Request FIN to target write-half shutdown is the separate
  T027b-2d3 slice. No slot removal, reclaim or reuse, per-flow graceful
  completion, trailer, new stream, fallback or error response, Domain DNS,
  product caller or runtime-readiness claim, registry or metrics change, new
  task, saved future, channel, collection, socket split or second owner, timer,
  scheduler, public API, config, schema, wire or version change, dependency,
  manifest, lockfile, vendor, core, client, SDK, CLI, `STATUS.md`, CI, remote,
  deployment, release, real-network, credential, infrastructure, or
  system-network work.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if the original
  `TcpStream` must move, split, clone, share, or gain a second owner; if fixed
  eight-slot independent buffers or the shared four-operation/64-KiB round
  cannot be kept; if readiness requires a saved future, task, channel,
  collection, general scheduler, timer, unsafe code, or polling sleep; if a real
  stable target `WouldBlock` cannot be produced; if current quiche DATA rearm
  semantics cannot be driven safely and boundedly; or if a dependency, public
  surface, fourth file, or `STATUS.md` change is needed.

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
