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

### T027b-2d1 — bounded target-to-client DATA and target-EOF response FIN

- **User result:** After the original slot's exact `:status = 200` response has
  been accepted by the server's local quiche queue, bytes read from that slot's
  one target `TcpStream` can be queued as raw DATA on the same response stream.
  Target EOF queues FIN only after all earlier target bytes. Local queue
  acceptance still does not prove client receipt; loopback receipt remains
  local test evidence only.
- **Scope:** Keep the fixed eight Classic CONNECT slots. Each slot may own one
  fixed 16 KiB payload buffer. An accepted response with an empty buffer borrows
  only its original target socket's readable wake; one cancel-safe `try_read`
  either preserves zero progress, prepares at most 16 KiB, or records target
  EOF. Before the biased actor wait, that same synchronous round uses an exact
  readable slot when present or probes at most one cursor-selected accepted
  response; `WouldBlock` returns to the normal wait without looping.
  `h3.send_body` retries only the exact unsent suffix, treats partial success
  precisely, and treats `Done` or `StreamBlocked` as zero progress. Empty-body
  `fin=true` advances only on `Ok(0)`. One actor round performs at most four
  target read or body-send operations and advances through a rotating slot
  cursor, for at most 64 KiB of payload progress. The original slot remains
  occupied and retains its socket after FIN acceptance.
- **Acceptance:** Prove bytes written before and after response observation
  arrive only after the exact 200 on the same stream; initial `WouldBlock`
  preserves the socket and later readiness wakes without a polling sleep; a
  payload larger than 16 KiB arrives byte-for-byte in multiple reads; a real
  small QUIC window preserves and retries the exact suffix without another
  target read; target EOF follows all bytes, while zero-byte EOF still produces
  FIN; eight simultaneously readable slots rotate to progress without any
  round exceeding four operations; and a real continuously ready actor inbox
  permits one inbound turn before the synchronous target probe, while target
  readiness cannot bypass cancel or timer priority. RESET, STOP_SENDING, target
  failure, hard expiry, revocation, and cancellation fail the generation
  closed, clear the fixed buffer, and release the socket. Authenticated client
  DATA remains rejected without `recv_body`, and its marker never reaches the
  target.
  Preserve all T027b-2d0 response, T027b-2c4/2c5 ownership and fairness,
  direct-v3 auth, EOF, flush, join, teardown, opener, privacy, and source-shape
  gates.
- **Out of scope:** No client-to-target DATA, target write, target write-half
  shutdown, bidirectional relay, client half-close forwarding, trailer, new
  stream, slot removal, reclaim or reuse, fallback or error response,
  product-server startup caller, registry or metrics change, new task, saved
  future, channel, collection, second socket owner, timer, scheduler, public
  API, config, schema, wire or version change, dependency, manifest, lockfile,
  vendor, core, client, SDK, CLI, `STATUS.md`, CI, remote, deployment, release,
  real-network, credential, infrastructure, or system-network work. Production
  Domain target opening remains temporarily fail-closed.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if the slot's
  socket must be moved, split, shared, or duplicated; if readiness needs a saved
  future, task, channel, collection, second owner, polling sleep, unsafe code,
  or new scheduler; if real partial/blocked behavior cannot be tested; or if a
  dependency, public surface, forbidden file, or `STATUS.md` change is needed.

This remains repository-local, private, feature-gated, and temporarily limited
to IP-literal production target opening. It is one bounded target-to-client
foundation slice, not a complete tunnel, client-to-target path, product runtime,
readiness result, release authorization, or product result.

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
