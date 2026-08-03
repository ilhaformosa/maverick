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

### T027b-2d0 — queue the Classic CONNECT success response after target handoff

- **User result:** Only after a real target `TcpStream` has returned to its
  originating fixed Classic CONNECT slot, queue exactly one response header,
  `:status = 200`, with `fin=false` on that request stream. Acceptance by the
  server's local quiche send queue does not prove that the client received the
  response. A client observing it in a loopback test is local test evidence
  only.
- **Scope:** Split the existing slot state minimally between target-owned
  response-pending and response-accepted. Immediately before each
  `h3.send_response` attempt, recheck the same generation and request stream,
  active non-revoked capability, hard deadline, maximum frame size, consumed
  target metadata, unique slot ownership of the still-live target socket, and
  absence of request reset or stop. `StreamBlocked` makes zero progress and
  preserves the same pending slot and socket for retry through the existing
  actor drive and flush path. Local queue acceptance advances only that slot to
  response-accepted. Any other response error fails the generation closed with
  the existing fixed privacy-safe close behavior.
- **Acceptance:** Prove a real loopback target handoff precedes one exact
  `Headers(:status=200)` client observation with more frames still possible;
  pre-handoff drives emit no response; handoff produces response-pending; local
  queue acceptance produces response-accepted without claiming client receipt;
  a real flow-control `StreamBlocked` writes no partial HEADERS, retains the
  original socket and pending state, then safely retries the same response once
  after unblocking. Recheck revocation, hard expiry, generation, stream, frame,
  reset, and stop failures before sending and release the socket on generation
  close. Admission expiry and the already-consumed target-open attempt deadline
  are not response deadlines. A peer request write-half FIN still permits the
  response. Target connect, egress, timeout, and Domain failures emit no 200;
  repeated drives emit no second response; post-200 DATA remains rejected.
  Preserve the fixed eight slots, four ready completions per round, T027b-2c4
  and T027b-2c5 quota, fairness, EOF, join, teardown, opener, direct-v3 auth,
  Domain parsing and admission, legacy, privacy, and source-shape gates.
- **Out of scope:** No CONNECT DATA read or write, relay, half-close forwarding,
  slot removal, reuse or recovery, fallback or error response, second response,
  product-server startup caller, registry or metrics change, new task, future,
  channel, collection, socket owner, timer, scheduler, public API, config,
  schema, wire or version change, dependency, manifest, lockfile, vendor, core,
  client, SDK, CLI, `STATUS.md`, CI, remote, deployment, release, real-network,
  credential, infrastructure, or system-network work. Production Domain target
  opening remains temporarily fail-closed; a truly cancellable resolver is a
  separate later decision.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes. Stop if the exact
  response cannot be queued through the existing slot owner and actor drive,
  if real blocked-to-unblocked behavior cannot be tested, or if any DATA plane,
  new owner, queue, timer, task, dependency, public surface, forbidden file, or
  `STATUS.md` change becomes necessary.

This remains repository-local, private, feature-gated, and temporarily limited
to IP-literal production target opening. It queues one response header but does
not implement a tunnel or DATA plane, create a product runtime path, establish
readiness, authorize a release, or produce a product result.

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
