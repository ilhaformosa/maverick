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

### T027c-2a — Private loopback IP-literal Classic CONNECT flow handle

**User result.** The private direct-H3 client runtime-policy owner can consume
one authenticated connection lease and open one Classic CONNECT stream to a
canonical loopback IPv4 or IPv6 literal. Exact `200` response headers return a
private bounded flow handle whose independent read, write, finish, cancel, and
close lifecycle is driven by the existing manager and quiche driver. This is a
private loopback wire/lifecycle foundation only. It is not SOCKS, CLI, SDK, or
product runtime; it is not a cross-crate client-to-server-to-TCP-target
end-to-end result and does not support Domain/DNS, non-loopback targets,
multiple flows, reconnection, or transparent retry.

**Scope.** Limit this slice to `ROADMAP.md` and the client's private quiche
foundation. Put the only open entry on `ClientRuntimePolicyOwner`; accept only
a nonzero-port loopback `SocketAddr` with zero IPv6 scope and flow information,
then construct the canonical IPv4 `ip:port` or IPv6 `[ip]:port` authority
before any command, header, stream, or data I/O. Consume the authenticated
lease and retain it in the returned flow handle. Reuse the single existing
manager and driver, with one Classic CONNECT application stream per
authenticated generation, fixed buffers, separate send and receive state, at
most one application slot plus one driver-pending slot per direction, and
chunks no larger than 16 KiB.

**Acceptance.** Exact `200` response headers are the only success boundary.
Writes acknowledge only after quiche accepts every byte in the submitted
chunk. Request-header `StreamBlocked` retries the same authority without
opening a second stream; body partial writes and `Done` retain the exact unsent
suffix.
Inbound application backpressure neither overwrites data nor stops hard
deadline, reset, cancellation, lease-drop, or owner-close handling. Local FIN
waits for queued bytes, remote FIN becomes EOF only after buffered bytes are
read, and the two halves terminate independently. Reset, STOP_SENDING,
`GoAway`, trailers, non-`200`, wrong-stream events, invalid lease, hard expiry,
owner close, duplicate FIN, and post-FIN writes fail with fixed privacy-safe
errors, clear fixed buffers, wake waiters, reclaim permits, and close the
generation without reopen. Focused local loopback tests cross the real
manager/driver/quiche path for canonical IPv4 and available IPv6, pre-I/O
rejection counters, more-than-16-KiB ordered full-duplex traffic, real low-
window send pressure, inbound backpressure, both half-close orders, bounded
explicit close, and fail-closed cleanup. T027a-1, T027c-1d, and server T027b-2d
remain separate regression evidence and are not combined into an end-to-end
claim.

**Out of scope.** Do not add a public API, second or independent manager,
task-level driver, router, command channel or queue, or framework; CLI, SDK,
SOCKS, TCP-target dialing, Domain/DNS, non-loopback I/O, multiple streams,
reconnection, transparent retry, real-network use, and manifest, feature,
schema, protocol, authentication-wire, or stored-profile changes remain
deferred. Do not buffer an entire flow in a `Vec` or an unbounded queue.
Explicit close is the bounded primary path; `Drop` remains only lease-drop and
abort fallback and does not claim graceful shutdown.

**Stop conditions.** Stop and re-adjudicate before touching a third file,
exposing the owner, flow handle, clock, or quiche type publicly, adding a
second manager/driver/task framework, enabling Domain/DNS or non-loopback I/O,
requiring a cross-crate target seam, weakening fixed resource or privacy
bounds, or changing wire/schema/version contracts.

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
