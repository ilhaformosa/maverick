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

### T027c-2c — Repository-local one-shot loopback SOCKS/H3 composition

**User result.** One explicitly unstable repository-test path accepts exactly
one real SOCKS5 TCP peer on an OS-assigned loopback port, validates one
loopback IP-literal CONNECT request, and composes it with the existing private
native-quiche owner, the real server endpoint, and one real TCP echo target.
Authentication and exact `200` precede the SOCKS success reply; ordered data
larger than 16 KiB and independent half-close then cross the complete local
composition. This is repository-local foundation evidence only. It is not the
normal `start_client`, CLI, SDK, long-running SOCKS service, product end-to-end
path, readiness result, release result, or real-network result.

**Scope.** Limit this slice to `ROADMAP.md`, `crates/maverick-client/src/lib.rs`,
`crates/maverick-client/src/quiche_foundation.rs`, and
`crates/maverick-server/src/quiche_endpoint.rs`. Extend only the existing
combination of `unstable-direct-v3-reference-test-support` and
`quiche-foundation` with fixed-result public wrappers required only by the Rust
crate boundary for success, observed rejection, and active-disconnect cleanup.
Behind them, bind one loopback TCP listener, accept one peer,
parse and reply through the existing `crate::socks5` implementation, and reuse
the existing owner, manager, driver, authenticated lease, private flow,
server endpoint/actor, and production target opener. Use one fixed 16-KiB
relay buffer and bounded local futures; add no task, channel, queue, manager,
driver, actor, trait, feature, dependency, or runtime framework.

The preserved remote-first red also permits one narrow client close repair.
Only after the authenticated client role's unique private stream has reached
clean completion in both directions, retain that known opened stream ID and
reuse the existing driver, UDP socket, and `Close` command to process packets
until quiche has collected the stream or a one-second bound expires. Collection,
not local FIN acceptance, lease reclamation, `stream_finished`, or
`stream_closed`, is the required evidence that the peer QUIC transport
acknowledged the outbound stream. It is not evidence that the TCP target
application consumed those bytes; the separate real-target byte-exact test
proves that boundary. Cancellation, disconnect, authentication failure,
expiry, incomplete flow, and driver error continue to close immediately
without this drain. Timeout is a fixed failure followed by fail-closed
transport teardown; this is not a generic graceful-shutdown promise.

**Acceptance.** Preserve one compile red that fails only because the new
cross-crate runner is absent. The positive green test sends real SOCKS5 bytes
through a loopback `TcpStream`, receives success only after auth-v3 and exact
`200`, and traverses real quiche UDP/TLS 1.3/H3, the real endpoint registry and
actor, production loopback target opening, and a real TCP target. More than
16 KiB moves byte-exactly in both directions. The target sends and half-closes
first; the SOCKS peer receives those exact bytes and EOF, then still sends its
full request and FIN to the target. Every wait is bounded, the one-shot listener
accepts no second peer, the target accepts exactly once, and explicit cleanup
does not succeed until that client stream is collected, then reclaims client
task permits plus all server registry/actor state.

Domain, UDP ASSOCIATE, non-loopback, zero-port, and malformed SOCKS requests
must be rejected before any H3 or target I/O with fixed privacy-safe results.
Authentication or exact-`200` failure must be observed by the real SOCKS peer
as rejection or EOF before any success reply. A separate active-flow test first
observes SOCKS success and one real target accept, then disconnects the local
peer; the runner must attempt best-effort flow cancellation before bounded owner
close and reclaim all client/server state. Existing T027c-2b cross-crate tests
remain unchanged and green; they are separate private-foundation evidence rather
than a product claim.

**Out of scope.** Do not modify or route through the normal `start_client`,
`ClientHandle`, session, SOCKS service loop, HTTP CONNECT, CLI, SDK,
config-file product loading path, or normal server entry. Synthetic test roles
may continue to use the existing in-memory parser. Do not add a second flow,
listener loop, reconnection,
transparent retry, Domain/DNS, non-loopback target, UDP relay, real-network
operation, new public capability, integration-test crate, or protocol, config,
authentication, frame, stored-profile, manifest, lockfile, or version change.
This local quality evidence does not update `STATUS.md` and is not product
end-to-end evidence.

**Stop conditions.** Stop and re-adjudicate before touching a fifth file,
changing any manifest or lockfile, exposing an owner, lease, flow, quiche,
exporter, secret, observation, listener, or stream capability, reaching the
runner through a normal product feature alone, adding any new command, task,
channel, or runtime coordinator,
enabling Domain/DNS or non-loopback I/O, weakening fixed resource/privacy
bounds, changing any other close/error/cancellation path, changing the server
event loop or normal SOCKS/session path, relying on a quiche private API or
upstream patch, or changing a wire/schema/version contract. Stop rather than
relabeling a
same-process test-support composition as the user-facing product path.

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
