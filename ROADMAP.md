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

### T027c-2e — Same-owner sequential SOCKS composition

**User result.** Two fixed repository-controlled SOCKS5 peers can finish two
different loopback IP-literal CONNECT flows in sequence through one private
native-quiche client owner. Both flows use the same manager, physical QUIC
connection, and authenticated generation, but distinct H3 request streams and
different TCP targets. This remains repository-local private-composition
evidence. It is not concurrent-flow support, a listener service, the normal
`start_client`, CLI, SDK, product end-to-end behavior, automatic reconnection,
readiness, release, or real-network evidence.

**Scope.** Limit this slice to `ROADMAP.md`,
`crates/maverick-client/src/lib.rs`,
`crates/maverick-client/src/quiche_foundation.rs`, and
`crates/maverick-server/src/quiche_endpoint.rs`. Reuse the existing explicitly
unstable fixed-result repository-test seam and real server endpoint. Preserve
the single client owner, manager, driver task and UDP socket; capacity-one
command queue and authenticated lease; fixed 16-KiB flow buffers; strict
loopback IP-literal target projection; privacy-safe fixed errors; and the
server endpoint's existing bounded actor, target and relay ownership.

The private runner accepts exactly two peers with two explicit accepts, not an
open-ended listener loop. Parse and validate each SOCKS request before H3
application I/O for that flow. Start one client owner, receive one foundation
observation, and retain it until both flows finish. After the first clean relay,
accept, parse, and validate the second peer, then start its authenticated
acquire immediately without sleep or polling. The existing manager must
withhold that acquire until the exact first request stream is transport-
collected, then return a lease for the same authenticated generation. Fail
closed and tear down the sole owner if
either peer, flow, target, authentication, admission, collection, or cleanup
step fails.

**Acceptance.** First add a focused real client/server/SOCKS behavioral test on
the clean T027c-2d parent and record its red result and root cause before adding
the sequential composition. The green test uses two real loopback `TcpStream`
SOCKS peers, two different real loopback TCP listeners, distinct fixed payload
patterns, one real server endpoint, one client owner, one manager, one driver
task, one UDP socket, and one auth-v3 exchange. Internally require both acquired
lease generation identifiers to match. Require one server actor's existing
test gate to observe both target-open completions, require each target to
receive and return only its own exact payload, and require two successful
target-open metric observations. Preserve the T027c-2d real-quiche regression
that records exactly two different request-stream identifiers; do not claim
that the cross-crate fixed-result seam exports those identifiers.

After each clean flow, require the sole authenticated lease permit to return.
The second successful acquire remains governed by the existing exact-collection
gate without sleep or polling; preserve the T027c-2d real-ACK regression that
is blocked before collection and ready afterward rather than claiming this
composition always observes the pending slot. The final stream may be collected
by the normal reaper or by the existing bounded close drain, depending on
scheduling. Preserve the existing close-drain regressions without changing
their counter meaning. After the second flow, explicitly close the owner and
endpoint, return all task permits, release both TCP listeners and the endpoint
UDP address, and leave no server actor or target task behind.
Repeat the focused cross-crate sequential SOCKS test at least 20 times to catch
acquire/collection races. Then run the complete client and server quiche
feature suites, default and no-default compatibility, Clippy, Rustdoc,
`user-smoke.sh`, and `local-harness.sh`.

**Out of scope.** Do not modify `STATUS.md`, manifests, `Cargo.lock`, core,
normal `start_client`, `ClientHandle`, the normal SOCKS/session/HTTP CONNECT
service, CLI, SDK, default features, protocol, authentication, frame, schema,
stored profile, or version. Do not add concurrent flows, a second active route,
flow map, open-ended listener loop, replacement generation, reconnect, retry,
backoff, Domain/DNS, UDP relay, non-loopback or real-network I/O. Do not expose
a stable public owner, manager, lease, flow, stream, listener, exporter,
observation, secret, or quiche type.

**Stop conditions.** Stop and re-adjudicate before touching a fifth file;
increasing a queue, lease, task, flow, actor, target, or buffer capacity; adding
a command, channel, `Notify`, task, manager, driver, actor, or runtime
coordinator; accepting a third peer; allowing the second flow before exact
first-stream collection; or using two owners, two client UDP sockets, two QUIC
connections, or two authentication exchanges as evidence for same-owner
sequential composition. Stop on any need for concurrency, automatic
replacement, a stable public API, Domain/DNS, UDP, non-loopback I/O, wire,
schema, or version change.

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
