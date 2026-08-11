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

### T024a-3 — Bound every legacy-H3 response-frame completion

**User result.** A legacy `feature = "h3"` client that keeps its QUIC
connection alive but stops reading one response must not retain that request's
server resource forever. Every actual Maverick DATA-frame completion and a
requested response finish must have the deadline owned by the current protocol
state. Expiry returns one fixed private transport error to the existing caller,
which releases the request and its target resources.

This closes one legacy-H3 transport-pressure lifetime boundary. It does not
claim H2-style progress-reset parity, add a timeout field, change configured
timeout values or defaults, or turn the sequential OpenUdp foundation into
general-purpose UDP.

**Scope.** Change only `ROADMAP.md`, `STATUS.md`,
`crates/maverick-server/src/server.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Keep the implementation private to
the existing legacy-H3 server path and preserve every public API. `STATUS.md`
may receive one narrow current-truth update only after the green implementation
and all required local gates pass. Keep relay, client, core, CLI, SDK,
manifests, `Cargo.lock`, and every other file unchanged.

**Behavioral red.** Use a real raw Quinn/H3 loopback client with a deliberately
small stream receive window and active QUIC keepalive. Send a valid
`ClientHello`, `OpenUdp`, and six same-flow `UdpPacket` frames, but do not call a
response-receive operation at any point. A real loopback UDP target must return
six fixed 8-KiB replies to the same observed server target-source address, for
48 KiB in total. Target
receipt proves that authentication and OpenUdp processing occurred; the raw
client does not read or claim to verify `ServerHello` or the OpenUdp
acknowledgement. After the configured state deadline, binding the exact UDP
source observed by the target must succeed while the QUIC connection remains
open. On the current bare-await implementation, the test must compile, receive
and answer the actual target packets, positively confirm all six requests and
replies plus one reused server source, then fail with status 101 because that exact source is still
`AddrInUse`. A missing server, mock, source scan, or QUIC connection idle expiry
is not a valid red cause.

**Green implementation.** Give each actual legacy-H3 Maverick DATA frame its
own completion deadline, including a runtime-padding frame, every cover-traffic
frame, and the business frame. Give a requested stream finish its own completion
deadline after the final DATA frame completes. The authenticated `ServerHello`
send uses `handshake_timeout_ms`; all other non-TCP state-machine sends use
`idle_timeout_secs`; and TCP relay sends and finish use the relay policy's
`idle_timeout`. On expiry return one fixed, privacy-safe private error and let it
propagate through the existing handler. Do not send a compensating Maverick
`Error` frame on the already blocked stream, reset the whole authenticated QUIC
connection, or copy peer, target, frame, flow, or backend details into the
error.

**Acceptance.** The behavioral red turns green while the test proves the raw
client, which never consumes the response direction, and real authenticated
legacy-H3 server remain connected beyond the server's state deadline and the
exact UDP source becomes reusable. The smallest deterministic server-side tests
lock the completion helper's deadline edge and fixed private error plus the
`ServerHello` versus ordinary-state budget selector. The shared send structure
must make runtime padding, every cover frame, the business frame, TCP relay
DATA/FIN, and a requested finish each invoke the bounded helper separately with
the timeout owned by that path. Existing H3 authentication, fallback, OpenUdp
roundtrip and ownership, DNS, padding and cover accounting, H2 behavior,
direct-v3/quiche H3, and every public API remain unchanged. TCP target, rate,
egress, and configured idle values remain unchanged; the sole policy application
is using the existing TCP relay idle budget for legacy-H3 response completion.
Run focused tests first, then the
relevant server and integration suites under no-default, `h3`, and all-features
matrices, formatting, strict Clippy, Rustdoc, `user-smoke.sh`, and
`local-harness.sh` locally.

**Out of scope and stop conditions.** Do not change H2 behavior or claim H2
progress-reset equivalence; frame, error, protocol, config, or schema versions;
dependencies, features, manifests, lockfile, authentication, admission,
fallback, limits, metrics, logging, UDP target ownership, DNS behavior, TCP
target, rate, egress, or configured idle values, client behavior, CLI, SDK, TUN,
direct-v3/quiche H3, or any machine network setting. The only TCP relay policy
application allowed is using its existing idle budget as the legacy-H3 response-
completion budget. Do not add a public type,
task, lock, queue, map, registry, retry, manager, actor, or coordination layer.
Stop and re-adjudicate if one private legacy-H3 deadline helper plus local call-
site plumbing cannot enforce the contract or if a fifth file is required.

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
