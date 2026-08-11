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

### T024a-2 — Bind every OpenUdp request frame to its opened flow

**User result.** After an authenticated request opens one `OpenUdp` flow, every
later non-`Padding`, actionable application frame on that request must carry
the same `flow_id`. A frame with a different identifier is a request-stream
protocol violation: the server must return exactly one `Error` for the opened
flow with `ProtocolError`, then terminate that request stream without decoding
its application payload or causing a frame-specific side effect. The handler
must not explicitly close the underlying authenticated transport connection;
only the invalid request stream ends. The tests prove request-stream
termination, not physical-connection reuse.

This closes one fail-closed association boundary in the existing H2 and legacy
`feature = "h3"` handlers. It does not change the frame format, create a flow
registry, add multiplexing inside one request, or claim general-purpose UDP or
product readiness.

**Scope.** Change only `ROADMAP.md`, `STATUS.md`,
`crates/maverick-server/src/server.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Keep the check inside each existing
`OpenUdp` request handler and preserve every public API. `STATUS.md` may receive
one narrow current-truth update only after the green implementation and all
required local gates pass. Keep relay, client, core, CLI, SDK, manifests,
`Cargo.lock`, and every other file unchanged.

**Behavioral red.** Use public `maverick_client::tunnel::open` calls to open
real authenticated H2 and legacy-H3 request streams, send a valid `OpenUdp`,
and then send a validly encoded `UdpPacket` whose `flow_id` differs. A real
loopback UDP target observer must reply if touched so the current implementation
completes dynamically rather than timing out. One fixed assertion must prove
that the mismatched packet reached that target on the current implementation;
the test must fail with status 101 after successful compilation and actual
target receipt. The green expectation is the opposite: an exact opened-flow
`ProtocolError` and no target receipt. Add the smallest corresponding evidence
for a mismatched `CloseFlow`; do not use a mock, source scan, fixed sleep, or
timeout-only silence as the red cause.

**Green implementation.** Capture the `OpenUdp` frame's `flow_id` before
entering each H2 or legacy-H3 receive loop. Immediately after reading every
later non-`Padding`, actionable frame, compare its identifier with that expected
value.
On mismatch, send exactly
`Error(expected_flow_id, ProtocolError)` as the terminal response and return.
Perform this check before frame-type dispatch, payload decoding, rate limiting,
DNS or egress-policy work, target-slot access, socket creation, or target I/O.
H2 completes the application error with `grpc-status: 0`; legacy H3 finishes
the request stream normally. Do not explicitly close the authenticated
physical connection, continue after the error, or report the untrusted
identifier.

**Acceptance.** The behavioral red must turn green for both H2 and confirmed
legacy-H3 transport; immediately after public tunnel creation, each test must
assert the actual H2 or H3 tunnel variant before sending any application frame.
Each mismatched-`UdpPacket` test must observe the exact
opened-flow error, prove the real UDP target was not touched, and prove terminal
H2 trailers or H3 FIN. The smallest mismatched-`CloseFlow` cases must receive
the same exact error and termination instead of being accepted as a valid
close. Existing same-identifier UDP roundtrips, explicit close, request EOF,
idle timeout, target ownership, flow limits, SOCKS UDP, bare `UdpPacket`, and
legacy-H3 behavior must remain unchanged. Run focused tests first, then the
relevant server and integration suites under no-default, `h3`, and all-features
matrices, formatting, strict Clippy, Rustdoc, `user-smoke.sh`, and
`local-harness.sh` locally.

**Out of scope and stop conditions.** Do not change frame, error, protocol,
config, or schema versions; dependencies, features, manifests, lockfile,
authentication, admission, fallback, limits, rate policy, egress policy,
metrics, logging, UDP target ownership, DNS relay, TCP relay, client behavior,
CLI, SDK, TUN, direct-v3/quiche H3, or any machine network setting. Do not add a
new public type, task, lock, queue, map, registry, retry, manager, actor, or
coordination layer. Stop and re-adjudicate if the invariant cannot be enforced
by one local guard in each existing handler or needs a fifth file.

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
