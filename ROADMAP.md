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

### T027c-2i — Stop a reset SOCKS peer before target open

**User result.** If the sole external loopback SOCKS peer sends one valid
IP-literal CONNECT and then resets while the direct-H3 owner is still waiting
for its first server observation, the opt-in public one-shot entry must stop
that attempt before acquiring a lease or opening the requested TCP target. It
must explicitly close the started owner, return its bounded lease and task
permit, and return the same fixed privacy-safe public error.

This closes one failure window in the unpublished, feature-gated, single-peer
library entry. It is not a second peer or flow, a reusable service, reconnect,
retry, replacement, external shutdown, UDP, non-loopback or real-network work.

**Scope.** Begin with only `ROADMAP.md` and
`crates/maverick-server/src/quiche_endpoint.rs`. Touch
`crates/maverick-client/src/quiche_foundation.rs` only after a credible
behavioral red demonstrates the production bug. `STATUS.md` may receive one
narrow current-truth sentence only after behavioral green and the complete
local gates, and only after explicit re-adjudication. Do not change library
exports, manifests, `Cargo.lock`, core, the auth-v3 specification, CLI, SDK, or
server production code.

**Behavioral red.** Bind and run the real loopback server endpoint with its
existing test gate armed to pause only the first actor-owned real server UDP
send. Drive a real external SOCKS peer through method negotiation and one valid
loopback IP-literal CONNECT. Wait for the positive server-send event: the
response packet has been built but remains unsent, so the client cannot yet
receive its first observation. Set zero linger, drop the peer, and then release
that real send.
The current code must fail the green expectation by opening the real target
after that reset; record the exact command, exit status, observed result, and
missing lifecycle branch before implementing the fix. Do not use a mock, source
scan, fixed sleep, or timeout-only silence as the red result.

**Green implementation.** During only the wait for the first
`FoundationObservation`, monitor a non-consuming terminal reset from the
accepted TCP stream. After that observation wins, preserve the existing lease
acquisition and H3-open sequence unchanged. Do not consume or discard early
peer bytes, split a pending open, cancel an H3 open already in flight, or use
owner `Drop` as cleanup. Every path after owner start must still explicitly
close that owner and verify the lease and task permits are returned.

**Acceptance.** The same real composition turns green with the fixed public
error returned within a bound shorter than the five-second handshake timeout,
zero target-open latency or failure observations, no queued target TCP
connection, no server registry/actor/unregistered residue, and successful
rebind of the client listener, target listener, and server UDP addresses. Since
the peer disappears before the first client observation, the server actor must
notify its parent join and be fully reclaimed before the test cancels the
now-empty endpoint. Existing pre-key actor semantics may let the actor join
without an endpoint shutdown error or reach the bounded forced-reclaim boundary,
so only `Ok(())` or `EndpointError::Shutdown` is accepted and every other
endpoint error fails.
Neither server safety result substitutes for the public fixed error, real
target backlog, and zero target-open metric assertions.
Preserve the T027c-2h successful external-peer and pre-owner rejection tests,
plus the T027c-2g active-shutdown, T027c-2f failure-isolation, T027c-2e
sequential, T027c-2d collection/reuse, and T027c-2c one-shot regressions. Repeat
the focused T027c-2i test at least 20 times, then run the complete client and
server quiche suites, compatibility matrices, Clippy, Rustdoc,
`user-smoke.sh`, and `local-harness.sh`.

**Out of scope and stop conditions.** Do not change a public API, feature graph,
wire/config/schema version, queue or resource capacity, SOCKS parser, server
target policy, target dispatcher, default H2 path, `start_client`,
`ClientHandle`, or normal `serve_socks`. Do not add a task, handle, manager,
driver, actor, watchdog, shutdown channel, public error type, second accept, or
new runtime policy. Stop and re-adjudicate if a correct fix must observe the
peer after H3 open begins, consume peer bytes, rely on timeout silence or
Drop/abort, touch a fourth file, or weaken explicit close and permit checks.

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
