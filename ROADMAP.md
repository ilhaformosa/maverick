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

### T027c-2b — Private cross-crate loopback H3 CONNECT relay proof

**User result.** One opt-in repository test composes the real private
native-quiche client runtime-policy owner, the real private server endpoint,
and one real TCP echo target on OS-assigned loopback ports. After auth-v3
succeeds, one IP-literal Classic CONNECT stream carries ordered bytes in both
directions, propagates request and response half-close, and shuts down within
fixed bounds. This is repository-local composition evidence for private
foundation seams. It is not the SOCKS, CLI, SDK, or normal product runtime; it
is not a process-level product end-to-end result, user result, readiness
result, release result, or real-network result.

**Scope.** Limit this slice to `ROADMAP.md`, the client library entry and
private quiche foundation, the server manifest's existing client
dev-dependency, and the server's private quiche endpoint and runtime. Extend
the existing explicitly unstable direct-v3 repository-test feature with one
fixed-result runner that is present only together with the client
`quiche-foundation` feature. The server test graph may enable that combination;
ordinary product builds must not. The runner consumes a complete client role
and accepts one loopback target address, then reuses the existing client owner,
manager, driver, authenticated lease, private flow, fixed buffers, deadlines,
and cleanup. It exposes no owner, lease, flow, quiche object, exporter, secret,
endpoint, authority, payload, observation, or receipt.

The preserved real-loopback red also permits one narrowly proven server
runtime repair. For the unique active slot matching that stream, after exact
`200`, a DATA readiness notification moves `Idle` to `RecvPending`. Further
notifications while the same fixed upload is already `RecvPending` or valid
`WritePending` are state-preserving coalescing only: they neither clear nor
overwrite the buffer or cursor. Every wrong stream, duplicate slot, pre-`200`,
absent target, peer-FIN, malformed pending state, shutdown, or
write-half-closed case remains fail-closed.

The server test must use the existing private `Endpoint::bind_test`, its real
registry and actors, and the production target opener without an
`ActorTestGate`. Client UDP, server UDP, and the TCP target bind only to
loopback addresses with OS-assigned ephemeral ports. No new runtime task,
manager, driver, actor, channel, queue, framework, or dependency is permitted.

**Acceptance.** A credible pre-change compile test fails only because the new
cross-crate runner is absent. The green path traverses real quiche UDP,
TLS 1.3/H3, auth-v3, exact `200`, server IP-literal target dispatch, a real
loopback `TcpListener`/`TcpStream`, request DATA and FIN, response DATA and
EOF, and bounded client/server shutdown. A fixed neutral payload larger than
one 16-KiB client chunk is verified byte-for-byte and in order; the target
accepts exactly one connection. Corrupt echo must be detected rather than
counted as success. Wrong authentication and correct authentication with
loopback egress denied must both fail with zero target accepts.

After the runner exists, a second preserved red reaches auth-v3, exact `200`,
and one real target accept, then closes with fixed Classic CONNECT DATA
rejection and delivers zero target bytes because a second valid same-stream
DATA readiness notification arrives while the first fixed upload is still
`WritePending`. A focused runtime regression and the full cross-crate transfer
must prove that coalescing preserves the exact pending bytes and cursor, later
drains all queued H3 bytes to the target, and does not weaken the existing
invalid-stream, lifecycle, target, response, or half-close rejection gates.

Every wait is bounded. The runner and its public error return only fixed,
privacy-safe results. The client explicitly closes its owner and reclaims its
task budget; the echo task is joined; the server is cancelled through its
existing test seam and finishes with no registered connection or actor. Target
resolution and connection success are counted once on the positive path, with
no failure counter. Existing T027c-2a client lifecycle and T027b-2d server relay
tests remain separate regression evidence, not substitutes for this
composition test.

**Out of scope.** Do not connect the runner to `start_client`, SOCKS, HTTP
CONNECT, CLI, SDK, config files, or the normal server entry. Do not add a
stable public API, new feature, dependency, task, manager, driver, actor,
channel, queue, framework, integration-test crate, or test binary. Domain/DNS,
non-loopback targets, real-network use, multiple flows, reconnection,
transparent retry, process-level product validation, and protocol, config,
authentication, frame, stored-profile, or version changes remain deferred.
This quality evidence does not update `STATUS.md`.

Do not rewrite H3 polling or actor scheduling, add buffering or readiness
queues, relax authentication, admission, lifecycle, target, or half-close
checks, or accept DATA outside the exact same-stream pending-work coalescing
described above.

**Stop conditions.** Stop and re-adjudicate before touching a seventh file,
changing `Cargo.lock`, exposing any private capability or quiche type, making
the runner reachable through a normal product feature alone, substituting a
synthetic target for real TCP dialing, adding another runtime task or
coordination framework, enabling Domain/DNS or non-loopback I/O, weakening
fixed resource or privacy bounds, changing event-loop ownership or ordering,
changing any other DATA state transition, or changing any wire/schema/version
contract. Stop rather than relabeling a partial handshake, queued bytes, or a
same-file fixture as the required cross-crate composition result.

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
