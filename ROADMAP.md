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

### T027c-2h — Feature-gated one-shot normal client entry

**User result.** An external library caller can pass one validated config-v3
H3 client role to a normal, non-test `maverick-client` entry. That entry binds
the role's configured loopback SOCKS5 address, accepts exactly one external
loopback peer, and carries one valid loopback IP-literal CONNECT flow through
the existing native-quiche owner and server endpoint before explicitly
reclaiming the complete client lifecycle.

This is an opt-in, workspace-source, single-peer library runtime. It is not the
existing `start_client`, `ClientHandle`, CLI or SDK path; not an open-ended or
long-duration listener; not concurrent-flow, retry, replacement or recovery
support; and not default-build, release, user, non-loopback or real-network
evidence.

**Scope.** Limit the complete slice to `ROADMAP.md`, `STATUS.md`,
`docs/AUTH_V3_DIRECT_SPEC.md`, `crates/maverick-client/src/lib.rs`,
`crates/maverick-client/src/quiche_foundation.rs`, and
`crates/maverick-server/src/quiche_endpoint.rs`. Do not update `STATUS.md` or
the auth-v3 specification until the behavioral green and full local gates are
complete.

Under `quiche-foundation` alone, add one public
`run_direct_v3_h3_client_once(ClientRoleConfig) -> anyhow::Result<()>`. It must
not depend on or return the unstable repository-test feature or error. The
public entry consumes the secret-bearing role by value, accepts only the exact
config-v3/H3 combination, and maps every internal failure to one fixed,
privacy-safe public error with no value-bearing source.

Copy the already validated local listener address before transferring the
complete role into the existing private auth owner. Bind exactly that nonzero
loopback address; a port of zero is rejected because this one-shot API does not
return an OS-assigned address. After the first peer is accepted, drop the
listener before parsing or starting transport work so no second peer can enter.
The accept is governed by the caller's task lifetime, not a test-only whole-run
watchdog. Map every attempt failure to the fixed public `anyhow` error. Preserve
the existing SOCKS parser's protocol-safe failure or EOF for malformed and
unsupported wire input, without appending a second reply when the parser has
already replied. Reject a parsed non-loopback peer, UDP ASSOCIATE, Domain
target, zero port or non-loopback IP with the fixed SOCKS `0x05` failure. Only
after the first request parses into one valid loopback IP-literal CONNECT may
the entry start the sole client owner, UDP socket, manager, driver and
authenticated generation.

Use the existing capacity-one command queue, lease and active route, fixed
buffers, authentication barriers, explicit flow finish/cancel and explicit
owner close. Do not promote the repository test's fixed whole-run watchdog into
a long-duration product claim. The entry ends after that first accepted peer's
single flow succeeds or fails; it never executes a second accept.

**Behavioral red.** First add the real public signature, configured listener,
external peer accept and SOCKS parse/validation scaffold. On a valid request,
the red scaffold must deliberately send the fixed SOCKS failure and return the
fixed public error before starting the owner. A real cross-crate test must bind
the real server endpoint and TCP target, connect an independently driven peer
to the configured client listener, complete the real SOCKS method and request
exchange, and observe this exact fixed failure with zero target-open metrics and
no queued target connection. This red must compile and fail its green
expectation; it must not be a missing symbol, mock, source scan, arbitrary
sleep, or timeout-only result. Record the exact command, exit status, observed
result and missing product branch before implementing green.

Before behavioral green closes, add a malformed or unsupported SOCKS regression
that locks the existing single protocol-safe failure/EOF and proves no second
reply is appended.

**Acceptance.** The same cross-crate test must turn green only when the public
entry, not an unstable fixed-result wrapper, carries one trigger to the real TCP
target and returns its exact acknowledgement to the external SOCKS peer. The
entry must write SOCKS success only after the authenticated Classic CONNECT is
open. Clean half-close must finish the H3 request; local failure must complete
explicit cancel. In every case drop the accepted local socket, return the sole
lease, explicitly close the owner and return its task permit.

Require exactly one successful target-open observation with every target
resolution/connect failure and timeout counter at zero, and exactly one server
actor target-open completion. After cleanup, require no second listener
connection, no server registry entry, actor or unregistered slot. Rebind the
configured client listener, TCP target and server UDP addresses. Preserve the
T027c-2g active shutdown, T027c-2f failure isolation, T027c-2e sequential,
T027c-2d collection/reuse and T027c-2c one-shot regressions. Repeat the focused
T027c-2h test at least 20 times, then run the complete client and server quiche
suites, compatibility matrices, Clippy, Rustdoc, `user-smoke.sh`, and
`local-harness.sh`.

After green only, update `STATUS.md` to record exactly one opt-in,
workspace-source, loopback-only, single-peer library runtime and state plainly
that the published Beta.4 artifact does not contain it. Update only the
now-stale opening runtime callout and H3 product-integration paragraph of the
auth-v3 specification; preserve every wire byte, label, vector, version and
broader deferred boundary.

**Out of scope.** Do not modify manifests, `Cargo.lock`, core, default features,
the existing `start_client`, `ClientHandle`, normal `serve_socks`, session, DNS,
HTTP CONNECT, TUN, CLI, SDK, server production code, metrics schema, protocol,
authentication, frame, config or stored-profile schema, or any version. Do not
expose a listener, owner, manager, generation, lease, flow, stream, target,
shutdown sender/receiver, secret, observation or quiche type.

Do not add a returned lifecycle handle, external shutdown claim, second accept,
second peer or flow, concurrent flow, open-ended loop, flow map, second route,
replacement generation, reconnect, retry, backoff, Domain/DNS, UDP relay,
non-loopback or real-network I/O. Dropping a future, owner or manager is not a
successful graceful-cleanup result.

**Stop conditions.** Stop and re-adjudicate before touching a seventh file;
changing the feature graph or any existing public API; increasing a queue,
lease, task, route, target, actor or buffer capacity; or adding a task, manager,
driver, actor, reusable shutdown coordinator or public error type. Stop if the
normal entry needs the legacy concurrent `serve_socks`, `ClientHandle`, a
second accept, owner cloning, secret cloning, replacement generation, public
shutdown, or an additional runtime policy.

Stop if a successful result relies on Drop/abort, a generic or value-bearing
error, a fixed sleep, timeout-only silence, source scan, mock transport,
unstable wrapper or synthetic counter as its sole evidence. Stop rather than
weakening the single-peer, loopback, explicit-close contract.

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
