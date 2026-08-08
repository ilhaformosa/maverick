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

### T027c-1b — Independent client-foundation readiness and cancellation

**User result.** The private direct-H3 client foundation can advance from its
own verified loopback connection facts instead of waiting for a second
same-process test participant. An early close is serviced cooperatively, and a
canceled pre-authentication wait no longer poisons the next authentication
attempt. This is still a private loopback foundation seam, not config trust
wiring, a SOCKS/CONNECT product path, real routing, product readiness, or a
release result.

**Scope.** Limit this slice to `ROADMAP.md` and the client's private quiche
foundation. Promote the existing low-level client construction into one
production-compiled private bootstrap that accepts an already prepared QUIC
trust configuration, an already-bound loopback socket, one owned auth runtime,
and the existing task permit. Remove the production dependency on the
test-pair readiness barrier, service close and authenticated-acquire commands
before foundation readiness, and discard canceled pending acquire responders.
Keep the existing manager, one-slot command queue, bounded join, generation
owner, and authentication state machine.

**Acceptance.** A client and server started independently without a shared
barrier complete the same-generation auth-v3 exchange using peer verification
and a synthetic loopback CA. Closing before handshake readiness completes
inside the existing join bound and returns the task permit. Canceling one
pre-authenticated acquire permits a later acquire to succeed without stopping
the driver. Explicit async close remains the primary bounded reclamation path;
Drop remains an abort-only fallback. Existing loopback limits, pre-auth
application rejection, authenticated lease invalidation, default behavior,
and all protocol, config, auth, frame, wire, and stored-profile versions remain
unchanged.

**Out of scope.** Do not add the `ClientRoleConfig` trust adapter, custom-CA
policy, certificate-pin enforcement, DNS, non-loopback I/O, public runtime or
lifecycle APIs, CLI/SDK wiring, SOCKS/CONNECT streaming, a second manager,
queue, task framework, dependency, feature, schema, or wire change. The
prepared QUIC configuration is a private lower-layer input and does not prove
that product trust configuration is wired.

**Stop conditions.** Stop and re-adjudicate before touching any additional
file, changing a manifest or feature graph, exposing quiche or a public handle,
consuming the full client role, enabling DNS/non-loopback/real-network I/O, or
requiring server, core, CLI, SDK, schema, or wire changes.

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
