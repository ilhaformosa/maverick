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

### T027c-1c — Private config-v3 client trust adapter

**User result.** The private direct-H3 client foundation can consume one owned
config-v3 H3 client role and explicit trusted authentication inputs, then apply
its literal loopback address, server name, CA policy, and optional leaf
certificate pin before authentication. This is still a private,
feature-gated, loopback-only foundation seam. It is not a CLI/SOCKS product
path, real routing, product readiness, or a release result.

**Scope.** Limit this slice to `ROADMAP.md` and the client's private quiche
foundation. Add one private adapter that first transfers the complete client
role into the existing generation-auth owner, accepts a task permit already
reserved by its caller, rejects non-H3, DNS, non-loopback, and zero-port peers
before CA or socket I/O, and performs a timeout-bounded matching-family
loopback bind. When a custom CA is configured, build a fresh BoringSSL trust
context containing only that CA; otherwise preserve quiche's platform-aware
backend-default root handling. Keep server-name verification mandatory. Decode
an optional SHA-256 leaf pin before I/O and compare it in constant time after
verified TLS 1.3 and H3 ALPN, but before exporters, H3 construction,
observation, or auth-v3.

**Acceptance.** A malformed pin is rejected by the canonical parser before the
adapter or a task permit exists. Invalid v1, H2, DNS, non-loopback, zero-port,
and missing-CA inputs reaching the adapter fail with fixed privacy-safe errors
before the next forbidden I/O stage and return the caller's task permit. A
custom synthetic CA and matching server name authenticate with no pin or a
matching pin. A wrong custom CA, backend-default roots against that private CA,
a wrong server name, or a wrong pin cannot produce a client observation or
authenticated lease; a matching pin never overrides failed PKI or name
verification. Wrong-pin
rejection occurs before any exporter/H3/auth observation. Explicit close
invalidates the successful lease and reclaims tasks. Existing independent
readiness, cancellation, bounded queues, default behavior, and all protocol,
config, auth, frame, wire, and stored-profile versions remain unchanged.

**Out of scope.** Do not add public APIs, CLI/SDK/SOCKS wiring, CONNECT
streaming, DNS or non-loopback support, real-network I/O, reconnect policy,
telemetry, a second manager/queue/task framework, dependency, feature, schema,
or wire changes. Backend-default root sets may differ between H2 and H3; this
slice preserves the policy boundary of exclusive custom CA versus backend
defaults, not byte-identical root stores. The private adapter does not prove a
product client runtime.

**Stop conditions.** Stop and re-adjudicate before touching any additional
file, changing a manifest or feature graph, exposing a public handle or quiche
type, enabling DNS/non-loopback/real-network I/O, inventing trusted time or
capability inputs, or requiring server, core, CLI, SDK, schema, or wire changes.

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
