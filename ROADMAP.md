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

### T027c-1a — Version-first server-role runtime entry

**User result.** The server library can accept one validated, version-first
server role and select either the unchanged config-v1 runtime or the existing
bounded config-v3 H3 foundation. The new config-v3 H3 branch remains a
loopback-only library seam; this is not CLI wiring, real routing, product
readiness, or a release result.

**Scope.** Limit this slice to `ROADMAP.md`, the server crate's public re-export
and runtime entry, and the private quiche endpoint wrapper. Config v1 may make
one `ServerConfig` clone, must immediately drop the secret-bearing
`ServerRoleConfig` before awaiting, and must call the existing `run_server`
unchanged. Config v3 H3 may run only when `quiche-foundation` is compiled and
must pass one
`Arc<ServerRoleConfig>` into the existing loopback-only endpoint with a
runtime-entry-owned metrics owner.

**Acceptance.** Version and transport selection occurs before certificate
reads or socket binds. Config-v3 H2, unavailable features, and inconsistent or
unsupported role combinations fail with one fixed privacy-safe error. Config
v1 behavior, endpoint bounds, authentication-before-CONNECT, target-open
deadline and egress ownership, clean endpoint shutdown, and all protocol,
config, auth, frame, wire, and stored-profile versions remain unchanged.
Focused tests cover selection, pre-I/O rejection, real loopback endpoint
lifecycle, cleanup, and both default and `quiche-foundation` builds.

**Out of scope.** Do not change manifests, default features, core config, CLI,
SDK, client routing, public lifecycle handles or metrics APIs, public quiche
types, non-loopback binding, domain resolution, target relay ownership,
schemas, wire formats, dependencies, system network settings, or real
infrastructure.

**Stop conditions.** Stop and re-adjudicate before touching any additional
file, changing the feature graph, exposing quiche or a new lifecycle handle,
adding a second listener/resolver/opener/task framework/queue, enabling
non-loopback I/O, or requiring any schema, wire, CLI, client, or core change.

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
