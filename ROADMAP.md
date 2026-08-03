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

### T027b-2b3 — authenticated Classic CONNECT admission metadata gate

- **User result:** One already authenticated private native-quiche server
  generation may strictly accept Classic CONNECT request metadata into a
  connection-local pending slot while its admission capability remains valid.
  The actual limit is eight pending slots, the smaller of the authenticated
  capability's advertised 128 flows and the existing QUIC bidirectional-stream
  limit of eight.
- **Scope:** Reuse the existing strict Classic CONNECT parser only after the
  same-generation active, unrevoked, admission-deadline, hard-deadline, and
  quota predicates pass; repeat the same capability predicate immediately
  before committing one structured target and port; retain only generation,
  stream, peer-write-half-close, and existing resource-limit metadata in a
  fixed eight-slot connection-local container; and clear every slot before the
  existing generation-wide `0x105` close lifecycle on slice-owned failure,
  hard expiry, or revocation. This slice changes only `ROADMAP.md` and the
  private server quiche runtime.
- **Acceptance:** Prove zero admission before complete auth confirmation; live
  domain, IPv4, and IPv6 request admission in both exact field orders; strict
  pre-auth, expiry, revocation, generation, quota, malformed-field, duplicate,
  unknown-field, method, and `more_frames` rejection; parser-to-commit time and
  revocation race closure; eight-slot enforcement without raising transport
  limits; DATA rejection without a body read or payload retention; first
  Finished as a write-half-close marker only; duplicate Finished, trailers,
  reset, STOP_SENDING, unknown-stream activity, Datagram, GOAWAY, and
  PRIORITY_UPDATE as generation-wide failures; target clearing on hard expiry,
  revocation, transport close, and drop; empty replacement-generation state;
  reauthentication before replacement admission; fixed value-free formatting;
  and preservation of auth-v3, strict-push, SETTINGS, parser, CID, capacity,
  inbox, `JoinSet`, close/drain, and actor-ownership coverage.
- **Out of scope:** No success response, response body, DATA read, frame-size
  data-plane enforcement, DNS, target connection, egress, opener, relay,
  fallback, task, channel, global registry, flow-local reset/recovery contract,
  transport-limit increase, production client runtime, public API, manifest,
  dependency, config, schema, spec, protocol, auth, frame, wire, version,
  `STATUS.md`, CI, remote, deployment, release, real-network, or system-network
  change. This private feature-gated dead foundation is not runnable H3, target
  connectivity, relay or data-plane capability, runtime readiness, release
  scope, or a product result.
- **Stop conditions:** Stop before a third changed product file; any parser,
  endpoint, core, client, manifest, lockfile, dependency, vendor, config, spec,
  schema, protocol, auth, frame, wire, version, public API, or `STATUS.md`
  change; any response or user-DATA read; any DNS, target, egress, opener,
  relay, fallback, task, channel, registry, new flow-local error contract,
  stream-limit increase, copied authentication or parser rule, unbounded
  resource, target-value disclosure, or regression in the preserved lifecycle
  and ownership controls.

This remains private repository-local authenticated admission metadata only.

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
