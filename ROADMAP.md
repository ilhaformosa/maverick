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

### T027b-2a — strict Classic CONNECT request/authority parser

- **User result:** A future authenticated standard HTTP/3 TCP Classic CONNECT
  path can pass its borrowed raw initial request fields through one strict,
  privacy-safe pure parser and receive the existing typed `(TargetAddr, u16)`.
  This slice has no product caller and performs no DNS lookup, egress decision,
  target connection, socket operation, or traffic relay.
- **Scope:** Change only this queue, `crates/maverick-server/src/lib.rs`, and one
  new private `crates/maverick-server/src/h3_connect.rs`. Accept exactly one
  byte-exact `:method = CONNECT` and one strict `:authority`, in either relative
  order, and no other field. Parse only canonical `domain:port`, `IPv4:port`, or
  `[IPv6]:port`; return the existing target type, lowercase ASCII domains, and
  discard all raw input and lower-level parse errors. Add no quiche dependency.
- **Acceptance:** Retain a real focused red test before implementation, then
  cover the complete positive and strict-rejection matrices for fields,
  authority, canonical ports, IPv4, bracketed IPv6, and ASCII domains. Errors
  are fixed, bounded, source-free, and value-free under both Display and Debug.
  The parser remains a synchronous private function with no caller or side
  effect. Existing T027b-1 resolver, egress, and structured-connect tests plus
  the server, core, client, workspace lint, and local product gates stay green.
  Any future runtime must enforce this order as a hard gate: authenticated
  generation, then policy/lease/admission/permit, then parse, then egress and
  DNS/connect work.
- **Out of scope:** No runtime or quiche caller, trailer input, response parser,
  DNS, egress, opener invocation, socket, target, real traffic, Extended
  CONNECT, `:protocol`, URI Template, CONNECT-UDP, IDNA, URL or HTTP/1 parser,
  public API, dependency or manifest, core/client/SDK/CLI change, config,
  protocol, authentication, frame, wire, stored schema, version, `STATUS.md`,
  CI, push, PR, merge, tag, release, remote, deployment, real network, or system
  network change.
- **Stop conditions:** Stop on a fourth changed file; a need for any dependency
  or manifest, public/runtime API, quiche integration, DNS/socket/opener/target,
  Extended CONNECT or UDP/IDNA work, logging of raw or lower-level errors, an
  unclear raw-header contract, a real-network or unstable-sleep test, any
  T023b-1/T027a-1/T027b-1 safety regression, or any focused or full local gate
  failure.

This pure parser is a future typed boundary, not a product H3 data plane,
authenticated runtime, target-opening result, or publication authorization.

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
