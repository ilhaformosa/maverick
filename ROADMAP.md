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

### T012b-1 — Consume v2 Policy for the first Auto/H2 transport decision

This repository-local slice is not bound to a release version.

- **User result:** The first real client runtime decision uses the already
  validated v2 Policy transport axis for the narrow Auto/direct-H2 subset,
  without changing any other working v1 transport path.
- **Scope:** In the existing private default-transport decision path, consume
  `project_v1_client_policy` only when it succeeds with explicit H2. Keep the
  public selector signature and explicit H2, WebSocket, and H3 connection
  primitives unchanged. Add private provenance tests and short contract notes.
- **Acceptance:** Omitted or explicit Auto in the supported T010b subset selects
  H2 with proof that the decision came from projected Policy. Every projection
  blocker, invalid source, and unsupported future success falls back to the
  unchanged legacy selector. Stable, valid Private where supported, configured
  H3, explicit or provider-fronted WebSocket, provider-fronted H2, and enabled
  shaping keep their current behavior across applicable feature builds.
- **Out of scope:** A complete client-role assembly or config v2; public API,
  schema, dependency, auth, frame, Mode wire byte, trust, name privacy, shaping
  runtime, H3 fallback, endpoint, secret, listener, Profile URI, SDK or CLI
  consumer, server, peer confirmation, connection-success claim, real network,
  release, deployment, and publication.
- **Stop conditions:** Stop if implementation requires a fourth file,
  `STATUS.md`, Cargo or lockfile changes, a dependency, public API expansion,
  duplicated projection rules, a protocol/auth/frame/wire change, a real
  network, or any system-network mutation.

## Execution Order

1. **Fix only reproduced Beta failures.** After Beta.2, use the smallest local
   reproduction and repair for a failure that a Beta user or an authorized
   field run actually observes. Preserve destination-free diagnostics and the
   existing privacy boundaries. Do not add speculative transports, tuning,
   orchestration, or connection-health machinery merely because Beta has
   started. A product-binary change requires a new reviewed Beta artifact; a
   documentation-only clarification must not pretend to be a product fix.
2. **Validate the Stable candidate on a fresh origin.** Before any Stable
   decision, obtain separate authorization for one freshly provisioned clean
   temporary origin and repeat artifact verification, from-scratch installation,
   ordinary browsing, and the applicable reliability and compatibility checks
   using the exact Stable-candidate artifact. The origin must pass the current
   host policy and every recorded stop rule. A retained reference origin or
   Beta result cannot replace this clean-origin gate, and this roadmap item does
   not itself authorize a server, provider change, spending, network change, or
   Stable claim.
3. **Track native server-side ECH upstream.** Keep the current provider-fronted
   path labeled as a workaround, not ECH. Do not fork rustls or vendor an
   unmerged ECH patch in the current plan.

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
version remain `1` for the published Beta.2 release; existing authentication
and frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
