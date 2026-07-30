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

### T009 — Freeze the strict config-v2 five-axis policy schema

This repository-local slice is not bound to a release version.

- **User result:** Maintainers can validate one small, strict five-axis v2
  policy document without pretending it is a runnable client or server config.
- **Scope:** Add `maverick_core::config::v2::Policy::from_yaml_str` for the
  explicit SecurityPosture, TransportStrategy, TrustRoute,
  NamePrivacyMinimum, and TrafficShapingPolicy requests. Accept only standard,
  Auto or H2, direct-to-Maverick or explicitly acknowledged Cloudflare TLS
  termination, plain SNI, and disabled shaping. Keep public fields private,
  public enums non-exhaustive, and all Serde wire types private.
- **Acceptance:** Direct and TLS-terminating-front policies both accept Auto and
  H2. Every mapping rejects unknown and duplicate keys. Missing axes, malformed
  version metadata, multiple documents, legacy Mode, route conflicts, and
  private input strings fail closed. Reserved H3, native ECH, and front with
  inner end-to-end protection are recognized but unavailable. Existing
  canonical v1 readers keep their current behavior and error text.
- **Out of scope:** Complete ClientConfigV2 or ServerConfigV2, serialization,
  generation, v1 conversion, T010b migration, Profile URI v2, runtime consumers,
  diagnostics, auth v3, PQ/KEX policy, WebSocket or H3 v2 transport, enabled
  shaping, UDP, publication, deployment, and release work. T017 is not reopened.
- **Stop conditions:** Stop before adding a dependency, Cargo or lockfile
  change, public Serde or Default surface, secret or network access, a runtime
  consumer, a new wire fact, or any file outside the four-file T009 slice.

T010b remains later source-level deterministic migration work. It must stop
rather than guess when the v1 oracle reports WebSocket or H3, mixed TrustRoute,
H3 fallback across a security boundary, enabled shaping, or unresolved legacy
Mode compatibility.

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
