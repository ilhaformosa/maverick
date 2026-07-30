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

### T010a — Freeze v1 effective behavior as an executable oracle

This repository-local slice is not bound to a release version.

- **User result:** Maintainers can give an already validated v1 client or server
  config to one deterministic oracle and see the behavior that current code can
  derive from it, plus a small ordered set of privacy-safe mapping blockers.
- **Scope:** Add a publish-false `maverick-tests` support module with separate
  client and server evaluators. Freeze local legacy Mode and wire ID, carrier
  policy, H3 setup-only fallback and cooldown policy, configured trust-route
  assumption per eligible carrier, including server H2 fronting only when its
  H2 front is selected, server WebSocket fronting, and direct server H3.
  Derive mixed-route blockers from the actual enabled carrier facts, then freeze
  per-carrier TLS/name-privacy/channel-binding facts, role-specific auth
  selection, and the padding, header-aware single-send delay/flush eligibility,
  cover eligibility, and budget behavior currently consumed by each role.
  Inputs are already validated v1 values plus H3 build availability; the oracle
  is pure and does not change or diagnose the runtime.
- **Acceptance:** Default-feature and no-default-feature oracle tests cover all
  three Modes across the applicable client and server cases, omitted versus
  explicit defaults, H2/fronted-H2/WebSocket/H3 policy, setup versus post-setup
  H3 failure, direct H2 beside a fronted WebSocket, direct H3 beside either
  front carrier, single-route H2 fronting, auth and channel-binding differences,
  zero and payload-conditional cover budgets, frame-header batch boundaries,
  role-specific shaping, fixed blocker ordering, and exclusion of private input
  strings. Existing pure scheduler, padding, or batching helpers are used as
  conformance controls where available. Formatting, owning-crate tests and
  Clippy, and both local product gates pass without a product-source,
  dependency, schema, protocol, frame, authentication-byte, or wire-version
  change.
- **Out of scope:** A config v2 DTO or parser, v1-to-v2 serialization,
  source-field presence, T010b migration, runtime-consumer changes, public
  product diagnostics, Profile URI v2, auth v3, PQ/KEX policy, H3 or UDP product
  work, publication, deployment, and release work. T017 is not reopened.
- **Stop conditions:** Stop before expanding beyond the publish-false test
  oracle, its library export, and this roadmap entry; adding a dependency or
  product public API; reading network, secrets, clocks, cooldown state, or the
  environment; changing current validation, defaults, runtime behavior, product
  facts, schemas, or wire bytes; or starting system-network or remote work.

T009 follows only after this oracle passes independent review and provides
sufficient evidence to freeze a strict v2 DTO and parser. T010b remains later
source-level deterministic migration work and is not authorized by this slice.

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
