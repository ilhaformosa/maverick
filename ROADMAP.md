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

### T012a — Freeze config v2 semantic contract

This repository-local slice is not bound to a release version.

- **User result:** The future config v2 has one small, explicit semantic
  contract that separates requested security, carrier selection, trust route,
  minimum name privacy, and traffic shaping without claiming unobserved runtime
  capabilities.
- **Scope:** Document the five independent axes, requested-versus-observed
  boundary, initial accepted and reserved values, Auto and fail-closed rules,
  minimum pure-validation conflicts, v1 compatibility boundary, and the exact
  T010a evaluator handoff. Keep the current v1-only parser and runtime
  unchanged.
- **Acceptance:** `CONFIG.md` explicitly says config v2 is not implemented and
  remains rejected. All five requests are mandatory in a canonical future v2
  config. Reserved H3, native-ECH, and inner-end-to-end routes remain
  unavailable. Auto cannot cross a trust or policy boundary or replay user
  data. Requested policy stays separate from read-only selected or observed
  results. v1 Mode, auth bytes, Profile URI v1, stored-profile schema 1, and
  config/protocol/frame/authentication wire facts remain unchanged. The diff is
  documentation-only and the local product gates pass.
- **Out of scope:** A config v2 DTO or parser, v1-to-v2 migration, runtime
  consumer changes, auth v3, actual TLS or name-privacy diagnostics, PQ/KEX
  policy, Profile URI v2, H3/UDP implementation, schema or wire changes,
  publication, deployment, and release-gate work. T017 is not reopened.
- **Stop conditions:** Stop before changing any file other than `CONFIG.md` and
  `ROADMAP.md`, adding a public API type or dependency, accepting config v2 in
  code, freezing an enabled traffic-shaping policy without lossless mapping
  evidence, changing a current product fact, or starting remote, system-network,
  or release work.

The next config task is T010a: implement a pure v1 effective-behavior evaluator
and prove field-by-field mapping or return a review blocker. T009 follows only
after that evidence is sufficient to freeze a strict v2 DTO and parser. Neither
follow-up is authorized by this docs-only slice.

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
