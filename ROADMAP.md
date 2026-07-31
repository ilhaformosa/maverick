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

### T011a-2 — Enforce the strict Profile URI v1 envelope

This repository-local slice is not bound to a release version.

- **User result:** A Profile URI with hidden outer baggage, broken percent
  encoding, invalid decoded text, or excessive parser input fails safely
  instead of being silently simplified or changed.
- **Scope:** Accept only the existing `maverick://profile/v1?...` envelope with
  no username, password, authority port, or fragment. Validate query percent
  triplets and decoded UTF-8 without lossy replacement, preserving URL form
  `+` behavior and legal Unicode. Bound the normalized parser input at 16 KiB
  before URL parsing or field reads, and warn for an argv URL password without
  exposing it.
- **Acceptance:** Username, password, port, fragment (including an empty
  fragment), incomplete or invalid percent triplets, invalid decoded UTF-8,
  and input above the exact limit all fail with a fixed privacy-safe error.
  Exact-limit input and legal lowercase or uppercase hex, Unicode, `+`, and
  encoded delimiters remain accepted. Rejection precedes secret parsing and
  file creation. The existing ten-key allowlist, duplicate rejection,
  serialization order, defaults, secret handling, QR and clipboard rules,
  permissions, overwrite protection, and explicit v2 rejection remain
  unchanged.
- **Out of scope:** Profile URI v2, a core codec, stored-profile migration,
  field-specific or credential-specific size limits, stdin or clipboard
  streaming, complete config v2, a client-role envelope or readiness API,
  runtime consumer, public API or schema changes, dependencies, server
  behavior, and real network work.
- **Stop conditions:** Stop if implementation requires a fourth file,
  `STATUS.md`, Cargo or lockfile changes, a dependency, public API or schema
  expansion, a core, SDK, client, or server change, an upstream input rewrite,
  a real network, or any system-network mutation.

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
