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

### T010b — Add the first Auto/H2 client policy projection

This repository-local slice is not bound to a release version.

- **User result:** Maintainers can project the first strictly bounded valid
  config-v1 client subset into a reusable typed v2 Policy without claiming a
  complete configuration migration.
- **Scope:** Add one public core entry point for an already parsed
  `ClientConfig`, a private-field result wrapper, current typed blockers, and
  product tests. Update the publish-disabled T010a client oracle only so Auto
  no longer receives the legacy-compatibility blocker, then test the production
  projection against that independent oracle.
- **Acceptance:** A valid Auto, direct-H2, plain-SNI, shaping-disabled client
  with no H3, WebSocket, or TLS-terminating front projects exactly to
  Standard/H2/DirectToMaverick/PlainSni/Disabled. The result retains Auto as
  separate compatibility metadata, derives wire byte `0` only through
  `Mode::wire_id()`, and reports no peer confirmation. Canonical source
  validation runs first; the remaining blocker order is Mode, H3, WebSocket,
  TLS-terminating front, then shaping. Client Auto loses only the obsolete
  oracle blocker; server, Stable, and valid Private behavior remain blocked.
  Returned values and blockers reveal no source configuration values.
- **Out of scope:** Raw YAML and Profile URI adapters, canonical YAML or other
  serialization, complete client or server config-v2 types, Stable or Private
  positive projection, H3, WebSocket, fronted transport, enabled shaping,
  runtime, CLI or SDK consumers, peer confirmation, auth v3, diagnostics, PQ,
  release, deployment, and publication.
- **Stop conditions:** Stop if the slice requires `STATUS.md`, a fifth file,
  Cargo or lockfile changes, a dependency, a schema/version or
  protocol/auth/frame/wire change, a runtime consumer, a real network, or any
  system-network mutation.

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
