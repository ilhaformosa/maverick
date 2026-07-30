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

## Next Repository-Local Slice

### T004 — Reject unknown keys in stored client-profile JSON

Queued on 2026-07-30 under the continued privacy-safe repository-local
development authorization recorded in `STATUS.md`. This roadmap sets execution
order only; it does not record or expand authorization. T004 is the next small
P0-E slice and executes before the general failure-driven order below. It does
not define the Beta.2 release scope or a schema-2 design.

- **User result:** the current reader intentionally tightens observable
  compatibility: exact known-field published Beta.1 flat profiles remain
  readable for explicit migration, while extra-bearing flat profiles previously
  accepted and ignored by the Beta.1 reader, and schema-1 envelopes with extra
  keys, are rejected before migration, secret-store access, or silent fallback
  to default values. The ignored extras were never preserved by migration or
  rewriting and were never a supported extension mechanism.
- **Scope:** tighten only the hand-written `StoredClientProfile` deserialization
  boundary with a private strict payload reader using the existing workspace
  `serde_ignored` dependency; add the SDK manifest and lockfile edge, a fixed
  anonymous Beta.1 fixture, focused tests, and the related configuration
  contract. Public nested SDK and shared core structs retain their direct
  generic Serde behavior.
- **Acceptance:** exact known-field Beta.1 flat profiles remain readable and
  explicitly migratable. Current and legacy representations reject unknown keys
  at every represented mapping node, including extra-bearing profiles accepted
  and ignored by the old Beta.1 reader and the two reproduced typos; malicious
  and numerous keys produce only the fixed bounded metadata error without key,
  value, or private-data echo; known duplicate keys remain rejected; rejection
  precedes secret-store access. Legal current round-trip, exact legacy migration,
  all three channel-binding choices, schema-0-envelope rejection, malformed
  current handling, secret redaction, and same-shape unsupported-schema behavior
  remain intact. SDK, core, smoke, complete local-harness, formatting, lint, and
  privacy checks pass.
- **Out of scope:** schema-2 design; generic core Serde tightening; CLI or
  runtime changes; config, protocol, auth, frame, wire, or stored-schema version
  changes; deployment, release, push, tag, publication, or infrastructure work.
  Rejection when callers manually construct and serialize a contradictory
  `StoredClientProfile` remains a separate future candidate rather than part of
  T004.
- **Stop conditions:** stop if closure requires changing any public nested or
  shared core DTO, parsing through `serde_json::Value`, matching error strings,
  changing a version boundary, expanding beyond stored-profile metadata, or
  using privileged, paid, system-network, real-network, or private
  infrastructure access.

After T004 completes or reaches a stop condition, resume the failure-driven
execution order below. Completion of T004 alone does not create a new product
result or change the milestone truth in `STATUS.md`.

## Execution Order

1. **Fix only reproduced Beta failures.** After Beta.1, use the smallest local
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

`protocol_version` and config `version` remain `1` for Beta.1. Any future
wire or config change requires an explicit compatibility decision based on
observed user need.
