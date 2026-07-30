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

### T005 — Reject contradictory stored profiles before serialization

Queued on 2026-07-30 under the continued privacy-safe repository-local
development authorization recorded in `STATUS.md`. This roadmap sets execution
order only; it does not record or expand authorization. T005 is the next small
stored-profile output-integrity slice and executes before the general
failure-driven order below. It does not define the Beta.2 release scope or a
schema-2 design.

- **User result:** a public `StoredClientProfile` with contradictory current
  metadata can no longer produce a schema-1 envelope through its top-level
  serializer. Rejection happens before a direct writer is called and uses a
  fixed, bounded error that cannot echo profile or endpoint metadata.
- **Scope:** after the existing schema and missing-channel-binding checks, gate
  only `StoredClientProfile::serialize` on the canonical
  `compatibility_status() == Current` predicate; add focused SDK tests and the
  related configuration contract. No public field, DTO, API signature, schema,
  version, or dependency changes.
- **Acceptance:** disabled-but-required channel binding, required binding with
  H3, and required binding with either the legacy or first-class
  TLS-terminating CDN path all report `Malformed` and are rejected by
  `to_string`, `to_value`, and direct `to_writer`. A direct writer receives no
  calls or bytes. Structurally complete malformed current JSON cannot be
  reserialized. The new error is exactly
  `invalid stored client profile metadata`, remains bounded and source-free,
  and never echoes synthetic private or control-character data. Existing schema
  and missing-binding error text and priority remain exact, including schema-2
  metadata that is also missing or contradictory. Legal current envelope shape
  and order, all three channel-binding choices, `require = false` with H3 or CDN
  metadata, normal store/migration/round-trip behavior, secret separation, and
  direct nested Serde compatibility remain intact.
- **Out of scope:** full `ClientConfig`, secret-store, or runtime validation;
  preventing callers from hand-writing equivalent JSON; atomic file persistence
  or a new stored-profile file API; nested/enclosing serializer write
  guarantees; changing downstream writer errors for legal profiles; generic
  Serde tightening; config, protocol, auth, frame, wire, or stored-schema
  version changes; dependencies; deployment, release, push, tag, publication,
  or infrastructure work.
- **Stop conditions:** stop if closure requires duplicating compatibility rules,
  calling full config validation, accessing a secret store, changing existing
  error priority or text, changing a public DTO/API/version/dependency, touching
  another product file, or using privileged, paid, system-network, real-network,
  or private infrastructure access.

After T005 completes or reaches a stop condition, resume the failure-driven
execution order below. Completion of T005 alone does not create a new product
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
