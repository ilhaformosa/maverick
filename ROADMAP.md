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

### T003 — Reject unknown keys in canonical v1 config loading

Queued on 2026-07-30 under the continued privacy-safe repository-local
development authorization recorded in `STATUS.md`. This roadmap sets execution
order only; it does not record or expand authorization. T003 is the first small
P0-E slice and executes before the general failure-driven order below. It does
not define the Beta.2 release scope or complete a config-v2 design.

- **User result:** a misspelled or otherwise unknown mapping key in client or
  server YAML loaded through the canonical v1 API is rejected with a safe
  structural parent location, or a fixed fallback error, instead of silently
  selecting a default or echoing the untrusted key.
- **Scope:** wrap only `ClientConfig::from_yaml_str` and
  `ServerConfig::from_yaml_str` with one private recursive ignored-field helper;
  give only `FallbackConfig`, the single internally tagged config enum, a
  private strict wire type and custom deserializer that maps invalid input to a
  fixed error; and add the narrowly required `serde_ignored` dependency,
  manifest and lockfile changes, documentation, and focused tests.
- **Acceptance:** root, nested, sequence-element, internally tagged fallback,
  advanced, and crypto unknown keys fail before validation or startup; errors
  report only a bounded safe structural parent location or a fixed fallback
  error, without the unknown key, its value, or other private configuration
  data; known duplicate-key rejection and all documented valid v1 defaults and
  fixtures remain intact. Direct generic Serde remains compatible except that
  invalid `FallbackConfig` input, including unknown variant keys, is rejected
  with the fixed error; stored-profile behavior remains compatible. Core, SDK,
  smoke, and complete local-harness checks pass.
- **Out of scope:** bulk `deny_unknown_fields` changes to shared public structs;
  any other direct generic Serde tightening; stored-profile JSON or migration;
  config v2; config, protocol, auth, frame, or wire-version changes; runtime
  transport, deployment, release, push, tag, publication, or infrastructure
  work.
- **Stop conditions:** stop if the hybrid boundary cannot reject every required
  recursive YAML key, if any second shared struct or enum would need tightening,
  if the private strict wire/custom deserializer exception would need to extend
  beyond `FallbackConfig`, if any version boundary must change, or if completion
  requires privileged, paid, system-network, real-network, or
  private-infrastructure access.

After T003 completes or reaches a stop condition, resume the failure-driven
execution order below. Completion of T003 alone does not create a new product
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
