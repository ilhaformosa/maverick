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

### T002 — Explicit stored-profile migration

Queued on 2026-07-30 under the continued privacy-safe repository-local
development authorization recorded in `STATUS.md`. This roadmap sets execution
order only; it does not record or expand authorization. T002 is the next narrow
SDK compatibility slice and executes before the general failure-driven order
below. It does not define the Beta.2 release scope.

- **Scope:** in `crates/maverick-sdk/src/lib.rs`, expose a typed compatibility
  status and a transactional legacy migration API that requires the caller to
  provide every channel-binding value explicitly. Preserve every other field
  represented by the current `StoredClientProfile` schema, keep secret references
  opaque, and serialize successful migrations with the existing versioned
  envelope.
- **Acceptance:** focused unit tests prove typed current/legacy/unsupported/
  malformed states, all three valid channel-binding combinations, preservation
  of every field represented by the current stored-profile schema, typed
  rejection of transport-incompatible explicit choices without partial
  mutation, no secret-store access, and both directions of the Beta.1-reader
  compatibility fixture. `cargo test -p maverick-sdk`,
  `./scripts/user-smoke.sh`, and `./scripts/local-harness.sh` pass locally, and
  the reviewed diff contains only this entry plus the bounded SDK implementation
  and tests.
- **Out of scope:** config, auth, frame, or wire-version changes; H2, H3, Auto,
  padding, server, packaging, deployment, host-network, infrastructure, release,
  tag, push, publication, automatic/default migration, or conversion of
  historical design documents into a second current-truth ledger.
- **Stop conditions:** stop before changing any additional product file,
  inferring a missing legacy security value, widening the public behavior beyond
  stored-profile compatibility, changing any existing protocol/config/auth/frame
  version, accessing a secret store, or requiring any remote, paid, privileged,
  or real-network action.

After T002 completes or reaches a stop condition, resume the failure-driven
execution order below. Completion of T002 alone does not create a new product
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
