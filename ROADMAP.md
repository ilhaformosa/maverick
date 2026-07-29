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

### T001 — SDK stored-profile channel binding

Queued on 2026-07-30 under the continued privacy-safe repository-local
development authorization recorded in `STATUS.md`. This roadmap sets execution
order only; it does not record or expand authorization. T001 is a narrow
exception for the channel-binding persistence failure reproduced in the current
SDK source and executes before the general failure-driven order below. It does
not define the Beta.2 release scope.

- **Scope:** add an independent stored-profile schema version in
  `crates/maverick-sdk/src/lib.rs`; write new stored profiles in a versioned
  envelope that the Beta.1 flat-profile reader rejects; preserve every
  `auth.channel_binding` field; and make legacy profiles without those fields,
  malformed current profiles, and unknown stored-profile schemas fail
  explicitly instead of restoring a security default.
- **Acceptance:** focused unit tests prove complete round-trip behavior,
  Beta.1-reader downgrade rejection, explicit legacy/malformed/unknown-schema
  rejection, and continued secret-store separation. `cargo test -p maverick-sdk`,
  `./scripts/user-smoke.sh`, and `./scripts/local-harness.sh` pass locally, and
  the reviewed diff contains only this entry plus the bounded SDK implementation
  and tests.
- **Out of scope:** config, auth, frame, or wire-version changes; H2, H3, Auto,
  padding, server, packaging, deployment, host-network, infrastructure, release,
  tag, push, publication, or legacy-profile migration API work; and conversion
  of historical design documents into a second current-truth ledger.
- **Stop conditions:** stop before changing any additional product file,
  widening the public behavior beyond stored-profile compatibility, changing
  any existing protocol/config/auth/frame version, performing a real
  secret-store write, or requiring any remote, paid, privileged, or real-network
  action.

After T001 completes or reaches a stop condition, resume the failure-driven
execution order below. Completion of T001 alone does not create a new product
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
