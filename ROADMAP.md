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

### T008 — Version-first config parser foundation

This repository-local slice is not bound to a release version.

- **User result:** A config declaring a future version is rejected as
  unsupported before Maverick tries to interpret it as v1 and reports a
  misleading missing or unknown v1 field.
- **Scope:** Add one private, duplicate-safe root-version discriminator shared
  by the canonical client and server YAML readers; dispatch only version `1` to
  the existing strict v1 reader; cover the inherited CLI and SDK paths with
  focused regression tests; document only the resulting reader contract.
- **Acceptance:** Legal v1 files and defaults remain unchanged. Every other
  integer version is rejected with a stable privacy-safe unsupported-version
  result. Missing, duplicate, non-integer, malformed-root, multi-document,
  malicious, and overlong version metadata fails closed without echoing
  untrusted content. Existing v1 unknown-key, duplicate-key, `FallbackConfig`,
  and direct generic Serde behavior remains compatible. Focused red-to-green,
  core, SDK, CLI, formatting, lint, user-smoke, and local-harness checks pass.
- **Out of scope:** Config v2 fields or semantics, v1-to-v2 migration, Profile
  URI v2, runtime-consumer migration, auth or wire changes, broad compatibility
  matrices, publication, deployment, and any subsequent slice not separately
  placed in this queue.
- **Stop conditions:** Stop before adding a public version model, dependency,
  product module, config/protocol/auth/frame/wire/stored-profile version change,
  remote or system-network action, or release work. Any such need returns to
  owner review.

T008 only creates a future version-routing foundation. It does not define
config v2 and does not change the published Beta.2 product facts in `STATUS.md`.
A later `ROADMAP.md` update closes or replaces this queue item. Completing T008
does not authorize any subsequent unqueued slice.

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
