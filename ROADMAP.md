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

### T013a — Freeze legacy-auth policy-projection compatibility

This repository-local slice is not bound to a release version.

- **User result:** Maintainers can identify the first honest v1-to-v2 client
  policy projection without calling local requested policy a peer-confirmed or
  runtime-observed result.
- **Scope:** In `CONFIG.md` and this roadmap only, freeze that auth v1/v2
  MAC-protect the client's legacy Mode but do not confirm it as a shared session
  policy. Keep legacy Mode separate from the five v2 axes, and define the first
  positive T010b input as a config-v1 `Mode::Auto` client with H2-only,
  direct-to-Maverick, plain-SNI, shaping-disabled behavior and no other blocker.
- **Acceptance:** The positive projection uses `transport.strategy: h2`, keeps
  source Mode Auto/wire byte 0 only as internal legacy compatibility metadata,
  and writes no Mode into v2 Policy YAML. Stable, Private, server migration,
  H3, WebSocket, mixed TrustRoute, enabled shaping, cross-boundary fallback,
  and peer confirmation remain distinct typed blockers. Ready means only
  **client policy projection ready**, not a complete or runnable v2 config.
  Existing protocol, config, auth, frame, stored-profile, version, and wire
  behavior remain unchanged.
- **Out of scope:** T010b implementation, product code, tests, auth v3 or any
  equivalent new wire contract, authenticated policy echo or selection,
  downgrade negotiation, RFC 9266 policy confirmation, fronted inner
  application-session or per-flow MAC, expiry, revocation, POST-to-CONNECT, H3,
  PQ/KEX, Profile URI v2, runtime consumers, publication, deployment, and
  release work.
- **Stop conditions:** Stop before changing `STATUS.md`, any source or test,
  Cargo or a lockfile, any schema or version, any protocol/auth/frame/wire fact,
  any secret or network state, or any file outside `CONFIG.md` and `ROADMAP.md`.

After this contract is reviewed, the next repository-local slice is T010b's
first config-v1 Auto/H2 client policy projection. It must produce only the
strict five-axis policy result and separate internal legacy compatibility
metadata; complete client or server migration remains later work.

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
