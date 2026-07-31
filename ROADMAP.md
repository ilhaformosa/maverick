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

### T014b-1 — Observe pooled H2 client-facing outer TLS versions

This repository-local slice is not bound to a release version.

- **User result:** During an owner- or operator-controlled shutdown, the
  privacy-safe H2 pool summary reports how many pool-managed physical
  connections actually negotiated outer TLS 1.2, TLS 1.3, or an unknown
  version. This is bounded diagnostic context, not an ordinary user's live
  status or a security recommendation.
- **Scope:** Read the negotiated version from rustls or BoringSSL after the real
  TLS handshake and before handing the stream to H2. Carry one fixed
  `TLS 1.2 | TLS 1.3 | unknown` classification to `ClientTunnelPool`, then count
  it exactly once when `install_and_checkout` installs the completed physical
  H2 generation. Keep the counts in a crate-private shutdown-only snapshot and
  include only fixed, destination-free integer counters in the existing
  controlled-shutdown summary.
- **Acceptance:** First installation counts once; cached checkout and stream
  reuse do not recount it; each replacement generation counts once.
  TLS 1.2 plus TLS 1.3 plus unknown always equals `connections_created`, with
  saturating counters. `unknown` is fail-safe for a missing or other backend
  result and is never guessed from configured or offered versions. The public
  `H2ConnectionPoolSnapshot` and `H2TunnelRequestSender`, connection success
  and failure behavior, TLS settings, authentication, wire, config and schema
  remain unchanged. Default browser TLS, no-default-features rustls, and H3
  feature builds and tests remain healthy.
- **Out of scope:** H3, H3-to-H2 non-pooled fallback, WebSocket, direct
  non-pooled `tunnel::open` H2, authenticated-session counts, provider-to-origin
  TLS, destination HTTPS, end-to-end Maverick TLS, ECH, post-quantum claims,
  channel-binding claims, cipher/group/ALPN/SNI details, ordinary-user live
  diagnostics, public APIs, config or schema changes, dependencies, servers,
  real networks, releases, and product or Live results. With a TLS-terminating
  provider front, the observed leg is client to provider edge. All-zero counts
  mean only that this process installed no H2 physical connection managed by
  this pool.
- **Stop conditions:** Stop if implementation requires a seventh file,
  `STATUS.md`, Cargo or lockfile changes, a dependency, a public API, config,
  schema or version change, core, SDK, CLI, server, H3, WebSocket or non-pooled
  tunnel changes, new diagnostics machinery, a remote or real network, any
  system-network mutation, or any claim that this diagnostic itself improves
  security or proves a product or Live result.

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
