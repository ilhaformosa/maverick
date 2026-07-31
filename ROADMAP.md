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

### T014b-2 — Observe actual pooled H2 outer TLS key-exchange groups

This repository-local slice is not bound to a release version.

- **User result:** During an owner- or operator-controlled shutdown, the
  privacy-safe H2 pool summary reports how many pool-managed physical
  connections actually negotiated each fixed outer-TLS key-exchange group
  class. This is bounded diagnostic context, not an ordinary user's live
  status, a security recommendation, or a post-quantum claim.
- **Scope:** Read the actually negotiated group from rustls
  `negotiated_key_exchange_group()` or BoringSSL's selected group API after the
  real TLS handshake. Immediately reduce it to
  `x25519_mlkem768 | x25519 | secp256r1 | secp384r1 | other_or_unknown`, carry
  only that fixed class into `ClientTunnelPool`, and count it at the same
  `install_and_checkout` generation-install point as the existing outer-TLS
  version observation. Keep both partitions in the crate-private shutdown-only
  snapshot and include only fixed, destination-free integer counters in the
  existing controlled-shutdown summary.
- **Acceptance:** First installation counts once; cached checkout and stream
  reuse do not recount it; each replacement generation counts once.
  The five group counters sum to `connections_created`, independently of the
  existing TLS 1.2, TLS 1.3, and unknown version partition, with saturating
  counters. `other_or_unknown` is fail-safe for a missing or unclassified
  backend result and is never guessed from configured or offered groups.
  Failed connections that never install are not counted. The public
  `H2ConnectionPoolSnapshot` and `H2TunnelRequestSender`, connection success and
  failure behavior, TLS settings and group lists, authentication, wire, config
  and schema remain unchanged. Default browser TLS, no-default-features rustls,
  and H3 feature builds and tests remain healthy.
- **Out of scope:** H3, H3-to-H2 non-pooled fallback, WebSocket, direct
  non-pooled `tunnel::open` H2, authenticated-session counts, provider-to-origin
  TLS, destination HTTPS, end-to-end Maverick TLS, ECH, post-quantum claims,
  require/prefer policy, enabling any hybrid-group registry entry,
  channel-binding claims, raw library group names, other cipher/ALPN/SNI
  details, ordinary-user live diagnostics, public APIs, config or schema
  changes, dependencies, servers, real networks, releases, and product or Live
  results. With a TLS-terminating provider front, the observed leg is client to
  provider edge. All-zero counts mean only that this process installed no H2
  physical connection managed by this pool. This observation is a prerequisite
  input for a later T015 policy decision; it neither defines nor authorizes that
  policy.
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
