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

### T013c-2 — strict direct-v3 role configuration and projection

- **User result:** Let a future local direct-v3 client or server role load one
  explicit, strict provisioning document and project it into the T013c-1 owned
  singleton/preselected capability without exposing secrets or using wire data
  to select a profile.
- **Scope:** Add config schema 3 as an intentionally forward-incompatible,
  pre-runtime client/server role schema. It requires the five explicit direct
  policy axes, auth minimum `direct_v3_only`, one singular provisioning binding,
  canonical nonzero opaque 16-byte values, nonzero epoch and credential expiry,
  and the existing full-UTF-8 `SecretString`. Client role data reuses the local
  SOCKS listener plus server address, name, path, CA, and pin settings. Server
  role data reuses its listener, TLS paths, and tunnel path. A version-first
  public role reader delegates v1 to the unchanged canonical reader, rejects v2
  as policy-only, strictly parses v3, and rejects every other version.
- **Acceptance:** Unknown, duplicate, missing, null, mixed-legacy, multi-document,
  malformed role/version, noncanonical ID, zero ID, zero epoch/expiry, and bad
  secret inputs fail closed through fixed privacy-safe errors. H2 and H3 role
  documents produce locally preselected capabilities that can drive the frozen
  pure auth-v3 encode/verify primitives without I/O. Full v3 documents remain
  rejected by the old canonical v1 readers and by direct generic v1 Serde.
  Config v2 remains strict five-axis policy-only. The new direct-v3 role and
  projection types expose no v3 secret, opaque ID, handle, or raw YAML and have
  no Clone, Default, Serialize, or generic Deserialize surface. The versioned
  role readers intentionally preserve `legacy_v1()` access to the unchanged v1
  public fields and `SecretString`; this slice does not close that legacy API.
- **Opaque-value rule:** Each provisioning handle and semantic ID must be
  independently nonzero and canonical base64url-no-pad. A handle and the four
  semantically distinct IDs may contain the same nonzero bytes; fixed positions
  and commitment domains already separate their meanings. Across independent
  bindings, T013c-1 continues to enforce unique handles, tuple-to-PSK and
  PSK-to-tuple uniqueness, and consistent deployment mappings.
- **Runtime boundary:** Schema 1 remains the only runnable CLI/client/server
  config. Schema 2 remains policy-only. Schema 3 is parsed and projected only;
  CLI, SDK, client, server, H2, and H3 runtime entry points do not accept it.
  No trusted connection context, exporter observation, wire input, clock read,
  secret-store access, fallback, or runtime authentication state is created.
- **Out of scope:** Stored profiles and SDK; auth wire/spec/vector changes;
  shared-listener multi-profile dispatch; fronted, Auto, WebSocket, rotation,
  legacy-auth mixing, fallback, PSK trials, runtime connection state, data-plane
  behavior, and PQ/hybrid policy. This slice changes no current product-runtime
  fact and does not modify `STATUS.md`.
- **Stop conditions:** Stop if this needs an eighth file, Cargo or lockfile
  change, a dependency, v1 public-shape/Serde change, runnable v2 or v3 config,
  SDK/CLI/client/server integration, auth-v3 security-logic or wire change,
  fronted/Auto/multi-profile support, remote work, or private data in the diff.

This slice is not tied to a release version, does not define v1.3 release scope,
and does not authorize CI, publication, push, deployment, or real-network work.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Wait for a concrete input.** Accept privacy-safe Beta feedback, a
   reproduced failure, or an explicit owner-defined minimal task. Do not infer
   a new product, release, deployment, or real-network authorization.
2. **Define one smallest slice.** Before implementation, put its user result,
   file scope, acceptance checks, out-of-scope boundary, and stop conditions in
   this queue. Preserve `STATUS.md` as the sole current-truth and authorization
   source.
3. **Keep stronger supply-chain claims deferred.** Provenance and attestation
   need an explicit identity and remote-permission design; signatures need a
   trust-root and key-custody decision; reproducible builds need a separate
   byte-for-byte build experiment. An SBOM is not any of those things.

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
version remain `1` in the published Beta.4 release; existing authentication and
frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
