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

### T027b-2c0 — freeze direct-v3 target-open policy before target I/O

- **User result:** One strict config-v3 server role carries its explicit,
  immutable target-open timeout and egress policy together with the already
  validated singleton auth binding. Any future opener MUST bind to this
  explicit policy; this slice does not implement an opener or type-level
  enforce that runtime binding.
- **Scope:** Require server-only `target_open.timeout_ms` in `1..=60000` and all
  five explicit `target_open.egress` booleans (`allow_loopback`,
  `allow_private`, `allow_link_local`, `allow_multicast`, and
  `allow_unspecified`); retain the values in the same frozen
  `DirectV3ServerRoleConfig`; expose read-only access; and reuse the existing
  `ServerEgressPolicyConfig` address-classification semantics. Add exactly two
  additive public read-only getters, `target_open_timeout_ms()` and
  `target_open_egress_policy()`; remove no existing public function or trait.
  Change only `ROADMAP.md`, `CONFIG.md`, the strict direct-v3 role parser, and
  its focused core tests, plus the five existing client/server test-fixture
  locations that parse legal config-v3 server roles; those five files receive
  fixture text only, with no production logic or assertion change.
- **Acceptance:** Parse the complete server role and preserve the timeout and
  every boolean exactly; accept timeout boundaries 1 and 60000; reject a
  missing, null, duplicate, unknown, or wrongly typed policy or nested field,
  timeout 0 or 60001, and any client-role `target_open`; never fill an omitted
  boolean by default; retain fixed value-free errors and Debug; preserve the
  v1/v2 behavior and the authority, TLS path, transport, auth ID, binding, H2,
  and H3 semantics of updated legal v3 roles; intentionally reject formerly
  valid v3 server documents that omit `target_open`; keep all client/server
  feature tests compatible by adding the same neutral explicit policy to their
  existing server-role YAML fixtures; and prove the diff adds no DNS, socket,
  opener, relay, or real I/O.
- **Out of scope:** No DNS lookup, TCP connection, target opener, response,
  DATA handling, relay, fallback, task, channel, server/client/SDK/CLI runtime,
  public runtime API, manifest, lockfile, dependency, vendor, auth-v3 byte,
  protocol, config-version, stored-profile, frame, wire, `STATUS.md`, CI,
  remote, deployment, release, real-network, or system-network change. This is
  public parser/getter pre-runtime config foundation, not runnable H3, target
  connectivity, runtime authentication, release scope, or a product result.
- **Stop conditions:** Stop before a tenth changed file; any manifest,
  lockfile, dependency, vendor, production server/client, SDK, CLI, config-v1,
  policy-only config-v2, stored-profile, auth, frame, wire, protocol, version,
  public runtime API, or `STATUS.md` change; any non-fixture change in the five
  added client/server files; any policy inferred from v1, v2, wire data, target
  data, or environment; any copied IP-classification rule; any DNS, socket,
  opener, response, DATA, relay, or real I/O; any mutable policy exposure, new
  Default or generic Serde surface, value-bearing Debug, or private-value
  disclosure.

This remains repository-local work on public parser/getter pre-runtime config
foundation only.

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
