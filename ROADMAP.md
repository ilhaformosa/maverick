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

### T027b-2c5 — wire production whole-attempt target opener into the fixed slot

- **User result:** The private feature-gated endpoint can make its first
  controlled real IP-literal target TCP connection and preserve that socket in
  the same originating fixed request slot. This still produces no H3 success
  response and proxies no application data.
- **Scope:** Have the actor-owned production `TargetDispatchFuture` pass the
  existing token's frozen target, port, absolute attempt deadline, and egress
  policy directly to the existing whole-attempt opener with the same
  `TargetOpenMetricSinks`. The direct-v3 production opener synchronously forms
  one `SocketAddr` for an IPv4 or IPv6 literal. Earlier parsing and admission
  still represent Domain targets, but this dispatch slice rejects them with a
  fixed resolution failure before `lookup_host` or any system resolver work.
  On IP-literal success, move the returned `TcpStream` only through the existing
  completion into the T027b-2c4 fixed slot. Retain the controlled synthetic
  dispatch seam only for tests of timeout, failure, panic, and teardown.
- **Acceptance:** The production future directly awaits the opener without a
  second deadline, timer, metric recorder, socket owner, task, or channel; all
  opener errors become one fixed source-free unavailable result. Keep at most
  eight actor-owned futures, eight runtime slots, and four ready completions per
  round. Prove loopback success and original-slot ownership, exact resolution
  and connect latency observations, egress rejection without a connection or
  false failure metric, Domain rejection before system resolution or socket
  handoff, whole-attempt deadline priority, prompt drop of injected pending
  generic-helper resolver or connect futures, privacy-safe errors, and all
  retained T027b-2c4 quota, fairness, teardown, EOF, join-before-reclaim, and
  source-shape properties. The injected resolver test is not evidence that
  blocking system DNS is cancellable.
- **Out of scope:** No 2xx or other H3 success response, Headers or DATA read or
  write, relay, half-close forwarding, slot reuse, fallback, product-server
  startup caller, registry or runtime-metrics ownership change, public API,
  config, schema, wire or version change, dependency, manifest, lockfile,
  vendor, core, client, SDK, CLI, `STATUS.md`, CI, remote, deployment, release,
  real-network, credential, infrastructure, or system-network work. A truly
  cancellable production Domain resolver remains a separate later decision;
  this interim restriction does not remove Domain parsing or admission.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_endpoint.rs`, and
  `crates/maverick-server/src/relay.rs` changes. Any need for another timer,
  metric owner, socket collection, background task, response or data plane,
  ninth slot, registry or runtime change, public API, dependency, or
  `STATUS.md` change requires re-adjudication.

This remains repository-local, private, feature-gated, and temporarily limited
to IP-literal production dispatch. Domain admission still exists but fails
closed here until a separately reviewed truly cancellable resolver is chosen.
This slice first stores one controlled real target socket in the already
verified ownership channel, but it does not make H3 successful, carry DATA, run
a relay, create a product-server startup path, establish runtime readiness,
authorize a release, or produce a product result.

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
