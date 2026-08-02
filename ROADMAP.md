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

### T023a-1 — reject pre-auth H3 application activity under bounded admission

- **User result:** While the auth-v3 product runtime still does not exist, a
  peer that exchanges only ordinary QUIC/H3 control streams and acceptable
  SETTINGS can produce one foundation fact observation. Any later
  application-visible H3 event is rejected with one fixed privacy-safe error
  and tears down that same connection generation; it cannot produce a second
  observation, authentication capability, target work, or automatic
  replacement.
- **Scope:** Keep admission inside the existing feature-gated
  `FoundationDriver` H3 polling path. Poll throughout the managed foundation
  generation, map any successful quiche application event to a fixed
  `FoundationError`, and never inspect, format, log, or preserve the event,
  headers, stream ID, path, address, connection ID, backend error, or payload.
  Reuse the existing task, command, observation, Datagram, QUIC stream/data,
  connection-ID, path, QPACK/header, socket, handshake, run, response, idle,
  and join bounds. The focused negative fixture waits for the ordinary fact
  observation, then uses one bounded test-only trigger to send one headers-only
  `GET` to the reserved neutral `.invalid` authority solely as a local attack
  input; it is not a product request seam or capability.
- **Acceptance:** Preserve the normal same-generation foundation and every
  T022a exporter-binding test. Record the receiving server generation after
  its single normal observation. In a strict local timeout, the later malicious
  event must make that driver return the fixed pre-auth error, close its
  observation channel without a second observation, refuse later manager
  acquisition, leave the real server accept count at one, and reclaim its task
  and socket resources. Repeat the negative test at least three times. Keep all
  current task/queue, stream/data, QPACK/header, Datagram, connection-ID/path,
  and timeout bounds unchanged, and retain fixed error `Display`, `Debug`,
  source-chain, and log privacy checks.
- **Runtime and truth boundary:** This is crate-private, non-default,
  loopback-only rejection evidence in a foundation that still has no product
  auth state, authenticated marker, target, DNS, CONNECT handling, relay, flow,
  or data plane. Ordinary H3 control streams and SETTINGS are not application
  activity, and `FoundationObservation` records TLS/H3 facts only; it is not an
  authenticated marker, capability, or state transition. The synthetic request
  exists only to attack the rejection gate and must not be described as product
  request support. This closes only the pre-auth application-event gap and does
  not complete T023a. `STATUS.md` remains byte for byte unchanged and is the
  sole current-truth and authorization source. This queue is not a completed
  ledger and does not define v1.3 release scope.
- **Out of scope:** Stateless Retry, multi-connection admission, post-auth
  quotas, expiry, revocation, auth runtime integration, authenticated state
  transitions, request handling, CONNECT, target, DNS, egress, relay, fallback,
  user flow, data plane, Datagram payload, resumed sessions, core/SDK/public
  API, config, wire, frame, schema, version, release, CI, remote,
  system-network, and real-network work remain deferred.
- **Stop conditions:** The exact changed-file boundary is `ROADMAP.md` and
  `crates/maverick-client/src/quiche_foundation.rs`; stop before changing any
  third file. Also stop if legal H3 control/SETTINGS cannot be distinguished
  from application events, a new dependency or public seam is required, the
  frozen core/wire/config/schema/version must change, or success would require
  implementing auth runtime, CONNECT, target, DNS, relay, user data, private
  data, remote action, CI, real networking, or a host-network change.

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
