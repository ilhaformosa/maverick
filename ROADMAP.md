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

### T026a — freeze direct-H3 auth-v3 connection-control mapping (docs only)

- **User result:** Freeze one unambiguous, carrier-specific exception to the
  current fail-closed pre-auth H3 event gate: exactly one ordinary HTTP/3 POST
  request stream carries the existing 256-byte `ClientControl` and exact
  320-byte `ServerConfirmation` on the same physical QUIC/TLS generation. The
  freeze keeps CONNECT, Extended CONNECT, Datagram payload, targets, and every
  user flow forbidden before complete mutual confirmation.
- **Scope:** Change only `ROADMAP.md` and `docs/AUTH_V3_DIRECT_SPEC.md`. Specify
  the exact ordered request and response field sections, byte-for-byte scheme,
  locally trusted authority, path, content type and content length rules,
  DATA/FIN completion, atomic generation slot, quiche 0.29.3 event handling,
  the separate bounded QUIC Datagram receive-queue gate, known push activity
  that quiche does not expose as distinct public events, same-stream
  blocked/partial-send retry, generation-wide close, no-fallback behavior,
  privacy-safe diagnostics, and reuse of the existing T023a resource
  framework. Record the later smallest
  runtime-reference file and test boundary, but write no Rust and create no
  product H3 seam.
- **Acceptance:** The direct-H3 mapping has one answer for every request and
  response field, duplicate or unknown field, partial or excessive body,
  trailer, timeout, reset, QPACK/header failure, concurrent stream, Datagram,
  GOAWAY, PRIORITY_UPDATE, and unknown application event. Cross-check known
  non-event `PUSH_PROMISE`, `CANCEL_PUSH`, `MAX_PUSH_ID`, push-form
  `PRIORITY_UPDATE`, and the push-stream boundary separately from genuinely
  unknown or reserved frames. Prove that every blocked or partial write remains
  the same attempt, same bound stream, exact remaining bytes, and existing
  deadline. Cross-check the
  frozen direct-H3 carrier ID, 256/320 lengths, RFC 9266 label with
  present-empty context, exact control path policy, connection generation, and
  no-0-RTT rule against T013b/T013c/T022a/T023a-1. Preserve the existing
  direct-H2 mapping byte for byte. Markdown structure, exact-file diff, privacy
  scan, and `STATUS.md` blob checks must pass.
- **Runtime and truth boundary:** This slice freezes documentation and work
  order only. `FoundationObservation` remains a collection of same-connection
  TLS/H3 facts, not an authentication capability or state transition. The
  current implementation still rejects every application-visible pre-auth H3
  event, but quiche Datagrams use a separate connection receive queue and
  T023a-1 did not prove a Datagram admission gate. The public quiche event API
  also does not independently surface every known push-related frame or stream
  activity, so T023a-1 did not prove their strict policy rejection. The current
  server role also
  has no independently trusted textual authority input and MUST NOT learn one
  from request bytes or peer SNI. Until those prerequisites and the sole
  exception are implemented and tested in separately reviewed work, product H3
  remains unavailable. `STATUS.md` remains byte for byte unchanged and is the
  only current-truth and authorization source. This queue is not a completion
  ledger and does not define v1.3 release scope.
- **Out of scope:** Rust, tests, vectors, config, schema, core, public API,
  protocol/auth/frame versions, legacy H2 behavior, CONNECT, Extended CONNECT,
  target, DNS, egress, relay, fallback, user flow, data plane, Datagram payload,
  resumed sessions, T023a-2 Stateless Retry or multi-connection admission,
  T023b post-auth quota/expiry/revocation, release, CI, remote, system-network,
  and real-network work remain deferred.
- **Stop conditions:** Stop before changing a third file or `STATUS.md`; before
  changing the frozen 256/320 wire bytes, vectors, labels, context, carrier ID,
  config/schema/auth/frame/protocol version, core primitive, or H2 mapping; or
  if quiche cannot express the one strict mapping without accepting pre-auth
  CONNECT, target, user DATA/Datagram, a second resource framework, private
  data, remote action, CI, real networking, or a host-network change. Also stop
  if the public API or a separately reviewed narrow observable/reject seam
  cannot reject every forbidden known push activity hidden from public H3
  events; do not classify those known activities as ignorable unknown or
  reserved frames.

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
