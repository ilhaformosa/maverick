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

### T027a-1 — authenticated single-stream classic CONNECT reference

- **User result:** Inside the private feature-gated direct-quiche foundation, a
  paired `127.0.0.1` reference may use one active, same-generation authenticated
  lease to arm at most one client-initiated classic CONNECT request stream. It
  checks the exact request and `200` response fields, carries distinct raw H3
  DATA bytes in both directions, and exercises half-close, reset, and real
  backpressure without resolving or dialing any target. This is a dormant local
  transport reference, not a product runtime, Developer Mode feature, public
  API, or path for real user traffic.
- **Scope:** Change only this queue and
  `crates/maverick-client/src/quiche_foundation.rs`. Add a module-private
  post-auth router and bounded one-shot flow state tied to the manager-issued
  lease, its connection generation, and a lease-specific revocation token.
  Reuse the existing physical connection, command queue, deadline/idle driver,
  and bounded partial/`Done` send helper. Keep synthetic payloads, peer faults,
  outcomes, and spies under `cfg(test)`.
- **Acceptance:** Preserve T026d authentication-once, strict pre-auth event
  gates, same-generation proof, deadline and close invalidation, server
  local-queue honesty, privacy, and reclamation. Prove pre-auth, closed,
  released, dropped, canceled, wrong-generation, and replaced-generation
  attempts send zero CONNECT headers; only one authenticated request stream can
  open; the request is exactly ordered `:method = CONNECT` then `:authority =
  reference.invalid:443`; and the success response is exactly `:status = 200`
  with `fin=false`. Strictly reject missing, duplicate, unknown, reordered, bad
  method or authority request fields and non-200, extra, duplicate, trailer,
  wrong-stream, or out-of-order response events. Prove distinct patterned raw
  DATA arrives byte-for-byte in both directions on that same stream, client
  request FIN still permits response DATA, server response FIN completes the
  flow, reset never retries, a second command or stream cannot reopen it, and a
  consumed success remains alive through another driver tick until explicit
  close. Force real quiche `StreamBlocked`, partial, and `Done` results and
  retain the exact unwritten suffix on the same stream. Keep one physical
  connection, no Datagram path, no target/DNS/fallback, fixed resource bounds,
  fixed value-free errors, cleared buffers, and complete permit reclamation.
- **Compatibility boundary:** The classic mapping itself sends no `:protocol`
  field and uses no H3 Datagram. This reference nevertheless runs only after
  the existing stricter foundation readiness check has observed peer-advertised
  Extended CONNECT and H3 Datagram capabilities. Decoupling that inherited
  precondition is a separate later decision; this slice does not establish
  generic classic-CONNECT peer compatibility.
- **Out of scope:** No target parsing-to-connect, DNS, egress policy, socket
  relay, fallback, UDP, product client or server path, CLI, SDK, public API,
  dependency, Cargo/lock/vendor/core change, wire or version change, CI, push,
  PR, tag, release, remote, deployment, real network, or system-network work.
  `STATUS.md` remains unchanged, and this task defines no release scope.
- **Stop conditions:** Stop on a third changed file; a need for target dialing,
  DNS, egress, socket relay, a second connection, or another queue, manager,
  registry, fallback, or timeout framework; inability to bind header emission
  to the active same-generation lease; dependency/vendor/core/public
  API/wire/version change; sensitive production diagnostics; fabricated
  backpressure evidence; or any focused or full local gate regression.

This private reference is not tied to a release version and does not authorize
publication, push, deployment, or real-network work.

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
