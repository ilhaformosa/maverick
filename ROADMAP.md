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

### T027b-1 — server-owned structured target-open seam

- **User result:** The server's existing target-opening implementation gains one
  crate-private entry that accepts an already structured `TargetAddr` and port.
  The existing public and crate-private `OpenTcpPayload` entries delegate to the
  same implementation, preserving current H2, WebSocket, and legacy behavior,
  errors, metrics, egress, DNS, connection ordering, timeouts, and
  `TCP_NODELAY`. There is no quiche caller, authority parser, new product entry,
  or path for real user traffic.
- **Scope:** Change only this queue and
  `crates/maverick-server/src/relay.rs`. Keep the public `open_target` and
  crate-private `open_target_with_metrics` signatures unchanged. Add exactly one
  crate-private structured `TargetAddr` plus `u16` entry using the existing
  timeout, egress, and metric inputs. Converge all TCP target opening on the one
  existing resolver, egress filter, dual-stack connection race, timeout,
  request-level metric, and `TCP_NODELAY` algorithm.
- **Acceptance:** First retain a failing focused test for the absent structured
  seam, then make it pass with the smallest implementation. Prove both the old
  payload entry and new structured entry connect to the same loopback ephemeral
  listener over IPv4 and, when available, IPv6. Prove structured domain input
  still uses the existing resolver; egress rejection happens before connect;
  old and new entries retain the same fixed error category and metric behavior;
  resolution/connect timeout and failure classification does not drift; and
  successful resolution/connect latency count semantics remain unchanged. All
  existing public target-open and server relay tests remain green. Errors and
  debug output add no target, domain, address, port, raw resolver error, local
  path, identity, credential, or endpoint value.
- **Hard prerequisite:** T023b-1 remains required before any real post-auth H3
  target wiring. The current authenticated capability does not retain the
  expiry, quota, and revocation state required to authorize target work. This
  seam must not be connected to quiche or treated as satisfying that gate.
- **Out of scope:** No authority parser, new caller, quiche or H3 socket relay,
  DNS task, second opener, alternate metrics or error system, queue, manager,
  trait, framework, public hidden API, product dial path, config/schema/wire/
  version change, dependency, Cargo/lock/manifest/core/client/server/SDK/CLI/
  vendor change, CI, push, PR, merge, tag, release, remote, deployment, real
  network, or system-network work. `STATUS.md` remains unchanged, and this task
  defines no release scope.
- **Stop conditions:** Stop on a third changed file; a need for an authority
  parser, new caller, target or DNS task, quiche integration, public signature,
  dependency, feature, config, schema, wire, or version change; any drift in
  H2/WebSocket/legacy behavior, egress-before-connect ordering, dual-stack
  ordering, timeout, metrics, or `TCP_NODELAY`; a test that cannot stay on
  loopback and OS-assigned ephemeral ports; a large refactor or new framework;
  or any focused or full local gate regression.

This internal seam is not tied to a release version and does not authorize
publication, product wiring, deployment, or real-network work.

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
