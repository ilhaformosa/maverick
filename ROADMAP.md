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

### T024a-4 — Fail closed after an interrupted client UDP relay

**User result.** Cancelling one in-flight client `UdpAssociation::relay_packet`
must make that association permanently unusable. A delayed target reply from
the cancelled exchange must never be returned as the response to a later
packet, and that later packet must not reach any target.

This closes one client-side ownership boundary around the existing serial UDP
exchange. It does not add request-response correlation, pipelining, full-duplex
UDP, or a general-purpose SOCKS or TUN UDP contract.

**Scope.** Change only `ROADMAP.md`, `STATUS.md`,
`crates/maverick-client/src/udp.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Preserve every public signature,
wire frame, protocol/config/schema version, feature, dependency, and manifest.
`STATUS.md` may receive one narrow current-truth update only after the green
implementation and every required local gate pass. Keep server, tunnel, core,
SOCKS, TUN, CLI, SDK, manifests, `Cargo.lock`, and every other file unchanged.

**Behavioral red.** One shared real-loopback test must cover the actual H2 and
legacy-H3 client tunnel variants. Open one `UdpAssociation`, send request A to
real target A, and wait until target A receives the exact payload and records
the server's exact UDP source before cancelling the still-pending relay future.
Target A then sends a delayed reply A. Reuse the same association for request B
to a different real target B. On the current implementation, the test must
positively prove that target B receives request B and that the second relay
incorrectly returns delayed reply A, then fail with status 101 at the fixed
fail-closed assertion. A timeout-only failure, mock, missing server, or transport
fallback is not a valid red cause. The H3 case must record H3 selection with no
cooldown before and after the exchange, so any H3-connect fallback to H2 is
rejected.

**Green implementation.** Keep the association's tunnel as optional private
ownership. Encode the request before taking that owner. Immediately before the
first transport await, take the tunnel out of the association; return it only
after a complete, matching UDP response is decoded successfully. After
ownership has been taken, cancellation, send failure, read failure, response
timeout, decode failure, terminal frame, or any other incomplete exchange drops
the tunnel and leaves the association permanently empty. Every later relay
attempt and `close` returns exactly `UDP association is no longer usable`
without transport or target I/O. A local encode failure happens before
ownership is taken and therefore leaves the association usable.

**Acceptance.** The shared behavioral test turns green for real H2 and
legacy-H3: after cancelling A, the second relay returns the fixed error before
sending B, target B remains uncontacted for a bounded observation window, and
the exact server source observed by target A becomes reusable. Existing healthy
same-association A-then-B roundtrips and explicit close remain green. The
smallest deterministic client tests lock successful owner restoration plus
fail-closed cancellation/error ownership where useful without exposing new
APIs. Run focused tests first, then the relevant client and integration suites
under no-default, `h3`, and all-features matrices, formatting, strict Clippy,
Rustdoc, `user-smoke.sh`, and `local-harness.sh` locally.

**Out of scope and stop conditions.** Do not change server, tunnel, core, TUN,
SOCKS, wire, config, limits, authentication, admission, fallback, metrics,
logging, task, lock, queue, map, retry, feature, dependency, manifest, lockfile,
or machine network settings. Do not claim correlation, full-duplex UDP, TUN or
SOCKS end-to-end readiness, physical-connection reuse, real-network evidence,
published-artifact change, or product readiness. Stop and re-adjudicate if
private optional ownership inside `UdpAssociation` cannot enforce the contract,
if healthy close must keep a different contract, or if a fifth file is needed.

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
