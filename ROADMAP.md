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

### T025a — Normal SOCKS IPv6-loopback UDP relay parity

**User result.** A normal `start_client` whose configured SOCKS5 listener is
the valid IPv6 loopback address `[::1]` can complete UDP ASSOCIATE and relay a
packet instead of advertising an IPv4 UDP socket whose packet is then rejected
by the existing control-peer identity gate. The local SOCKS control and relay
use the same IP family, while the target carried inside the SOCKS UDP packet
remains independent and may still be IPv4. This is local bind-family parity,
not an IPv6-target, dual-stack, IPv4-mapped-address, non-loopback, remote-network,
general-purpose UDP, product-readiness, or release result.

**Confirmed source defect.** Version-1 `ClientConfig` accepts any loopback
`SocketAddr`, including `[::1]`, and normal `start_client` binds that configured
SOCKS listener. The UDP ASSOCIATE handler nevertheless binds its relay
unconditionally to `127.0.0.1:0`, returns that IPv4 address, and later requires
the UDP peer IP to equal the TCP control peer IP exactly. Therefore a control
peer at `::1` cannot use the advertised IPv4 relay: an IPv4 UDP packet is
dropped before tunnel open or target I/O. The existing reply encoder already
supports an IPv6 BND address, so this card needs no SOCKS encoding change.

**Scope.** Hard-limit the complete card to four files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-client/src/socks5.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Behavioral red changes only
`ROADMAP.md` and `tcp_relay.rs`; do not touch production code or `STATUS.md`
until the compile-ready red is independently accepted. Preserve the exact
control-IP and first-UDP-peer pin, every manifest, dependency, feature,
`Cargo.lock`, public API, Maverick protocol and frame encoding, protocol/config/
profile version, server/core/target path, tunnel and connection-manager path,
H2/H3/WebSocket scheduling, TCP/DNS/HTTP CONNECT/TUN behavior, and direct-v3/
quiche H3 path.

**Behavioral red.** Add one final-shape real-loopback test based on parent
`26f78c28a5a6a399dab4ba8b4d86b2197192ca24`. Start `MaverickHarness`, clone its
real client configuration, change only `local.socks5.listen` to `[::1]:0`, and
start that second normal client through public `start_client`. The test must
connect its real TCP control over `::1`, complete method negotiation and UDP
ASSOCIATE, and parse the entire IPv4 or IPv6 BND reply rather than assuming a
fixed ten-byte shape.

The parent branch must observe the advertised IPv4 loopback relay, send one
valid IPv4-target SOCKS UDP packet to it from an IPv4 loopback UDP peer, and
prove boundedly that the real IPv4 target receives nothing. It must also prove
the second client's H2 pool has zero connections, opened streams, and active
streams, which fixes the drop before tunnel work. Capture this expected parent
failure as data, close the control, shut down the second client and harness
cleanly, and only then fail at the fixed panic
`normal SOCKS IPv6 UDP relay stayed unavailable`, producing status 101.

The same test must already contain the green branch. If the reply advertises
`[::1]` with a nonzero port, bind the local UDP peer to `[::1]:0` but keep the
encoded tunnel target IPv4. The real target must receive the exact payload and
reveal its server-side UDP source; its reply must return from the exact
advertised IPv6 relay with the exact IPv4 SOCKS target metadata and payload.
After control EOF, the exact server-side target source must become reusable and
both clients plus the harness must shut down cleanly. A compile failure,
loopback-family skip, IPv6 target substitution, direct public UDP association,
mock, test hook, target contact on the parent branch, parent H2 activity,
incomplete BND parsing, leaked source, unclean shutdown, timeout propagated as
the test error, or different panic is not an accepted red. Record the exact
command, output, exit status, changed-file list, and binary diff hash, then stop
for independent green authorization.

**Green contract.** Add one crate-private bind-family helper in `socks5.rs`.
It chooses the family of the accepted TCP control peer when available and the
control stream's local family only as the existing direct-call fallback. IPv4
selects the existing `127.0.0.1:0`; IPv6 selects `[::1]:0`. Bind exactly one
loopback UDP socket and feed its actual local address to the existing SOCKS
reply encoder. Do not bind the peer's exact source address, create a dual-stack
socket, or treat `127.0.0.1` and `::1` as the same identity.

The relay socket family describes only the local SOCKS peer. Decoded IPv4,
IPv6, and domain targets retain their existing tunnel representation and
behavior; the green test proves only an IPv4 target carried through an IPv6
local relay. Keep exact control-IP equality, exact first-peer address and port
pinning, malformed-packet rejection, retry/fallback behavior, target switching,
association lifecycle, and response encoding unchanged. The helper adds no
task, channel, queue, lock, map, second socket, retry, log, or new error value.

**Green evidence and compatibility.** Re-run the new exact IPv6-control test,
the existing normal H2 and selected-H3 SOCKS UDP roundtrips, H2 serial target
switching, H3 single-active-target handoff, peer-IP/first-peer unit gates, and
the affected client and relay matrices. Only after formatting, strict Clippy,
warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh` pass may
`STATUS.md` record the new behavior and exact evidence boundary.

This changes existing public `start_client` and `serve_udp_associate`, plus
crate-private `serve_udp_associate_with_pool`, runtime behavior without changing
a Rust signature. It changes no package version or published Beta.4 artifact; any
later publication requires a new prerelease and must not rewrite Beta.4. Do not
claim dual-stack-listener compatibility, IPv4-mapped IPv6 support, non-loopback
access, IPv6 target reachability, real-network evidence, or product readiness.

**Stop conditions.** Stop and re-adjudicate if red needs production code,
`STATUS.md`, `support/mod.rs`, a third changed file, a second test file, a test
hook, non-loopback I/O, or cannot bind `::1` on the current host. Stop green if
it needs `accept_udp_peer`, `session.rs`, `lib.rs`, `udp.rs`, any server/core/
frame file, a fifth file, public API or wire change, a manifest, dependency,
feature or `Cargo.lock` change, two UDP sockets, a task/channel/queue/lock/map,
IPv4-mapped-address equivalence, non-loopback acceptance or binding, relaxed
control-IP/first-peer pinning, or an IPv6 target to make the test pass. Also
stop if the result would need to be described as dual-stack, general-purpose
UDP, a remote-network result, product readiness, or a release result.

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
