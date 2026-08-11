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

### T024b-3 — Normal SOCKS legacy-H3 duplex UDP integration

**User result.** The normal `start_client` SOCKS5 UDP service can receive
fixed-target datagrams that arrive through an actually negotiated legacy-H3
duplex flow even when the local SOCKS peer has sent no new packet. H2,
WebSocket, actual H3 without the selected mode bit, and H2 returned by the
existing scheduler after an H3 setup failure all remain the existing flags-zero
serial path with one target named independently by each packet. This is narrow,
unpublished SOCKS integration, not a general-purpose UDP, TUN, games, voice,
or real-network result.

**Scope.** Hard-limit the complete card to six files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-core/src/frame.rs`,
`crates/maverick-client/src/udp.rs`,
`crates/maverick-client/src/socks5.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Behavioral red changes only
`ROADMAP.md` and `tcp_relay.rs`; do not touch production code or `STATUS.md`
until the red is independently accepted and green is authorized. The sole
`frame.rs` change is the public duplex-flag Rustdoc correction required after
normal selected-H3 SOCKS becomes a consumer; do not change the constant, wire,
test, or core behavior. Preserve every manifest, dependency, feature,
`Cargo.lock`, public API, wire number and encoding, protocol/config/profile
version, server path, normal TCP/DNS/HTTP CONNECT/TUN path, and
direct-v3/quiche H3 path.

**Behavioral red.** One final-shape real-loopback test must start the normal
client through `MaverickHarness`, complete SOCKS5 UDP ASSOCIATE, and use an
actual negotiated legacy-H3 carrier with no cooldown and no H2 pool activity.
Packet A must reach one real UDP target; that target must reveal the exact
server UDP source, return A successfully through SOCKS, and then send two
further datagrams to the still-owned source without another local client
packet. The old serial parent must deliver neither push. After bounded control-
EOF cleanup, the test must rebind the exact source, reconfirm H3 without
cooldown, shut down cleanly, and only then fail at the fixed panic
`normal SOCKS legacy-H3 UDP target push stayed unavailable`, producing status
101. A compile failure, mock, public library-only association, direct tunnel
helper, H2/WebSocket path, H3 cooldown, missing A roundtrip, target that did not
really send the pushes, leaked source, timeout returned as the test error, or
different panic is not an accepted red. Record the exact parent, command,
output, exit status, changed-file list, and diff hash, then stop for independent
green authorization.

**Green tunnel decision.** For the first accepted local UDP packet, the normal
SOCKS handler calls `ClientTunnelPool::open` exactly once. If that already-open,
authenticated tunnel is actually H3 and its verified selected mask contains
the existing UDP-mode negotiation bit, construct the duplex association from
that same tunnel and request flags-one. Otherwise, the same already-open actual
H2, WebSocket, or H3-without-the-bit tunnel constructs the unchanged flags-zero
serial association and preserves per-packet target selection. H2 returned by
the existing scheduler after an H3 setup failure is simply that one already-
open H2 tunnel; the SOCKS handler makes no second connection, scheduler, or
fallback decision. Once an H3 tunnel authenticates and duplex setup begins,
any acknowledgement, framing, transport, cancellation, or terminal failure
ends that SOCKS UDP association; do not fall back, replay, or resend the first
datagram on another carrier.

**Duplex-only fixed target and ownership.** Only an actual H3 tunnel with the
verified selected bit and flags-one `OpenUdp` fixes the first legal SOCKS UDP
packet's exact logical target and port for the lifetime of that duplex
association. A later packet for another target or port is dropped locally
before tunnel send; it must contact neither the fixed target A nor rejected
target B, and a following valid packet for A must still work. Flags-zero H2,
WebSocket, and H3 serial associations retain their existing target named by
each packet and do not apply this local different-target drop. Keep one handler
as the sole owner and one `tokio::select!` over control EOF, local SOCKS UDP
input, and target push from the duplex receive half. Add no spawned task,
channel, queue, lock, second association owner, target map, retry, or packet
correlation. Preserve the existing single accepted local UDP peer rule and
SOCKS packet encoding.

**Failure and cleanup contract.** Local malformed, fragmented, and wrong-peer
packets remain drops. A different-target packet is also a local non-poisoning
drop only for the flags-one fixed-target duplex association; flags-zero serial
paths retain their existing per-packet target behavior. Once the handler has
chosen authenticated H3 duplex, any duplex open, first or later send, receive,
terminal, or close failure ends the entire current SOCKS control association
and terminates its handler. It never returns to local-input waiting, clears the
association for reopening, or silently reopens the fixed target. Control EOF,
handler cancellation, clean target idle close, transport error, and normal
return release the duplex owner and exact server UDP source. Do not copy
target, backend, credential, certificate-path, or raw transport values into a
new public error or log category.

**Green acceptance.** Turn the behavioral red green without weakening its
normal `start_client` → SOCKS UDP → authenticated H3 → real-target path. It
must receive both unsolicited pushes in their target-send order and retain the
same exact server source. That observed order is bounded loopback regression
evidence only, not an API or product promise of ordering, fairness, no loss, or
request-response correlation. Add focused real-loopback coverage that (1)
sends a different-target packet after A on flags-one duplex, proves zero A and
B target contact from that packet, then successfully continues with A; (2)
proves the normal H2 SOCKS UDP path retains flags-zero per-packet target
switching; (3) proves an unavailable H3 setup may yield the existing H2
fallback only inside the one pool open, while a failure after H3
authentication/duplex start never falls back or replays; and (4) proves
control EOF while the target-push receive direction is pending cancels that
borrow safely and releases the exact source within the existing bound.

Keep evidence layers explicit. Real normal-client carrier evidence covers
selected legacy-H3 duplex, H2 serial behavior, one in-pool H3-setup-to-H2
fallback, authenticated H3 duplex-open rejection ending the control
association without fallback, and control EOF while receive is pending. Unit
and source evidence lock the single `ClientTunnelPool::open` call, the actual-
carrier plus verified-selected-bit decision, actual H3 without that bit
remaining serial, WebSocket remaining serial at the client decision, exact
flags-one versus flags-zero acknowledgement shapes, fixed-target local
filtering before send, every established-duplex send/receive/terminal failure
branch ending the control association, and the single-owner `select!`
structure. Do not claim a real normal-client H3-without-the-bit dynamic test;
adding a test-only negotiation hook or changing a seventh file is outside this
card. Existing WebSocket TCP and handshake regressions remain its dynamic
compatibility evidence; the current WebSocket server has no normal UDP success
path, so this card does not invent one or claim a WebSocket UDP roundtrip.
Existing public-association tests for clean server idle and transport failure
remain lower-layer lifecycle evidence, not normal SOCKS end-to-end evidence.
Preserve the public duplex API and its cancellation/failure contract, existing
H2/H3 serial `UdpAssociation`, raw-wire duplex server tests, SOCKS local-peer
restriction, TUN behavior, and all TCP/DNS/HTTP CONNECT behavior. Run the
focused red/green test, affected client tests, relevant H2/H3/WebSocket
integration matrices, formatting, all-target/all-feature strict Clippy,
warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh` locally.

**Truth, compatibility, and stop conditions.** This is a SemVer-observable
behavior change to the existing public `start_client` and
`serve_udp_associate` entry points, but it changes no public Rust signature.
The unpublished source card does not change the package version; any future
publication requires a new prerelease and must not rewrite Beta.4. It changes
no published Beta.4 artifact, deployment authorization, release state,
human-user result, or real-network evidence. Only after every green gate passes
may `STATUS.md` record the exact source behavior and residual limits. Stop and re-adjudicate if
compile-ready red or safe green needs `lib.rs`, `tunnel.rs`,
`connection_manager.rs`, `transport.rs`, any server file, any non-documentation
core change, a manifest, a seventh file, a second tunnel open, a
task/channel/queue/lock, flags-one target switching, any change to flags-zero
per-packet target selection, fallback after authenticated H3 duplex start, or
a new public API.

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
