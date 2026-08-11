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

### T024b-1 — Negotiated legacy-H3 server UDP push

**User result.** A directly authenticated legacy-H3 peer whose MAC-verified
`ServerHello` selected `FEATURE_OPEN_UDP_MODE_NEGOTIATION` may request the
already named duplex mode with `OpenUdp(flags = OPEN_UDP_FLAG_DUPLEX)`. The
server acknowledges that exact flow and mode, and the peer's first valid
same-flow `UdpPacket` fixes one loopback-tested target. After that first packet,
the target may send additional datagrams through the same H3 request stream
without waiting for another peer request, while the peer may continue sending
datagrams in the other direction. This is an authenticated legacy-H3
server/wire foundation only. Production `UdpAssociation`, SOCKS, and TUN paths
remain flags-zero serial users and do not request duplex mode.

**Scope.** Change at most these six files: `ROADMAP.md`, `STATUS.md`,
`crates/maverick-core/src/frame.rs`, `crates/maverick-server/src/relay.rs`,
`crates/maverick-server/src/server.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. `STATUS.md` may receive one narrow
current-truth update only after the implementation and every required local
gate pass. The public duplex-constant documentation in `frame.rs` changes only
after behavioral green. Preserve protocol, config, and stored-profile version
`1`; reuse the existing negotiated feature bit, `OpenUdp` flag, frame types,
payloads, and encodings without adding a new number or wire field. Preserve
every public API signature, dependency, feature, manifest, and `Cargo.lock`.
Keep every client crate, H2 behavior, feature-zero behavior, reserved-mode
rejection, WebSocket, direct-v3/quiche H3, SOCKS, TUN, DNS, TCP, configuration,
limits, fallback, metrics, logging, CLI, SDK, and every other file unchanged.

**Behavioral red.** Add one raw real-Quinn/H3 loopback test. Before and after
the request it must prove H3 is the active transport candidate and is not in
cooldown; the sender must be the actual H3 variant. It must open an H3 request
stream, receive HTTP `200` with `application/octet-stream`, authenticate the
returned `ServerHello` MAC, and verify that the selected mask contains the
requested mode-gate bit. It then sends `OpenUdp` with the duplex flag and a
valid same-flow packet toward a real loopback UDP target. At the exact parent,
the test must positively observe the opened flow's exact `ProtocolError`, H3
response FIN, and a bounded interval with zero target contact before failing at
one fixed panic with status 101: `negotiated legacy-H3 duplex OpenUdp stayed
rejected`. A missing symbol, compile error, mock, H2 fallback, missing server,
wrong content type, unverified handshake, or timeout-only failure is not a
valid red.

**Green implementation.** Accept duplex mode only on the actual legacy-H3
carrier when the MAC-verified selected feature mask contains the existing mode
gate and the `OpenUdp` flags are exactly `OPEN_UDP_FLAG_DUPLEX`. Return an exact
same-flow `WindowUpdate` with that same duplex flag and an empty payload before
admitting packet traffic. Feature-zero plus any nonzero flag, any reserved or
mixed flag, and every nonzero H2 `OpenUdp` remain exact same-flow
`ProtocolError` plus their existing terminal carrier shape before flow permit,
`OpenUdp` payload decode, rate policy, target ownership, resolution, socket, or
target I/O. Flags-zero H2 and legacy-H3 remain serial.

Keep one handler future and one target owner; add no spawned task, channel,
queue, lock, retry, replay, packet correlation, second owner, or automatic
fallback. Split the H3 request stream into its send and receive halves, then
select among peer-frame input, the active connected UDP target's receive
future, and the flow idle deadline. H3 DATA and FIN keep the existing
whole-operation completion deadline. If a response DATA or FIN expires or is
partially written, immediately unwind and drop the stream and target owner;
do not retry the response, reuse the ambiguous owner, or send another Maverick
`Error` on the blocked stream. H3 flow control and the UDP socket buffer are
the only buffering. A bounded response send may pause both input directions.

The first decodable same-flow `UdpPacket` fixes its logical `TargetAddr` and
port before policy, name resolution, socket creation, or target I/O. Later
packets may reuse only that exact logical pair. A different target or port
returns the opened flow's exact `ProtocolError` and FIN without resolving,
opening, sending to, receiving from, or otherwise touching the different
target. A wrong-flow actionable frame returns the opened flow's exact
`ProtocolError` and FIN before payload decode, target locking, rate policy, or
target I/O. Malformed or unsupported frames fail closed without becoming target
operations. Prefer a ready peer control frame when selecting, but do not claim
absolute cross-direction ordering: a valid target datagram that already won a
selection may be forwarded before a concurrently arriving bad peer frame is
decoded. Once that bad frame is decoded, start no further target operation and
release the owner while unwinding.

Apply the existing bounded user rate policy to payload bytes in both
directions. Reset the flow idle deadline after each valid same-flow peer packet
and after each datagram received from the fixed target; target traffic may
therefore keep this foundation flow alive. Request EOF releases the owner.
Idle expiry sends the existing same-flow empty `CloseFlow` and bounded FIN.
An explicit valid same-flow `CloseFlow` sends no extra Maverick data frame,
finishes the H3 response within the existing completion deadline, and releases
the exact owner.

**Acceptance.** The real-H3 test turns green with an exact duplex
`WindowUpdate`. Send peer packets A and B before any target reply and prove the
real target receives both from one exact server UDP source. After the first
request establishes that source, have the target send three datagrams without
any intervening peer frame; receive three exact same-flow `UdpPacket` frames,
which is more target output than the two preceding peer requests. Send peer
packet C afterward and prove the target receives it from the same source. Then
send explicit same-flow `CloseFlow`, observe H3 FIN, and rebind the exact
released UDP source. Add bounded tests for target-change rejection with zero
old- or new-target contact, wrong-flow/malformed rejection, active-owner idle
close, and blocked-response deadline cleanup.

Production peer-to-target and target-to-H3 branches must borrow the same
`UserPolicy` and reuse its same `Option<Arc<RateLimiter>>`, throttling the
corresponding payload byte length before target-send or H3-send I/O. Keep the
existing `RateLimiter` unit gate; this card adds no nonzero-rate real-H3 duplex
timing evidence and must not claim end-to-end rate-policy verification.

The existing feature-zero and reserved-mode H2/H3 rejection matrix, flags-zero
serial H2/H3 behavior, H2 completion behavior, H3 FIN behavior, wrong-flow
gate, interrupted-association failure behavior, and target-source reuse and
release tests must remain green. Run the focused H3 red/green test first, then
the affected relay and server unit tests, relevant H3 integration tests,
formatting, strict all-target/all-feature Clippy, Rustdoc with warnings denied,
`user-smoke.sh`, and `local-harness.sh` locally.

**Out of scope and stop conditions.** Do not add a public client duplex API or
wire duplex mode into `UdpAssociation`, SOCKS, TUN, H2, WebSocket, DNS,
direct-v3/quiche H3, CLI, SDK, or configuration. Do not add multi-target
duplex, target switching, request-response correlation, CONNECT-UDP, QUIC
Datagram, physical-connection reuse evidence, or a second runtime owner. Do not
claim product full-duplex UDP, games or voice suitability, general-purpose
SOCKS/TUN UDP, real-network evidence, a published-artifact change, product
readiness, or release authorization. Stop and re-adjudicate if safe stream
splitting, a single fixed target owner, existing H3 completion deadlines, idle
cleanup, two-direction rate policy, or exact terminal behavior cannot fit the
six-file allowlist, or if any client/H2/direct-v3 behavior must change.

The authenticated feature selection and QUIC/TLS transport integrity protect
this direct legacy-H3 foundation. This card adds no per-flow MAC. It does not
alter or close the separately documented provider-fronted H2 terminating-
intermediary trust residual.

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
