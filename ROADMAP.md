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

### T024b-0 — Negotiate and reject unsupported UDP modes

**User result.** An authenticated legacy H2 or opt-in legacy-H3 peer must never
silently turn a requested UDP mode into the existing serial exchange. Feature
bit `1 << 0` means only that both peers understand the `OpenUdp` mode gate.
`OpenUdp` flags `0` keeps the existing serial request/reply behavior. Bit
`1 << 0` names a known but unsupported duplex request; every nonzero flag value,
including unknown bits, must fail closed with the opened flow's exact
`ProtocolError`. This card does not implement duplex UDP.

**Scope.** Change at most these eight files: `ROADMAP.md`, `STATUS.md`,
`crates/maverick-core/src/auth.rs`, `crates/maverick-core/src/frame.rs`,
`crates/maverick-client/src/tunnel.rs`, `crates/maverick-client/src/udp.rs`,
`crates/maverick-server/src/server.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. `STATUS.md` may receive one narrow
current-truth update only after the green implementation and every required
local gate pass. Preserve the protocol, config, and stored-profile version,
every existing frame encoding, public API signature, feature, dependency,
manifest, and `Cargo.lock`. Keep relay internals, SOCKS, TUN, direct-v3/quiche
H3, normal WebSocket TCP behavior, WebSocket mode-bit offer/selection,
configuration, CLI, SDK, and every other file unchanged.

**Behavioral red.** Raw public-tunnel tests must cover actual H2 and actual
legacy-H3 without using a production client helper to pre-filter the request.
Send a valid `ClientHello` with feature flags `0` or the requested mode-gate
bit, then pipeline `OpenUdp(flags = 1)` and a same-flow valid `UdpPacket` toward
a real loopback UDP target. On the current implementation, each test must
positively observe the target's exact request and reply, the server's
`WindowUpdate`, and the returned UDP response before failing at one fixed
assertion with status 101. A compile error, fallback response, mock, missing
server, timeout-only failure, or wrong transport is not a valid red cause. The
H3 case must establish a real Quinn/H3 carrier rather than H2 fallback.

**Green implementation.** Add `FEATURE_OPEN_UDP_MODE_NEGOTIATION = 1 << 0` as
the sole meaning of negotiated mode-gate understanding. New legacy clients
request it only on legacy H2 or legacy-H3, servers select it there only when
requested, and old feature-zero peers remain authenticated. Add the new bit to
the existing supported-feature mask without clearing, replacing, synthesizing,
or weakening the existing TLS channel-binding selection. A selected handshake
mask is an authenticated supported subset of the requested mask, not a promise
to echo every requested bit. Therefore a new client must accept an old server's
valid selected subset when the mode-gate bit is absent and continue to send only
flags-zero serial UDP. The WebSocket carrier continues to request and select
zero for this bit and keeps its existing normal TCP behavior.

Each concrete H2, H3, or WebSocket client request/tunnel stores the complete
`feature_flags_selected` value only after the corresponding `ServerHello` MAC,
protocol fields, and requested-subset check all pass. It must not reconstruct
that value from the client's offer, carrier choice, or configuration. In
particular, a valid old server that does not select the new bit leaves the
stored value exactly `0` when it selected no other feature; the client must not
promote its own offer into a negotiated fact.

Keep every production `OpenUdp` request at flags `0`. Its existing successful
acknowledgement remains an exact same-flow `WindowUpdate` with flags `0` and an
empty payload. Recognize the duplex bit as named but unsupported; do not add a
duplex state, task, queue, lock, retry, or packet-correlation layer. On both
legacy H2 and legacy-H3 server paths, reject every nonzero `OpenUdp` flag with
an exact same-flow `Error`: flags `0` and only the encoded `ProtocolError`
payload. That per-flow error is an exact flow-id response, unlike the handshake
mask's subset semantics. Reject before acquiring a flow permit, decoding the
`OpenUdp` payload, applying rate policy, opening a target slot or socket, or
performing target I/O. H2 completes that terminal application response with
`grpc-status: 0`; H3 completes it with FIN.

Before the production client sends its first `UdpPacket`, it accepts the open
acknowledgement only when the frame is exactly `WindowUpdate`, has the requested
flow identifier, flags `0`, and an empty payload. A wrong type or flow, any
nonzero acknowledgement flag, or any nonempty acknowledgement payload fails
closed before UDP application data is sent. This shared client check applies to
any production UDP tunnel attempt, including a WebSocket-backed attempt; normal
WebSocket TCP behavior and mode-bit offer/selection remain unchanged.

**Acceptance.** The raw H2 and H3 tests turn green: the authenticated selected
subset contains the requested mode-gate feature, the only post-hello response
is the opened flow's exact `ProtocolError`, no `WindowUpdate` is sent, and the
real UDP target stays uncontacted for a bounded observation window despite the
pipelined same-flow packet. Add the smallest core and client tests that lock
feature encoding and supported-mask selection without regressing the existing
TLS channel-binding bit, plus production flags `0` and exact flags-zero
`WindowUpdate` shape.

Unit tests must cover auth v1 and auth v2 feature encoding and selected-subset
handling, TLS channel-binding preservation, and old-server subset
compatibility, including a new client accepting an old server's valid selected
subset and retaining flags-zero serial UDP. Both handshakes then feed the same
selected-mask helper and the same H2/H3 dispatch gate. The real-carrier H2/H3
raw behavior matrix uses auth v1 and must cover: feature-zero plus flags-zero
keeps the existing serial flow with a new server; feature-zero plus the duplex
bit or a reserved nonzero bit fails closed; mode-gate-requested plus the duplex
bit or a reserved nonzero bit fails closed; and mode-gate-requested plus
flags-zero keeps serial behavior while a new/new legacy H2 or legacy-H3
handshake selects the bit. WebSocket continues to request/select zero for the
bit. Existing normal serial UDP roundtrips, wrong-flow rejection,
interrupted-association fail-closed behavior, H2 gRPC completion, and H3 FIN
behavior must remain green. Run focused tests first, then the relevant core,
client, server, and integration suites under no-default, `h3`, and all-features
matrices, formatting, strict Clippy, Rustdoc, `user-smoke.sh`, and
`local-harness.sh` locally.

**Out of scope and stop conditions.** Do not implement full-duplex UDP,
pipelining, packet correlation, CONNECT-UDP, QUIC Datagram, a general-purpose
SOCKS or TUN UDP contract, physical-connection reuse, or any new runtime owner.
Do not change direct-v3/quiche H3, normal WebSocket TCP behavior, WebSocket
mode-bit offer/selection, config, limits, fallback, metrics, logging,
dependencies, manifests, lockfiles, or machine network settings. Do not claim
real-network evidence, published-artifact change, games or voice suitability,
product readiness, or release authorization. Stop and re-adjudicate if exact
pre-admission rejection cannot be shared safely by H2 and H3, if feature-zero
peers would break, if existing flags-zero serial behavior changes, or if a
ninth file is needed.

The handshake authentication covers requested and selected feature masks, but
this card adds no separate per-flow MAC over `OpenUdp` flags. Direct legacy H2
or H3 therefore continues to rely on its end-to-end transport integrity. The
provider-fronted H2 path retains its already documented terminating
intermediary trust: that intermediary can observe or alter per-flow tunnel
frames. This residual is not closed, renamed, or promoted into an end-to-end
cryptographic guarantee by mode negotiation.

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
