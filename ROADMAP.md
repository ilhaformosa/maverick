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

### T024b-2 — Public legacy-H3 duplex UDP association

**User result.** An opt-in Rust library caller can open one public
`LegacyH3DuplexUdpAssociation` for one exact target through the already
authenticated legacy-H3 carrier. It exposes borrowed sending and receiving
halves, so the caller may submit datagrams and independently receive target
pushes without changing the existing serial `UdpAssociation`, SOCKS, or TUN
paths. This is an unpublished, feature-gated library result, not ordinary
product integration.

**Public shape.** Under `feature = "h3"`, add only these public types and
methods:

- `LegacyH3DuplexUdpAssociation::open(&ClientConfig, TargetAddr, u16)`;
- `split(&mut self) -> (&mut LegacyH3DuplexUdpSendHalf,
  &mut LegacyH3DuplexUdpReceiveHalf)`;
- `LegacyH3DuplexUdpSendHalf::send_packet(Bytes)`;
- `LegacyH3DuplexUdpReceiveHalf::receive_packet() -> Result<Option<Bytes>>`;
- `LegacyH3DuplexUdpAssociation::close(self)`.

The target and port are fixed at `open`, so the sending half accepts only
payload bytes. A successful send means only complete tunnel submission, not
target receipt. Receive returns the next target datagram without correlation.
The halves borrow the parent and cannot become independent `'static` owners.
Document no fairness, ordering, no-loss, SOCKS/TUN, real-network, or product-
readiness promise.

**Scope.** Hard-limit the complete card to these seven files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-core/src/frame.rs`,
`crates/maverick-client/src/udp.rs`,
`crates/maverick-client/src/tunnel.rs`,
`crates/maverick-client/src/h3_transport.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. During behavioral red, change only
`ROADMAP.md`, `udp.rs`, `tunnel.rs`, and `tcp_relay.rs`; `h3_transport.rs` may
be added only if the final public signature cannot compile without the future
abort type, and it must not yet implement green abort behavior. Do not touch
`STATUS.md` or `frame.rs` until every green gate passes. Preserve every
manifest, dependency, feature, `Cargo.lock`, wire encoding, protocol/config/
profile version, and every existing public signature.

**Behavioral red.** First add the final public API shape as a compiling minimal
scaffold. `open` must make a new direct Quinn/H3 connection without calling the
general scheduler or its H3-to-H2 fallback and without reading or writing H3
cooldown state. It must use the production `ClientHello` and verify the
production `ServerHello` MAC, protocol, and requested-feature subset, require
the selected mode-gate bit, send exact flags-one `OpenUdp`, and verify the
exact same-flow, flags-one, empty acknowledgement. Every earlier failure maps
to the separate source-free category `legacy-H3 duplex UDP open failed`. Only
after that exact acknowledgement, `open` returns
`legacy-H3 duplex UDP client unavailable` and drops the dedicated owner, so the
red test can distinguish the acknowledged path from an early failure. Other
scaffold methods return the unavailable category rather than panicking or
exposing a partly usable object.

One real `MaverickHarness` loopback test must call that public API, prove H3 is
the active candidate with no cooldown before and after, use a real UDP target,
observe the fixed error with no source, and prove one bounded second of zero
target contact. Only then may it fail at the fixed panic
`public legacy-H3 duplex association stayed unavailable`, producing status
101. A missing symbol, compile failure, mock, hand-built handshake, H2/WS
fallback, target contact, timeout-only failure, or different panic is not an
accepted red. Record the exact parent, command, output, exit status, and diff
hash, then stop for independent green authorization.

**Green ownership and failure contract.** Direct legacy-H3 is the only carrier.
Keep one dedicated H3 connection and request stream; do not retry, replay, or
fall back to H2, WebSocket, flags-zero serial, or direct-v3/quiche H3. The
verified selected mask must contain the existing mode gate, and the client must
accept only the exact flags-one acknowledgement before exposing the
association.

Split the H3 request stream once. The association owns both halves and the sole
transport. `h3_transport.rs` may provide only a crate-private synchronous abort
handle shared by those halves. Use one shared atomic unusable flag, without a
lock, task, channel, queue, second owner, or multi-target map. Pending receive
must be cancellation-safe. Before the first transport await, send and close
must poison their direction with a scope guard; cancellation, deadline,
partial write, transport failure, malformed frame, wrong flow/flags/target, or
terminal error makes the whole association unusable and synchronously aborts
the connection. Do not restore, retry, or reuse an ambiguous owner.

Every H3 DATA and request FIN uses a whole-operation completion deadline. Send
encodes the fixed target and port into exact same-flow flags-zero `UdpPacket`.
Receive accepts only exact same-flow, flags-zero `UdpPacket` for that fixed
target and port, returns its payload, maps the server's idle `CloseFlow` plus
response FIN to `None`, and otherwise fails closed with fixed errors that
contain no backend, target, server, credential, certificate path, or raw error.

`close(self)` races two bounded operations: send exact same-flow empty
`CloseFlow` plus request FIN, while draining any already racing valid packets
until response FIN. Either clean terminal order succeeds and releases the
owner; cancellation, timeout, partial send, malformed terminal data, or
transport failure aborts it. Drop without successful close also aborts. This
card promises no physical-connection reuse.

**Green acceptance.** Split evidence into explicit layers. Through only the
public API and a real loopback H3 server, send A and B before any target reply
and prove both reach the target from one exact server UDP source. Then have the
target send three datagrams without another client frame and receive all three
in arrival order, which is more target output than preceding requests. Send C
afterward and prove the same source remains in use. Close, observe bounded
response completion, and rebind the exact source.

The same public real-H3 layer must prove: full config validation, disabled H3,
a valid WebSocket/fronting selection, and required channel binding all reject
before even a configured UDP server sentinel is contacted; unavailable H3
does not authenticate through an available H2 server; cancelling a pending
receive permits the same half to continue; cancelling send while its poison
guard is armed in a deterministic pre-I/O shaping wait poisons the whole
association; cancelling close aborts and releases the owner; an active target
owner reaches idle `CloseFlow` plus FIN as `None`; and an oversized send after
packet A returns the fixed source-free send-failed category, contacts the
target no further, aborts, and releases the exact source. Later operations
after either poison path must return the fixed source-free unusable category.

Unit and source evidence lock the other reachable invariants: the exact
flags-one acknowledgement classifier rejects wrong flags, flow, or payload;
the receive classifier rejects malformed, wrong-flow, wrong-flags, or
wrong-target frames; the atomic poison guard is sticky and aborts once; close
drops a still-pending direction immediately when its peer fails; and the same
armed guard encloses the real H3 DATA and request-FIN awaits. Existing raw-wire
server duplex tests remain server/protocol regression evidence, not public API
causal evidence.

This card does not add a scripted malicious H3 peer, so it does not claim a
public-carrier dynamic failure for missing feature selection, wrong
acknowledgement, malformed/wrong-flow/wrong-target response, or the fixed
receive-failed and close-failed categories. It also does not deterministically
drive cancellation during a transport write, a partial write, or a blocked
response; the shaping cancellation is specifically pre-I/O. Preserve the
server duplex matrix, flags-zero H2/H3 serial association, H2 nonzero
rejection, WebSocket, SOCKS, TUN, and direct-v3 behavior. Run the focused
red/green test, affected client unit tests, relevant H3 integration tests,
formatting, all-target/all-feature strict Clippy, warning-denied Rustdoc,
`user-smoke.sh`, and `local-harness.sh` locally.

**Truth and compatibility.** This additive public API is SemVer-observable
under the opt-in H3 feature and must not be hidden or called a private seam.
Package version does not change in this unpublished source card; any future
publication needs a new prerelease rather than changing Beta.4. Only after all
green gates pass, update `STATUS.md` to distinguish this public source API from
the still-serial production client paths, and narrow the duplex-constant
documentation in `frame.rs` so it remains true. Do not claim a new human user,
general SOCKS/TUN UDP, games or voice suitability, real-network evidence,
published-artifact change, product readiness, or release authorization.

**Out of scope and stop conditions.** Keep existing `UdpAssociation`, H2,
WebSocket, SOCKS, TUN, DNS, TCP, direct-v3/quiche H3, CLI, SDK, configuration,
limits, metrics, and logging behavior unchanged. Add no target switching,
multi-target owner, packet correlation, CONNECT-UDP, QUIC Datagram, retry,
fallback, task, channel, queue, or lock. Stop and re-adjudicate if compile-ready
red or safe green needs `transport.rs`, `lib.rs`, a server file, a manifest,
an eighth file, a public backend type, or cannot satisfy strict negotiation,
borrowed ownership, synchronous whole-association abort, bounded close, and
privacy-safe fixed errors.

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
