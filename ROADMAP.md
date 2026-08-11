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

### T024b-4 — Normal SOCKS legacy-H3 single-active-target handoff

**User result.** A normal `start_client` SOCKS5 UDP association using actually
selected legacy-H3 duplex mode can move from target A to target B and later
back to A instead of silently dropping every packet that names a target other
than the first. Each handoff cleanly closes the old fixed-target flow before it
opens the replacement, so the client exposes only the current target through
SOCKS and owns only one association at a time. A completed client close does
not promise that the remote handler has already dropped its flow permit. This
is sequential single-active-target compatibility with the existing serial UDP
model, not concurrent multi-target UDP, physical H3 connection reuse, a remote
permit barrier, a fairness or no-loss promise, TUN integration, games or voice
suitability, a real-network result, or product readiness.

**Scope.** Hard-limit the complete card to four files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-client/src/socks5.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Behavioral red changes only
`ROADMAP.md` and `tcp_relay.rs`; do not touch production code or `STATUS.md`
until the compile-ready red is independently accepted. Preserve every
manifest, dependency, feature, `Cargo.lock`, public API, wire number and
encoding, protocol/config/profile version, server/core/frame path, tunnel and
connection-manager implementation, normal H2/WebSocket/flags-zero UDP path,
TCP/DNS/HTTP CONNECT/TUN path, public fixed-target duplex-association contract,
and direct-v3/quiche H3 path.

**Behavioral red.** Replace the existing normal-client different-target drop
test with one final-shape real-loopback test based on parent
`c8b54b8ce2cd5419ba36603e2eb2e40452f5bcdd`. It must start the normal client
through `MaverickHarness` with experimental H3 and metrics; complete SOCKS5 UDP
ASSOCIATE; reconfirm an actual H3 candidate with no cooldown; and use two real
loopback UDP targets. Packet A1 must complete one full roundtrip and reveal the
exact server UDP source.

The local peer then sends B1. The test must concurrently prove B1 never reaches
target A and wait boundedly for B. On the parent, B remains unavailable because
the fixed-target handler drops it locally. That timeout is captured as the
single missing behavior rather than returned as the test error. The same SOCKS
control and local UDP peer must then send A2, complete another full roundtrip,
and retain A's exact source, proving that the parent is otherwise healthy. The
test must observe exactly one authenticated session, zero H2 pool activity,
and no H3 cooldown. It then closes the SOCKS control, rebinds every observed
exact source, reconfirms no H3 cooldown, and shuts the fixture down cleanly.
Only afterward may it fail at the fixed panic
`normal SOCKS legacy-H3 UDP target handoff stayed unavailable`, producing
status 101.

The same final test shape must already contain the green branch. If B1 arrives,
it must carry exactly B1, return B's response through a correctly encoded SOCKS
packet, and record B's exact source. Without another local UDP packet, target B
must then send one fixed unsolicited push to that source and the SOCKS peer must
receive it with B's exact logical address and port. A2 must then not reach B,
must reach A, and must return through the SOCKS relay. With all three opens
actually selected as H3 and no cooldown or H2 activity, the cumulative
authenticated-session count must be exactly three. After EOF, all unique A1,
B1, and A2 sources must be reusable. A compile failure, direct tunnel or public
library call, mock, H2 fallback, B1 touching A, missing A recovery, timeout
propagated as the test error, leaked source, H3 cooldown, unclean shutdown, or
different panic is not an accepted red. Record the exact command, output, exit
status, changed-file list, and binary diff hash, then stop for independent green
authorization.

**Green lifecycle.** A same-target packet continues on the current duplex
association. When one accepted local packet names a different logical target
or port, retain only that single triggering packet, end the borrowed receive
future, take sole ownership of the old association, and run its existing
bounded close while control EOF remains able to win. Only a successful clean
close return may clear the old association and allow exactly one new
`SocksUdpAssociation::open_with_pool` call for the triggering packet's target.
Do not send that packet on the old flow. Do not begin the new open until the
old close returns successfully. A close error, timeout, cancellation, or
control EOF ends the SOCKS handler without opening or contacting the new
target.

The fresh pool open is a new scheduler decision made only after the old H3
association's client close returns and before the triggering packet has been
sent. Its existing pre-request H3 transport-setup failure may therefore return
one H2 serial association; that is neither replay nor fallback of a sent packet.
An actual H3 tunnel with the verified selected mode bit creates a new
fixed-target duplex association; actual H2, WebSocket, or H3 without that bit
uses the unchanged serial association. A retryable pool or serial-open failure
drops only the retained packet and leaves association state empty; it does not
automatically retry or replay it, although a later new local packet may make
its own open attempt. Once the fresh H3 request authenticates and duplex setup
begins, open, acknowledgement, send, receive, terminal, or close failure
remains terminal for the SOCKS control with no H2 fallback, retry, replay, or
reopen.

**Ownership, loss, and control.** Keep one handler, one accepted local UDP peer,
one client-owned live association, one target owner, and at most one retained
handoff packet. Control EOF must remain selectable while the old association
closes, the fresh pool open waits, and the triggering packet is first sent. EOF
during old close cancels and aborts the old owner and never opens the new one;
EOF during fresh open or first send drops the unsent or ambiguous triggering
packet, aborts the new owner when required by its existing guard, and never
replays it. Existing duplex non-EOF control-byte handling remains unchanged;
if the fresh decision returns serial, its later control handling remains the
existing serial behavior.

After the handler selects a handoff, valid pushes that race from the old target
may be drained and discarded during close and must never be relabeled as the
new target. While close/open/send is pending, the handler does not read another
local datagram: additional packets may remain in the operating-system socket
buffer or be dropped, with no application queue, ordering, fairness, or
no-loss promise. Every successful H3 handoff creates another physical
connection and authenticated session because the current pool shares only H2;
source review must prove the client completes the old close before beginning
that fresh pool open and authentication. A close response FIN is not a server
permit-drop barrier: the remote handler may briefly retain its permit until its
scope drops. This card neither proves nor guarantees a remote permit barrier or
the absence of a brief remote permit-lifetime overlap. Cumulative sequential
handshakes are not bounded by this card. Do not copy target, backend,
credential, certificate path, peer address, or raw transport values into a new
public error or log category.

**Green evidence and compatibility.** The main A1→B1→A2 normal-client test
dynamically proves that the triggering packet does not contact the old target,
three successful H3 authentications are observed cumulatively, the new B
association delivers one unsolicited push without another local packet, H2
pool activity and H3 cooldown remain absent, and every exact source is
reclaimed after control EOF. It does not dynamically prove when the client
called the fresh pool open or began authentication. Source review alone must
lock successful old-close return before the one fresh pool-open and
authentication call, plus EOF selection at every transition await; neither
that review nor this card treats response FIN as a remote permit-drop barrier.
Re-run the existing normal selected-H3 unsolicited-push, authenticated
duplex-open failure/no-fallback, initial H3-setup-to-H2 serial fallback,
ordinary H2 serial target switching, H3/H2 SOCKS roundtrip, and public duplex
close/send cancellation coverage. Existing scheduler and lower-layer tests
remain the evidence for fresh pre-request fallback and association
cancellation; do not claim a new dynamic post-handoff fallback or stalled-close
test without such a test.

This changes existing public `start_client` and `serve_udp_associate` runtime
behavior and is therefore SemVer-observable without changing a Rust signature.
It changes no package version or published Beta.4 artifact; any later
publication requires a new prerelease and must not rewrite Beta.4. Only after
the focused and affected matrices, formatting, strict Clippy, warning-denied
Rustdoc, `user-smoke.sh`, and `local-harness.sh` pass may `STATUS.md` record the
new behavior and exact evidence limits.

**Stop conditions.** Stop and re-adjudicate if red needs production code,
`STATUS.md`, `support/mod.rs`, a third changed file, a manifest, dependency,
feature, test hook, non-loopback I/O, or a second test file. Stop green if it
needs `udp.rs`, `lib.rs`, `tunnel.rs`, `connection_manager.rs`, `transport.rs`,
any server/core/frame file, a fifth file, a public API or wire change, more than
one live association, a task/channel/queue/lock/map, more than one retained
packet, new-open-before-clean-close, automatic retry, or sending one triggering
packet on both carriers. Also stop if control EOF cannot cancel every handoff
await, a close failure can reach the new target, authenticated H3 failure can
fall back or replay, flags-zero target behavior changes, or the result would
need to be described as concurrent multi-target UDP, a remote permit barrier,
physical-connection reuse, fairness, no loss, games or voice suitability,
product readiness, or real-network evidence.

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
