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

### T024b-3a — Bound and cancel normal SOCKS legacy-H3 setup

**User result.** A normal `start_client` SOCKS5 UDP association no longer hangs
indefinitely when its selected legacy-H3 peer accepts QUIC and HTTP/3 but then
stalls while returning the authenticated Maverick `ServerHello`, or returns a
complete valid `ServerHello` selecting flags-zero compatibility and withholds
the ensuing `OpenUdp` acknowledgement. The configured connect deadline ends
that exact SOCKS association, and closing the SOCKS control connection cancels
the pending application-handshake setup promptly. Neither path sends the first
UDP payload, falls back to H2, replays it, or places H3 in cooldown. This is
local reliability hardening against a stalled or faulty endpoint, not general
multi-target UDP, TUN integration, malicious-server completeness, a real-
network result, or product readiness.

**Scope.** Behavioral red is limited to `ROADMAP.md` and
`crates/maverick-tests/tests/tcp_relay.rs`. Green may additionally change only
`STATUS.md`, `crates/maverick-client/src/tunnel.rs`,
`crates/maverick-client/src/udp.rs`, and
`crates/maverick-client/src/socks5.rs`. Preserve every manifest, dependency,
feature, `Cargo.lock`, public API, wire number and encoding,
protocol/config/profile version, server path, H2/WebSocket setup behavior,
successful legacy-H3 tunnel behavior, non-H3 TCP/DNS/HTTP CONNECT/TUN behavior,
public duplex-association contract, and direct-v3/quiche H3 path. Because the
application handshake is part of the common legacy-H3 tunnel open, its new
failure bound is observable by every caller of that common path; this card does
not falsely promise that a stalled legacy-H3 TCP, DNS, HTTP CONNECT, or TUN
open retains an indefinite wait.

**Behavioral red.** One final-shape real-loopback test must start the normal
client with `start_client`, complete SOCKS5 UDP ASSOCIATE, and send the first
legal local UDP packet. A real Quinn/H3 peer trusted by the production TLS
configuration must accept the production request, decode and verify its actual
`ClientHello`, return HTTP 200 `application/octet-stream`, construct a
MAC-valid `ServerHello`, send every byte except its final byte, and keep the
connection available. The test runs two independent cases: a short configured
connect deadline with the SOCKS control left open, and a long deadline followed
by control EOF only after the peer confirms the valid prefix was sent. The
first must end the control association and abort the exact H3 request and
connection no earlier than a reasonable lower bound and no later than a bounded
allowance around the configured deadline. The second must both return EOF to
the local SOCKS control reader and abort the H3 request and connection within
500 milliseconds of local control EOF. Both must prove zero real-UDP-target
contact, zero TCP/H2 fallback attempts on a same-port sentinel, exactly one H3
connection and request with no same-connection or new-connection replay, zero
H2 pool activity, no H3 cooldown, no replay, and clean bounded shutdown. Only
after both cases clean up may a failure use the fixed panic
`normal SOCKS stalled H3 setup stayed alive`, producing status 101.

A second final-shape test reuses the same normal-client and scripted-peer
boundary but sends the complete MAC-valid `ServerHello` with selected mask
zero. It must positively observe the production client send one same-request,
nonzero-flow, exact flags-zero `OpenUdp` carrying the configured idle value,
then withhold the acknowledgement. With the SOCKS control left open, the same
250-millisecond setup deadline, reasonable lower bound, bounded upper allowance,
zero target/H2/fallback/replay/cooldown checks, and strong abort cleanup apply.
Only after cleanup may its parent behavior fail at the fixed panic
`normal SOCKS flags-zero H3 OpenUdp setup stayed alive`, producing status 101.

A mock, direct tunnel or public library call, production test hook, unverified
hello, invalid certificate, incomplete HTTP setup, peer that never confirms its
partial-hello or exact flags-zero-`OpenUdp` barrier, timeout returned as the test
error, target or fallback contact, H3 cooldown, leaked client/server task,
compile failure, or different panic is not an accepted red. Record the exact
parent, command, output, exit status, changed-file list, and diff hash, then
stop for independent green authorization.

**Green contract.** Give the actual-H3 application handshake—from request send
through a completely received and MAC-verified `ServerHello`—one
`connect_timeout_ms` budget in the common legacy-H3 tunnel-open path. Successful
legacy-H3 opens retain their existing result, but every caller of that common
path gains this bounded application-handshake failure instead of an indefinite
wait. Dynamic evidence in this card covers only normal SOCKS UDP; it does not
claim a new runtime cancellation test for TCP, DNS, HTTP CONNECT, or TUN. A
timeout after the H3 request has begun is terminal for that SOCKS association:
drop and synchronously abort its dedicated H3 request/connection, end the
handler, do not mark scheduler cooldown, and do not try H2, replay, resend, or
reopen. While this association open is pending, select the existing control
stream for EOF; EOF cancels and aborts the same owner immediately. Enable this
biased, EOF-first select from one static configured-H3-candidate predicate:
the H3 build is present, mode is `auto`, `experimental_h3` is enabled, and
WebSocket is not selected. This avoids making a second dynamic transport
decision that can race cooldown expiry. The select therefore also spans H3
cooldown and the same pool-open attempt's permitted pre-request H3-connect-to-
H2 fallback wait. Default-H2 `auto`, `stable`, `private`, and WebSocket
configurations retain their direct await. Preserve ordinary
unavailable-H3 transport-connect fallback before an H3 request exists unless
the local SOCKS control reaches EOF first.

If a complete MAC-valid `ServerHello` selects flags-zero compatibility mode,
the ensuing actual-H3 `OpenUdp` acknowledgement wait must use the same bounded
setup policy and control-EOF cancellation. Its timeout is terminal for that
actual-H3 SOCKS association and does not fall back, replay, resend, or reopen.
Do not broaden that deadline to H2 or WebSocket serial association setup.
Existing selected-bit duplex
acknowledgement, send, receive, close, and unusable-state deadlines remain
unchanged. Dropping a pending future must own enough state to abort; do not add
a detached task, channel, queue, lock, retry, second tunnel, or test-only seam.

**Compatibility, evidence, and stop conditions.** The green behavior is
SemVer-observable through existing public `start_client` and
`serve_udp_associate` entry points but changes no signature. Existing honest
H3 success, pre-connect H3-to-H2 fallback, H2/WebSocket serial UDP, selected-H3
duplex UDP, successful TCP, DNS, HTTP CONNECT and TUN paths, and public duplex
library tests must remain green. The common tunnel-open timeout intentionally
changes stalled legacy-H3 failure duration for those callers, while their
successful path remains unchanged. A scripted partial `ServerHello` through
normal SOCKS UDP proves only that client-side stall/cancellation shape; it is
not dynamic evidence for other callers or for a malicious peer's wrong
acknowledgement, malformed/wrong-flow/wrong-target response, partial client
transport write, or blocked client response. Only after all green gates pass
may `STATUS.md` record the exact behavior and residuals.

Stop and re-adjudicate if red needs `support/mod.rs`, production code, a third
test file, a manifest, dependency, feature, or test hook; or if green needs
`lib.rs`, `connection_manager.rs`, `transport.rs`, any server/core/frame file,
a seventh file, a public API change, a task/channel/queue/lock, changed H2 or
WebSocket-only setup semantic, cooldown/fallback/replay after an H3 request
begins, or broader malicious-peer and transport-pressure claims. EOF
cancellation while one statically configured H3 candidate is in cooldown or
its same open attempt is still completing the permitted pre-request H2 fallback
is intentional and must not be generalized to default-H2 `auto`, `stable`,
`private`, or WebSocket configurations.

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
