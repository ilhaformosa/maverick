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

### T025e — normal selected-H3 TUN reply-independent send-ahead

**User result.** After a normal opt-in TUN client finishes submitting UDP packet
A to one selected legacy-H3 association, local packet B for the same
`{app, target}` can be submitted without waiting for the target to reply to A.
This is sequential send-ahead after the current transport send completes. It is
not concurrent progress while that send is blocked, target delivery proof,
response correlation, general pipelining, or a product result.

**Confirmed source gap.** T025d lets the worker accept `Ok(None)` and continue,
but `MaverickDuplexDatagramFlow` inherits the default `submit_datagram`, which
calls its existing send-then-receive `exchange`. The real selected-H3 adapter
therefore remains reply-gated even though the generic runtime foundation is
ready.

**Scope.** Hard-limit the complete card to four files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-client/src/tun_runtime.rs`, and
`crates/maverick-tests/tests/tun_packet_runtime.rs`. Behavioral RED may change
only the roadmap and real integration test. Production and `STATUS.md` stay
untouched until independent Green authorization. Preserve maverick-tun,
generic `UdpAssociation`, every serial H2/WebSocket/flags-zero path, SOCKS,
server, core, DNS, TCP, direct-v3, connection-manager, transport, manifest,
dependency, feature, `Cargo.lock`, public API, wire, protocol/frame/config/
profile version, and published Beta.4 artifact.

**Adapter contract.** Override `submit_datagram` only for the private
`MaverickDuplexDatagramFlow`. Reject any endpoint different from the fixed open
target before a send. Borrow the existing send half from the sole association
owner, call its existing `send_packet` exactly once, and return `Ok(None)` only
after that future succeeds. Do not wait for a target datagram, fabricate a
response, replay, retry, resend, reopen, or add a second owner. Existing
`exchange`, `receive_unsolicited`, and `close` behavior remain available and
unchanged. Every serial implementation inherits T025d's default exact
`exchange -> Some` behavior.

Cancellation before the existing send guard is armed performs no transport
send. Once that guard is armed, an in-progress send failure or cancellation
retains the existing sticky invalidation and abort behavior. A completed send
does not prove target delivery or identify a later response. The T025d worker
continues to own one flow and its existing bounded command channel; add no
production task, channel, queue, lock, map, buffer, pending response, counter,
config, correlation identifier, or capability flag.

**Behavioral RED.** Based on exact parent
`c4f0421549d2ed11921dda8ada38a3d9687fcfa5`, start the normal client with H3 and
TUN enabled and one real loopback UDP target. Send local A, require the target
to receive A, record its exact source, and deliberately withhold a reply. Send
local B for the same app and target. Before observing B, prove that the packet
runtime accepted and parsed both local packets, emptied ingress, retained one
active association, and recorded no rejection, malformed packet, or UDP drop.
Capture whether the target receives B from the same exact source before any
target response; absence is data and must not propagate as the test error.

Then reply to A, require its packet-runtime delivery, ensure B reaches the same
target source if it was previously absent, reply to B, and require its delivery.
With no new local packet, send and receive one exact-target push, then send C,
require C from the same source, and return its response. Require actual H3 with
no cooldown, zero H2 pool activity, exactly one opened and zero failed TUN UDP
association, no drop, bounded stopped/quiescent cleanup, exact source rebind,
and clean fixture shutdown before the sole fixed panic
`normal TUN legacy-H3 UDP second send stayed reply-gated`. The parent must
compile and exit 101 only there. Any earlier timeout/error, H2 path, second
association, source change, fabricated output, forced cleanup, leak, or
different panic is not an accepted RED. Freeze the exact command, output,
files, diff check, privacy scan, and binary diff hash, then stop for independent
Green authorization.

**Evidence and compatibility.** Green must make that same real-loopback test
prove A and B reach the target in order from one exact source before either
target reply, followed by both replies, one target push without local input, C,
and bounded cleanup. Source review must separately establish exact-target
pre-send rejection, one existing low-level send call, `Ok(None)` only after its
success, one owner, and no retry or correlation claim. Re-run T025d's fake
submission test, the T025c push test, TUN runtime and client feature matrices,
relevant H2/flags-zero/SOCKS regressions, all-features workspace, strict Clippy,
warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh` before updating
`STATUS.md`.

This changes normal opt-in public `start_client` TUN behavior and is
SemVer-observable without adding or changing a public Rust signature. It does
not change a package version or published artifact. Any future publication
requires a new prerelease and must not rewrite Beta.4. This result will not
prove progress during a transport-blocked send, request-response correlation,
arbitrary response ordering, fairness, no loss, multi-target reuse, IPv6,
malicious-peer or transport-pressure behavior, games or voice suitability, a
real TUN device, real-network behavior, product readiness, deployment, or
release authorization.

**Stop conditions.** Stop if implementation needs a fifth file, a public API,
client UDP/pool/transport change, any server/core/SOCKS/maverick-tun edit, a
second owner, or a production task/channel/queue/lock/map/buffer/pending
response. Also stop on any wire/config/version/manifest/dependency/`Cargo.lock`
change, serial-path drift, retry/replay/reopen, target mismatch reaching the
tunnel, inability to preserve cancellation fail-closed behavior, or any claim
beyond sequential submission after the existing send future completes.

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
