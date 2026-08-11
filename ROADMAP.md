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

### T025f — authenticated legacy-H3 duplex ready-target non-starvation

**Foundation result.** On one authenticated raw legacy-H3 duplex `OpenUdp`
flow with a nonzero user rate limit, a target datagram that is already ready is
forwarded before the tail of one buffered burst of otherwise valid same-flow,
same-target peer datagrams. This is one bounded local server scheduling result,
not a normal `start_client` result, a general fairness or no-loss guarantee, or
a product result.

**Confirmed source gap.** The duplex server loop currently uses a biased select
that always checks peer input before target receive. When one H3 DATA operation
contains several complete Maverick frames, `h3_read_next_frame` can decode the
remaining peer frames immediately from its existing receive buffer. A target
datagram that becomes ready while a valid peer frame is waiting in the shared
user limiter can therefore remain behind every buffered peer frame. `STATUS.md`
already records this starvation boundary.

**Scope.** Hard-limit the complete card to five files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-server/src/server.rs`,
`crates/maverick-tests/tests/tcp_relay.rs`, and
`crates/maverick-tests/tests/support/mod.rs`. Behavioral RED changes exactly
the roadmap and those two test files. Do not change production or `STATUS.md`
until the compile-ready RED is independently accepted. Preserve H2,
WebSocket, flags-zero and serial UDP, every client/SOCKS/TUN/direct-v3 path,
the one target owner, every manifest, dependency, feature, `Cargo.lock`, public
API, frame encoding, protocol/config/profile version, and published Beta.4
artifact.

**Behavioral RED.** Based on exact parent
`d0f76b07457d8df3c59a105f0396a9907bac76d3`, add one test-only optional user
rate-limit field to `HarnessOptions`, default it to `None`, and map it directly
to the existing `UserConfig.rate_limit`. Use `1,000` bytes per second in one
raw Quinn/H3 loopback test. Complete the production authenticated handshake,
verify the MAC-valid `ServerHello` selected the existing mode-negotiation bit,
open one flags-one duplex flow, and require the exact same-flow, flags-one,
empty acknowledgement before sending application datagrams.

Encode peer packets 1, 2, and 3 as valid same-flow, same-fixed-target frames,
concatenate all three encoded frames, and submit them with exactly one H3
`send_data` call. Packet 1 and packet 3 are tiny. Packet 2 carries about 300
bytes so the real shared limiter creates an approximately 300-millisecond
window. After the real target receives packet 1 and reveals the exact server
source, wait about 50 milliseconds and complete a roughly 550-byte target push
to that source. Require exact packet 2 from the same source, prove that source
is still owned, then capture as a boolean—never as a propagated timeout—
whether packet 3 reaches the target in a bounded middle window before the
ready push is serviced.

On the parent, the peer-biased loop must deliver packet 3 in that window. The
Green branch must leave packet 3 absent while it forwards the exact push first.
In both branches, eventually require exact packet 3 from the same source and
require the raw H3 response to contain the exact push target, port, flags,
flow, and payload. Then send exact `CloseFlow` plus request FIN, require
response FIN with no trailers, rebind the exact target source, verify actual H3
with no fallback or H2 pool activity, and shut the fixture down cleanly. Only
after all cleanup may the parent fail at fixed panic
`legacy-H3 duplex ready target stayed starved behind peer burst`, producing
exit 101. A compile failure, multiple DATA submissions for the burst, missing
MAC-selected bit, early target push, wrong payload/source, incomplete target
send, H2/fallback path, leaked owner, cleanup failure, timeout propagated from
the middle observation, or different panic is not an accepted RED.

**Green server contract.** Keep the outer peer-first select and every terminal
or invalid-peer ordering rule. Only after the current peer frame has passed the
existing same-flow check, is not `CloseFlow`, is an exact flags-zero
`UdpPacket`, decodes successfully, and matches the already fixed target and
port may the handler perform one nonblocking target-receive probe. Never probe
before the first target owner exists. If one target datagram is immediately
ready, process exactly that one through the existing shared user limiter,
frame encoder, H3 response completion deadline, and error path before applying
the limiter or target send for the current peer frame. If no target datagram is
immediately ready, process the peer frame immediately on its existing path.

Do not loop or drain, and do not add a task, channel, queue, buffer, lock, map,
second owner, retry, replay, resend, or correlation identifier. A target
receive or H3 response failure remains terminal and must prevent the current
peer packet from reaching the target. Wrong-flow, close, malformed,
wrong-type/flags, and wrong-target input must still terminate before any new
target I/O. Peer EOF, incomplete tail, peer read failure, idle handling,
source ownership, and response completion bounds remain on their existing
paths.

**Evidence and compatibility.** The focused test will prove only that one
already-ready target packet crosses the tail of one finite valid peer burst
under one nonzero-rate raw-H3 loopback setup. Source review must separately
prove the validation-before-probe ordering, the one-probe ceiling, reuse of the
single target owner and existing deadline/error paths, and absence of new
resources. Re-run the existing negotiated push, wrong-flow, wrong-target,
malformed, idle, blocked-response, flags-zero, H2, and WebSocket regressions,
then all workspace matrices, strict Clippy, warning-denied Rustdoc,
`user-smoke.sh`, and `local-harness.sh` before updating `STATUS.md`.

The Green changes observable authenticated legacy-H3 server scheduling and
shared-limiter accounting order. It is therefore SemVer-observable even though
it adds no public signature or wire value. Any future publication requires a
new prerelease and must not rewrite Beta.4. This does not prove fairness under
an unbounded peer stream, arbitrary ordering, no loss, request correlation,
multi-target behavior, transport pressure, games or voice suitability,
non-loopback or real-network behavior, normal client behavior, human-user
progress, product readiness, deployment, or release authorization.

**Stop conditions.** Stop if RED cannot compile and fail only at the fixed
post-cleanup panic, cannot deterministically make the push ready before packet
3 processing, needs a fourth RED file, or cannot prove one H3 DATA submission,
exact source ownership, and complete cleanup. Stop Green if it needs a sixth
file, a public/wire/config/version/manifest/dependency/`Cargo.lock` change, a
new production resource, a second or looping target probe, target I/O before
complete peer validation, target failure followed by peer send, or any H2,
WebSocket, serial, client, SOCKS, TUN, direct-v3, retry, replay, or owner drift.

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
