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

### T025d — TUN response-optional datagram submission foundation

**User result.** A TUN UDP worker can complete one local datagram submission and
accept the next local datagram without requiring an immediate remote response
to the first. Existing serial connectors still perform their exact one-request,
one-response exchange. This card is a public contract and fake-connector packet
runtime foundation; the normal selected-H3 consumer remains the immediately
following T025e slice, not a result of this card.

**Confirmed source gap.** `DatagramFlow::exchange` always returns one datagram.
The TUN worker therefore remains inside the first exchange until remote input
arrives. A connector that can submit independently cannot tell the worker that
submission completed without fabricating a response, so a second local packet
waits in the existing bounded command channel.

**Scope.** Hard-limit the complete card to five files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-tun/src/lib.rs`,
`crates/maverick-tun/src/runtime.rs`, and
`crates/maverick-tun/tests/runtime.rs`. Behavioral red may change only the
roadmap, the public trait's additive default skeleton, and the runtime test;
production runtime behavior and `STATUS.md` remain unchanged until Green.
Preserve every client, server, core, SOCKS, DNS, TCP, direct-v3, manifest,
dependency, feature, `Cargo.lock`, wire, protocol/frame/config/profile version,
and published Beta.4 artifact.

**Public contract.** Add one object-safe provided method,
`DatagramFlow::submit_datagram`, which returns
`Result<Option<Datagram>, FlowError>`.
Its default must call the existing required `exchange` exactly once and wrap
that response in `Some`, so existing implementers inherit the default while
repository serial runtime behavior remains unchanged.
`Ok(None)` means only that local submission completed without an immediate
response. It is not clean EOF, target acknowledgement, delivery proof, request
correlation, or permission to lose the payload. Later remote input remains the
job of `receive_unsolicited`. Keep the required `exchange` and `close` methods
and their signatures unchanged.

**Runtime contract.** The UDP worker command path calls the new provided method
once. `Some(datagram)` enters the unchanged exact-target, payload, event,
single-pending-response, accepted-backpressure, and packet-writer path.
`None` emits no response, refreshes the existing successful-activity idle
deadline, and returns to the same command, independent-receive, cancellation,
idle, and shutdown select. Reuse the existing bounded command channel and one
flow owner. Do not add a production task, channel, queue, lock, map, buffer,
pending response, counter, config, capability flag, retry, replay, resend, or
correlation identifier.

**Behavioral red.** Based on exact parent
`49157d74c96561190c9ece65488c7c870ab8f794`, add a fake target-aware flow whose
old `exchange` records local A and then waits for cancellation, while its new
submission override records a payload and returns `Ok(None)`. Send A and require
that it entered the old exchange. Send B while no remote response exists and
capture B's current absence as data rather than propagating a timeout. The
future Green branch must observe A and B in order with no fabricated output,
then deliver one exact-target push without local input and submit C afterward.

Drop packet input and require non-forced shutdown, one exact target-aware open,
zero failed associations, zero dropped datagrams, and a fully quiescent final
snapshot before the sole fixed panic
`TUN duplex UDP second submission stayed blocked behind a missing response`.
The parent must compile and fail only there with exit 101. A compile failure,
missing A, B already submitted, timeout as the test error, fake response,
second open, forced cleanup, leaked resource, or different panic is not an
accepted RED. Freeze the exact command, output, files, diff check, privacy scan,
and binary diff hash, then stop for independent Green authorization.

**Evidence and compatibility.** Green must make the same final-shape test prove
ordered A/B submissions without remote input, no fabricated response, one
later exact-target push, C after the push, one flow, and bounded cleanup. The
existing serial fake and packet-runtime suites must prove that the default
still maps one `exchange` response to `Some` byte-for-byte. Re-run the TUN
runtime and library suites, all-features workspace, no-default client matrices,
strict Clippy, warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh`
before updating `STATUS.md`.

This result will not prove a real Maverick client or selected-H3 carrier,
transport-blocked send concurrent with receive, general pipelining, response
correlation, ordering beyond the observed local submissions, fairness, no loss,
multi-target reuse, IPv6, games or voice suitability, a real TUN device,
real-network behavior, product readiness, or release authorization. The one
additive provided public method is SemVer-observable and may conflict with a
downstream same-name method even though existing implementers inherit a
default. It changes no package version or published artifact. Any future
publication requires a new prerelease and must not rewrite Beta.4.

**Stop conditions.** Stop if implementation needs a sixth file, a second public
item or changed required signature, a public type/error/capability flag, a
client/server/core/SOCKS/transport edit, any production task/channel/queue/lock/
map/buffer/pending response, or any wire/config/version/manifest/dependency/
`Cargo.lock` change. Also stop if `None` is treated as EOF or a response, if a
serial flow no longer performs the exact existing exchange, if cleanup or idle
bounds change, or if the result must be described as real H3, blocked-send
concurrency, general duplex UDP, product, or release evidence.

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
