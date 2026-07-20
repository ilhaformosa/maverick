# Product TUN Engine Research

Status: historical preselection research captured on 2026-07-10 and refreshed
for the Phase 0 decision on 2026-07-12. The fixed comparison in
`docs/TUN_ENGINE_COMPARISON.md` selects `smoltcp 0.13.1` only for unprivileged
Phase 1. No route, DNS, firewall, proxy, VPN, interface, or remote-host state was
changed by the comparison.

## Purpose

Maverick needs a maintained userspace TCP/IP engine for product TUN packet
I/O. The project will not implement TCP state, retransmission, congestion,
fragmentation, or packet reassembly from scratch.

This research narrowed the questions for the post-M6 comparison spike. The
later comparison, not this historical snapshot alone, pinned versions, ran the
fixed synthetic harness, and recorded license, unsafe-code, resource, and
lifecycle evidence.

## Maverick Constraints

An acceptable engine or adapter must:

- accept an injected packet stream or already-open TUN handle;
- leave route, DNS, firewall, and interface mutation to Maverick's separately
  approved privileged helper;
- expose IPv4 and IPv6 TCP plus bounded UDP behavior;
- let Maverick reuse its existing auth, H2 connection pool, TCP, DNS, UDP,
  flow-limit, timeout, shutdown, and diagnostics behavior;
- support deterministic unprivileged tests;
- keep packet payloads, destinations, credentials, and private infrastructure
  out of ordinary logs;
- have a compatible license and a reviewable unsafe or foreign-runtime
  boundary;
- avoid forcing a product application to understand Maverick wire frames.

## Research Set

The following three families formed the fixed post-M6 comparison set. Their
final disposition is recorded in `docs/TUN_ENGINE_COMPARISON.md`.

### 1. Native Rust Async Stack: ipstack And tun2proxy

`ipstack` is an asynchronous userspace TCP/IP stack that accepts an
`AsyncRead + AsyncWrite` packet device and yields TCP, UDP, or unknown-protocol
streams. Its own documentation calls it unstable and under development.

`tun2proxy` is a higher-level Rust TUN-to-SOCKS/HTTP implementation built on
`ipstack`. It exposes a library entry point over an injected async device, a
TUN file-descriptor option, IPv4/IPv6, SOCKS5 UDP, and multiple DNS strategies.
Its optional setup mode can change system routing and resolver state, so that
mode is forbidden in the Maverick comparison. Only an injected device or a
pre-opened handle may be used.

Potential fit:

- lowest language-boundary cost for Maverick's Tokio-based runtime;
- a black-box spike can point tun2proxy at Maverick's loopback SOCKS5 listener;
- an embedded spike can compare direct `ipstack` streams with a future narrow
  Maverick flow connector;
- tun2proxy already builds as a Rust library, static library, and dynamic
  library for multiple platforms.

Risks to prove or reject:

- `ipstack` explicitly describes its API as unstable;
- TCP correctness under loss, reordering, half-close, reset, window pressure,
  and long-lived flows requires independent testing;
- the reviewed snapshot contains explicit unsafe `Send` and `Sync` impls for
  its error type and platform-specific unsafe code in a Windows example;
- tun2proxy includes additional proxy parsing, DNS, FFI, platform, and setup
  code that Maverick may not need;
- the black-box SOCKS bridge is useful for a spike but would duplicate parsing
  and add a local hop if retained as the final architecture.

Research disposition: keep both levels in one family. Compare direct `ipstack`
embedding against a tightly restricted tun2proxy library bridge; do not adopt
both.

### 2. Native Rust Low-Level Stack: smoltcp

`smoltcp` is a standalone event-driven Rust TCP/IP stack. Its documented
features include IPv4/IPv6, TCP, UDP, fragmentation and reassembly, configurable
resource counts, congestion-control choices, and an abstract device trait.

Potential fit:

- direct Rust integration and a small engine-owned surface;
- explicit buffers and compile-time/runtime resource limits;
- packet-device abstraction suitable for deterministic synthetic tests;
- long public history and a permissive 0BSD license.

Risks to prove or reject:

- it is lower level than Maverick needs and requires more adapter and scheduler
  code;
- its documented TCP omissions include selective acknowledgements, TCP
  timestamps, and packetization-layer path MTU discovery;
- hosted TUN/TAP and raw-socket helpers contain OS-facing unsafe code;
- a mobile or lossy-network product must not assume an embedded-oriented stack
  behaves like a desktop kernel stack without measurement;
- its current minimum supported Rust version must remain compatible with the
  project's release toolchain.

Research disposition: keep as the native-Rust control candidate. It must win on
correctness, boundedness, and maintainability, not merely on language match.

### 3. Foreign Runtime Boundary: gVisor netstack

gVisor netstack is a full userspace network stack written in Go. The official
networking guide says it can be reused independently and supports several link
layers. The same guide also says its API does not guarantee stability and is
not published with Go module-style versions. The independent `tun2socks`
project demonstrates a cross-platform proxy adapter built on this stack.

Potential fit:

- broad, real userspace-stack behavior and an existing tun2socks integration;
- TCP/IP behavior does not need to be implemented in Maverick;
- a process boundary can isolate the foreign runtime and keep Rust unsafe code
  out of Maverick's protocol crates.

Risks to prove or reject:

- Go runtime, build, packaging, update, and crash-management complexity;
- no stable versioned netstack API contract;
- in-process FFI would be a larger safety and lifecycle surface than a sidecar;
- sidecar IPC and loopback SOCKS add resource and observability costs;
- Apple and mobile packaging must be validated separately rather than inferred
  from desktop success.

Research disposition: keep only as the foreign-runtime comparison. Prefer a
strict process boundary over in-process FFI for the first spike.

## Non-Selected Reference

lwIP is a mature small C TCP/IP stack with IPv4, IPv6, TCP, UDP, DNS, and a BSD
license. It remains a useful behavior and resource reference, but it is not in
the first comparison set because a new C FFI, allocator, threading, and callback
boundary would add substantial unsafe integration work without a clear benefit
over the three families above.

## Snapshot Evidence

The local source inspection used temporary shallow checkouts outside this
repository and deleted them after inspection. Counts are navigation aids, not
security scores or vulnerability findings.

| source snapshot | observed version | relevant observation |
| --- | --- | --- |
| `narrowlink/ipstack` `c06e2a1aaecfd78033e1dca233c2e871b007ae30` | released `1.0.0` | about 3,510 Rust lines; eight test attributes; six unbounded channels; two unsafe auto-trait impls in library code |
| `tun2proxy/tun2proxy` `eed123fbbec06295bf83f9be36d5a0f64ed9a8cb` | released `0.8.2` | about 4,687 Rust lines; injected async-device API; two test attributes; inherits released `ipstack 1.0.0` |
| `smoltcp-rs/smoltcp` `e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897` | released `0.13.1` | about 59,236 Rust lines; 528 test attributes; selected feature graph excludes hosted OS-facing PHY helpers |

Exact dependency source, release tag, checksum, transitive graph, license text,
and selected features are now pinned in the comparison package. A mutable
repository head remains forbidden as a dependency pin.

## Comparison Order After M6

The following order is complete through selection and Phase 1 implementation.

1. Freeze the adapter contract and synthetic matrix.
2. Recheck upstream maintenance, releases, licenses, advisories, MSRV, and
   platform support.
3. Pin no more than three candidate revisions in isolated spike manifests.
4. Run unprivileged synthetic correctness and resource tests.
5. Run a black-box loopback spike before changing Maverick's internal flow API.
6. Prototype the leading embedded boundary only if the black-box result is
   useful.
7. Select one candidate or record a no-selection result with rejection reasons.

Decision: `smoltcp 0.13.1` is selected for Phase 1. The `ipstack` family and
gVisor sidecar are rejected for the reasons recorded in
`docs/TUN_ENGINE_COMPARISON.md`.

## Decision Rules

Reject a candidate if it:

- requires route, DNS, firewall, or interface mutation inside the packet engine;
- cannot accept a pre-opened or injected packet stream;
- cannot bound flows, buffers, queues, or shutdown time;
- fails deterministic TCP close/reset/retransmission or UDP lifecycle tests;
- requires payload or destination logging for normal operation;
- has an incompatible license or an unsafe/foreign boundary the project cannot
  review and maintain;
- requires changing the frozen Maverick wire or authentication formats.

Do not select solely by benchmark throughput. Correct recovery, lifecycle,
bounded resources, platform packaging, and maintenance cost are release gates.

## Primary Sources

- [ipstack repository](https://github.com/narrowlink/ipstack)
- [ipstack API documentation](https://docs.rs/ipstack/)
- [tun2proxy repository](https://github.com/tun2proxy/tun2proxy)
- [smoltcp repository](https://github.com/smoltcp-rs/smoltcp)
- [smoltcp API documentation](https://docs.rs/smoltcp/)
- [gVisor networking guide](https://gvisor.dev/docs/architecture_guide/networking/)
- [gVisor repository](https://github.com/google/gvisor)
- [gVisor-based tun2socks repository](https://github.com/xjasonlyu/tun2socks)
- [lwIP project page](https://savannah.nongnu.org/projects/lwip/)
