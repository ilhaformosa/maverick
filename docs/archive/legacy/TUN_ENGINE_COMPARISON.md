# Product TUN Engine Comparison

Status: Phase 0 accepted on 2026-07-12. `smoltcp` `0.13.1` is selected only for
the unprivileged Phase 1 packet adapter. No real TUN device, route, resolver,
firewall, proxy, VPN, interface, public socket, or remote host was used.

## Decision

Use released `smoltcp` `0.13.1`, registry archive SHA-256
`5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e`,
behind a Maverick-owned bounded adapter.

The selected engine owns TCP state, retransmission, windows, reassembly, FIN,
RST, and UDP socket buffers. Maverick must own packet admission, flow and queue
limits, async scheduling, DNS/UDP policy, flow connector tasks, cancellation,
diagnostics, and every operating-system integration boundary.

This is not a product-readiness decision. Phase 1 subsequently passed its
bounded adapter/lifecycle exit gate, and the separately approved Phase 2 IPv4
matrix later passed. IPv6 is unscheduled, and product integration remains
outside this engine-selection result.

## Fixed Inputs

| family | fixed snapshot | license | decision |
| --- | --- | --- | --- |
| `ipstack` plus `tun2proxy` | `ipstack 1.0.0` at `c06e2a1`; `tun2proxy 0.8.2` at `eed123f` | Apache-2.0 plus MIT | rejected |
| `smoltcp` | `0.13.1` at `e347a1e` | 0BSD | selected for Phase 1 |
| gVisor netstack sidecar | source snapshot `6d73c10` | Apache-2.0 | rejected |

Exact full revisions, registry archive hashes, license hashes, toolchain, safety
flags, and aggregate results are machine-checked in
`spikes/tun-engine-comparison/candidates.json` and
`spikes/tun-engine-comparison/results/`.

## Evidence

The isolated selected-candidate harness is not a Cargo workspace member. It pins
`smoltcp = "=0.13.1"`, disables default features, and enables only standard
allocation, IP-medium, dual-stack, fragmentation, TCP/Reno, and UDP features.
Hosted raw-socket and TUN/TAP PHY helpers are absent.

Results:

- exact released `ipstack 1.0.0`: 8 of 8 upstream unit tests passed;
- exact released `tun2proxy 0.8.2`: 2 of 2 upstream unit tests passed with the
  default UDP-gateway feature disabled;
- exact released `smoltcp 0.13.1`: 409 of 409 upstream tests passed for the
  selected feature set;
- Maverick comparison harness: 19 of 19 tests passed;
- mapped comparison cases: 26 of 26 passed;
- explicit concurrency baseline: 100 admitted TCP flows, then zero retained
  sockets after teardown;
- in-memory packet queues never exceeded four entries;
- each TCP flow used fixed 4 KiB receive and send buffers;
- each UDP socket used fixed 4 KiB payload buffers and four message slots.

The comparison covers dual-stack transparent TCP and UDP endpoint mapping,
request/response payloads, malformed and invalid-checksum rejection, empty,
oversized, and saturated admission, unmatched-flow reset, half-close, peer and
engine reset, idle timeout, SYN-ACK retransmission, reordered and duplicate
segments, slow-reader backpressure, malformed bursts, UDP queue saturation, and
the exact 100-flow admission boundary.

Reproduce the committed layer with:

```sh
cargo test --locked \
  --manifest-path spikes/tun-engine-comparison/smoltcp-harness/Cargo.toml
python3 scripts/check-tun-engine-comparison.py
python3 scripts/test-tun-engine-comparison.py
```

## Why The Others Were Rejected

### ipstack Family

The released `ipstack` core has six unbounded Tokio channels across global
admission, device egress, session removal, per-flow packets, and per-flow data.
Its configuration has no global flow or accept-queue limit. A Maverick semaphore
outside the crate cannot bound packets already accepted into those queues when a
consumer stalls.

`tun2proxy` uses that released core and therefore inherits the blocker. Its
injected-device entry point avoids host setup, but retaining the bridge would
also duplicate proxy parsing and add DNS, platform, FFI, and optional setup code
that the final embedded connector does not need. Passing small upstream unit
suites does not repair the resource model.

### gVisor Sidecar

gVisor netstack is capable, but its reusable API has no stable versioned module
contract. The allowed first boundary would be a separate Go process, not
in-process FFI. That requires a new bounded and authenticated IPC protocol,
process supervision, crash cleanup, cross-platform sidecar artifacts, and a
second local proxy hop. Those costs are not justified while the native candidate
passes the fixed primitive gate.

## Dependency And Unsafe Review

All selected direct and transitive licenses are compatible with Maverick's
Apache-2.0 distribution. The selected feature graph contains ten runtime
packages and no TUN, raw-socket, libc, FFI, or platform-setup dependency.

`cargo-geiger 0.13.0` reported zero used unsafe expressions in the compiled
`smoltcp` feature set, and the comparison crate forbids unsafe code. It also
reported used unsafe internals in `arrayvec`, `byteorder`, `etherparse`,
`hash32`, `heapless`, and `stable_deref_trait`. These are packet parsing and
bounded container implementations rather than an OS or foreign-runtime
boundary. They remain part of the dependency audit; this decision does not call
the full graph unsafe-free.

## Phase 1 Closeout

The selected dependency entered the product workspace behind build gate
`tun-runtime` and runtime gate `advanced.experimental_tun` with these controls:

- already-open packet I/O; no device creation or host setup API;
- MTU check before engine admission;
- fixed packet ingress and egress queue depths;
- fixed maximum TCP flows, UDP associations, DNS exchanges, and child tasks;
- fixed per-flow buffers and one bounded pending chunk in each direction;
- deterministic immediate rejection above admission limits;
- monotonic timers, TCP and UDP idle expiry, and fragment expiry;
- one cancellation tree with bounded graceful and forced shutdown;
- aggregate diagnostics without addresses, names, payloads, credentials, or
  infrastructure labels;
- existing SOCKS5, HTTP CONNECT, DNS, UDP, H2-pool, and shutdown tests remaining
  green.

Adapter-level DNS, bounded UDP policy, cancellation, idempotent shutdown, child
task accounting, combined engine/connector buffer accounting, coarse
diagnostics, and real Maverick loopback reuse pass Phase 1 tests. The separate
Phase 2 IPv4 matrix added real-TUN fragmentation, ICMP policy, bounded pressure,
RSS/CPU sampling, recovery, and cleanup evidence. IPv6 is unscheduled. 100-flow
stress, sustained throughput, and product-client behavior remain later gates
and are not silently counted as engine-selection or product-readiness evidence.
