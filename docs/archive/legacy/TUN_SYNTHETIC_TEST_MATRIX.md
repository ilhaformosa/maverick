# Product TUN Synthetic Test Matrix

Status: Phase 0 comparison and Phase 1 unprivileged runtime coverage are
implemented. The matrix remains the broader product target, so unimplemented
rows stay visible rather than being counted as passes. No real TUN, route,
resolver, interface, firewall, proxy, VPN, or remote-host operation was used.

## Purpose

Compare packet engines and then hold the selected runtime to one fixed workload.
The harness answers three questions:

1. Does the candidate handle the packet and stream lifecycle correctly?
2. Does it stay bounded under malformed input, concurrency, and backpressure?
3. Can it start and stop cleanly behind Maverick's proposed adapter contract?

Throughput is secondary to correctness, cleanup, and bounded resource use.

## Implemented Coverage

Phase 0 records 19 isolated harness tests mapped to 26 matrix cases, 409 selected
upstream-feature tests, exact dependency/license hashes, and the explicit
selection in `spikes/tun-engine-comparison/results/smoltcp.json`.

Phase 1 adds 21 `maverick-tun` tests, two feature-gated connector tests, and two
feature-gated real Maverick loopback tests. They cover:

- IPv4 and IPv6 TCP round trips, local half-close, remote refusal/reset,
  connect cancellation, backpressure, and idempotent shutdown;
- DNS and generic UDP round trips, independent association mapping, admission
  limits, queue saturation, oversized response rejection, connector-failure
  accounting, and idle cleanup;
- malformed bursts, MTU and family gating, non-initial IPv4 fragment rejection
  when IPv4 is disabled, bounded queues/buffers/tasks, and post-run quiescence;
- invalid config/runtime context and connector accounting, read/write failure,
  reader panic, accepted-packet drain before EOF stop, graceful and forced
  shutdown, and connector reset-versus-EOF preservation;
- one real generated-certificate/auth/H2 loopback path that reuses one H2
  connection for TCP, DNS, and UDP without a public socket.

Still open and not counted as Phase 1 passes:

- adapter-level ordered, out-of-order, overlap, timeout, and exhaustion
  fragmentation fixtures;
- IPv6 extension-header and fragment-chain policy, plus explicit ICMP behavior;
- the full matrix at 100 concurrent adapter flows and repeated long-duration
  churn;
- sustained RSS, CPU, throughput, and shutdown-latency baselines;
- any real-device route, resolver, control-plane bypass, leak, crash, or residue
  result.

## Harness Topology

The default comparison is entirely in memory:

```text
synthetic packet peer
    <-> bounded in-memory PacketIo
    <-> candidate engine adapter
    <-> fake MaverickFlowConnector
    <-> deterministic TCP, DNS, and UDP peers
```

The fake connector records logical operations and simulates success, delay,
backpressure, reset, timeout, and cancellation. It does not open public sockets
or a real TUN device.

The implemented second mode connects the embedded flow connector to a generated
Maverick loopback server on OS-assigned loopback ports. It does not use a
black-box SOCKS hop or change system networking.

## Fixture Rules

- Build packets with structured packet APIs, not hand-edited byte strings,
  except for explicitly malformed cases.
- Use symbolic or documentation-only addresses in committed fixtures.
- Generate checksums deterministically.
- Record the random seed when a property test is used.
- Cap fixture size, fragment count, flow count, queue depth, and runtime.
- Never include real domains, addresses, credentials, packet captures, host
  labels, or local paths.
- Store expected operations separately from candidate output so an adapter
  cannot make its own result true.

## Baseline Matrix

### Packet Admission And Parsing

| id | case | required result |
| --- | --- | --- |
| PKT-01 | minimum valid IPv4 TCP packet | accepted and classified once |
| PKT-02 | minimum valid IPv6 TCP packet | accepted and classified once |
| PKT-03 | valid IPv4 UDP packet | accepted and mapped to one UDP association |
| PKT-04 | valid IPv6 UDP packet | accepted and mapped to one UDP association |
| PKT-05 | truncated IP header at every boundary | rejected without panic or allocation spike |
| PKT-06 | invalid total or payload length | rejected with a coarse reason |
| PKT-07 | invalid TCP or UDP checksum | deterministic reject or documented policy |
| PKT-08 | unsupported next-header or protocol value | explicit unsupported result, no false success |
| PKT-09 | empty packet and packet larger than configured MTU | bounded rejection |
| PKT-10 | repeated malformed packet burst | bounded queue, no log amplification, no task leak |

### IPv4, IPv6, MTU, And Fragmentation

| id | case | required result |
| --- | --- | --- |
| IP-01 | IPv4 and IPv6 routes for the same logical target | correct family retained |
| IP-02 | IPv4 packet exactly at MTU | accepted without extra fragmentation |
| IP-03 | IPv6 packet exactly at MTU | accepted without extra fragmentation |
| IP-04 | packet one byte above MTU | documented fragment or reject behavior |
| IP-05 | ordered IPv4 fragments within budget | one correct reassembled payload or explicit unsupported result |
| IP-06 | out-of-order fragments within budget | correct result or explicit unsupported result |
| IP-07 | overlapping, duplicate, missing, or excessive fragments | bounded reject and state cleanup |
| IP-08 | fragment timeout | reassembly state removed within configured bound |
| IP-09 | IPv6 extension-header chain at configured limit | deterministic handling |
| IP-10 | extension-header chain over configured limit | bounded reject |

An unsupported fragmentation path is acceptable during candidate comparison
only when it is explicit and becomes a product blocker. It cannot be counted as
a passing full-device result.

### TCP Lifecycle

| id | case | required result |
| --- | --- | --- |
| TCP-01 | IPv4 connect, request, response, close | exact payload and clean close |
| TCP-02 | IPv6 connect, request, response, close | exact payload and clean close |
| TCP-03 | local half-close followed by remote data | data delivered, then bounded close |
| TCP-04 | remote half-close followed by local data | documented behavior without hang |
| TCP-05 | local reset | connector cancelled and state released |
| TCP-06 | remote reset | reset reflected to packet peer and state released |
| TCP-07 | remote open refusal | bounded connection failure, no false established state |
| TCP-08 | connect timeout | fails within configured window and releases permit |
| TCP-09 | idle timeout | flow closes within configured window |
| TCP-10 | retransmission after one dropped segment | payload succeeds or candidate is rejected |
| TCP-11 | reordered segments | exact payload with bounded reassembly state |
| TCP-12 | duplicate segments and duplicate acknowledgements | no duplicated application bytes |
| TCP-13 | zero-window then reopen | sender pauses and resumes without unbounded buffering |
| TCP-14 | slow Maverick connector reader | backpressure reaches packet peer |
| TCP-15 | slow packet peer reader | connector writes remain bounded |
| TCP-16 | shutdown during connect | task, permit, and engine state released |
| TCP-17 | shutdown during bidirectional transfer | bounded drain, then deterministic close |
| TCP-18 | repeated reuse of the same address tuple after close | no stale-state collision |

### DNS

| id | case | required result |
| --- | --- | --- |
| DNS-01 | valid A-style query payload | one bounded Maverick DNS exchange |
| DNS-02 | valid AAAA-style query payload | one bounded Maverick DNS exchange |
| DNS-03 | connector returns a valid response | exact response delivered once |
| DNS-04 | connector timeout | bounded failure with state cleanup |
| DNS-05 | malformed or oversized query | rejected before unbounded allocation |
| DNS-06 | repeated identical queries | each request follows documented cache policy |
| DNS-07 | concurrent queries at limit | all complete or receive explicit admission failure |
| DNS-08 | one query above limit | rejected without starving admitted work |
| DNS-09 | cancellation during exchange | pending connector work cancelled |
| DNS-10 | diagnostics snapshot | counts only; no queried name or payload |

The packet engine does not choose the system resolver or apply resolver
settings. The product layer supplies interception and resolver policy.

### UDP

| id | case | required result |
| --- | --- | --- |
| UDP-01 | one IPv4 request and response | exact datagrams and endpoint mapping |
| UDP-02 | one IPv6 request and response | exact datagrams and endpoint mapping |
| UDP-03 | multiple datagrams in one association | ordering policy documented and no cross-flow mix |
| UDP-04 | two peers with the same destination | independent association state |
| UDP-05 | response from unexpected endpoint | deterministic reject or explicit mapping policy |
| UDP-06 | datagram at configured maximum | accepted without truncation |
| UDP-07 | datagram over configured maximum | bounded reject |
| UDP-08 | connector response timeout | association remains or closes per policy |
| UDP-09 | idle association expiry | all state and queue entries released |
| UDP-10 | association limit reached | new association rejected without affecting existing ones |
| UDP-11 | queue saturation | drop/backpressure policy is explicit and counted |
| UDP-12 | shutdown with active associations | all associations close within bound |

### Concurrency And Resource Bounds

Run each supported TCP, DNS, and UDP path at one, ten, one hundred, and the
configured maximum concurrent operations.

| id | case | required result |
| --- | --- | --- |
| RES-01 | one operation | baseline counts and latency recorded |
| RES-02 | ten concurrent operations | zero cross-flow corruption |
| RES-03 | one hundred concurrent operations | within configured task, queue, and memory bounds |
| RES-04 | exactly at admission limit | admitted work completes |
| RES-05 | one operation above limit | explicit immediate rejection |
| RES-06 | repeated open/close cycles | no monotonic flow, task, or buffer growth |
| RES-07 | stalled connector at queue limit | memory remains bounded |
| RES-08 | malformed flood mixed with valid work | valid admitted work is not permanently starved |
| RES-09 | diagnostics polling during load | bounded cost and stable cardinality |
| RES-10 | quiescence after load | active counts return to zero |

Resource checks record resident memory, allocated engine state when exposed,
task count, active flows, queue depth, bytes buffered, and shutdown latency.
Absolute performance thresholds are set only after the same harness produces a
repeatable baseline on one pinned candidate and toolchain.

### Startup, Shutdown, And Recovery

| id | case | required result |
| --- | --- | --- |
| LIFE-01 | valid startup | ready only after packet I/O and connector exist |
| LIFE-02 | invalid MTU or zero limits | startup rejected before accepting packets |
| LIFE-03 | packet I/O fails during startup | all run-owned state released |
| LIFE-04 | connector fails during startup | packet I/O closed and no ready state emitted |
| LIFE-05 | packet read failure at runtime | coarse failure and bounded shutdown |
| LIFE-06 | packet write failure at runtime | coarse failure and bounded shutdown |
| LIFE-07 | engine task panic or unexpected exit | SDK sees failed state and cleanup requirement |
| LIFE-08 | first shutdown | new flows stop, active work drains within bound |
| LIFE-09 | repeated shutdown | idempotent result |
| LIFE-10 | restart after clean shutdown | fresh state, no stale tuple or queue entries |
| LIFE-11 | forced cancellation | all child tasks terminate within bound |
| LIFE-12 | diagnostics after stop | zero active state and no secret data |

### Logging And Privacy

| id | case | required result |
| --- | --- | --- |
| LOG-01 | normal TCP/DNS/UDP success | no payload, destination, query name, or credential |
| LOG-02 | parser error | bounded coarse reason, no raw packet dump |
| LOG-03 | remote connect failure | no private endpoint or auth material |
| LOG-04 | debug disabled | no packet capture produced |
| LOG-05 | explicit private debug capture | stored outside public artifacts with provenance |
| LOG-06 | repeated error | rate-limited or aggregated output |

## Candidate-Specific Adapter Checks

Every candidate must additionally prove:

- the injected device path works without candidate-managed system setup;
- route/DNS/setup commands cannot be reached through the adapter configuration;
- candidate-specific background tasks are included in shutdown accounting;
- unsafe, FFI, subprocess, and foreign-runtime boundaries are listed;
- default logging is intercepted or configured to Maverick's privacy policy;
- engine version and source revision appear in private test provenance;
- replacing the candidate does not change public config or Maverick wire
  behavior.

## Result Records

The Phase 0 machine-readable candidate records use this shape:

```json
{
  "schema": 1,
  "tested_commit": "SOURCE_COMMIT",
  "candidate": "CANDIDATE_NAME",
  "candidate_version": "PINNED_VERSION",
  "candidate_revision": "PINNED_REVISION",
  "toolchain": "PINNED_TOOLCHAIN",
  "mode": "in_memory",
  "seed": 0,
  "started_utc": "UTC_TIMESTAMP",
  "finished_utc": "UTC_TIMESTAMP",
  "cases_total": 0,
  "cases_passed": 0,
  "cases_failed": 0,
  "resource_peak": {
    "active_flows": 0,
    "tasks": 0,
    "queued_packets": 0,
    "buffered_bytes": 0
  },
  "shutdown_elapsed_ms": 0,
  "known_gaps": []
}
```

Private diagnostic attachments may contain deeper timing and resource traces.
Public summaries contain only redacted aggregate results and hashes.

## Acceptance Gates

The completed Phase 0 candidate gate required:

- every supported correctness case passes with zero unexplained failures;
- unsupported cases are explicit product blockers, not silent skips;
- concurrency above the configured limit is rejected deterministically;
- tasks, flows, queues, and buffers return to baseline after quiescence;
- shutdown and forced cancellation complete within their configured bounds;
- ordinary logs pass secret, destination, path, and infrastructure hygiene;
- the adapter never executes system-network mutation;
- existing Maverick SOCKS5, HTTP CONNECT, DNS, UDP, H2-pool, and shutdown tests
  still pass after the later implementation begins.

No synthetic result by itself proves real-device readiness. The later approved
Phase 2 IPv4 matrix supplied narrow disposable-system evidence for route, DNS,
interface, control-plane preservation, failure recovery, and residue behavior;
it did not turn this synthetic matrix into a product-readiness result.

Phase 1 complete means its narrower exit gate passed: dual-stack TCP, DNS,
bounded UDP, close/reset/backpressure/cancellation, bounded resource snapshots,
real Maverick loopback reuse, and the unchanged default workspace harness. It
does not mean every row above passed. Phase 2 was separately approved and
accepted for its recorded IPv4 scope. IPv6 is unscheduled, product readiness
remains open, and any new privileged run requires fresh approval.
