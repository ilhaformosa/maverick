# Approved-Host Post-v1 M6 Evidence - 2026-07-11

Status: accepted engineering evidence for the post-v1 M6 layered two-host
gate. This is not a production-readiness, formal security-audit, anonymity,
censorship-resistance, or browser-equivalence claim.

Private hostnames, addresses, SSH aliases, usernames, provider resource names,
ports, certificate paths, generated credentials, and raw infrastructure logs
are intentionally omitted. Detailed source logs and analyses remain in ignored
private evidence storage.

## Scope And Provenance

- tested source commit: `b3a1793`
- binary version on both roles in every accepted run: `maverick 1.0.0`
- transport: direct TLS 1.3 plus HTTP/2
- relay path: SOCKS5 TCP echo through Maverick
- topology: distinct approved client and server VMs
- developer workstation role: SSH orchestration and evidence collection only

The clean 24-hour run used matching client/server binary SHA-256
`be59424387adae97f55ea3507b63d0c617b1e9c699251991b6806ab1c0688a34`.
The later impairment and failure runs used matching client/server binary
SHA-256
`658851652e28ec5679959f899f6e63fabfa42d97d083629bd0336cc5014876a7`.
Both builds came from the same tested source commit. Their byte hashes differ
because the project does not yet pin a fully reproducible Linux build
toolchain. Each evidence layer records its own exact role hashes; no report
treats the builds as byte-identical.

The repository changes after the tested commit and before this report were
documentation only. Runtime crates, Cargo metadata, checked-in configuration,
test runners, and CI workflows used for the evidence did not change.

## Clean 24-Hour Stability

- configured duration: 86,400 seconds
- probe interval: 300 seconds
- iterations: 288
- passed: 288
- failed: 0
- latency minimum/mean/P50/P95/P99/maximum:
  59/88.44/81/126/137/187 ms
- probe-start gaps: 300-301 seconds, with none above 301 seconds
- detailed client logs: 288
- detailed probe logs: 288
- failure logs: 0

Client resource evidence contains 576 complete lifecycle samples and a real
Maverick process row in every sample. Server evidence contains 1,450 complete
continuous samples and a real Maverick process row in every sample. Server
sampling gaps were 60-61 seconds. Client gaps follow the documented probe-start
and probe-finish sampling model; every gap was reconciled with the probe
schedule.

## Eight-Hour Network Impairment

- configured duration: 28,800 seconds
- probe interval: 300 seconds
- scenarios: 8
- iterations: 96
- passed: 96
- failed: 0

| Scenario | Samples | Mean | P95 | Maximum | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| baseline | 6 | 119.17 ms | 208 ms | 208 ms | 6/6 pass |
| 50 ms latency, 10 ms jitter | 12 | 817.83 ms | 927 ms | 927 ms | 12/12 pass |
| 100 ms latency, 20 ms jitter | 12 | 1,522.83 ms | 1,605 ms | 1,605 ms | 12/12 pass |
| 0.5% loss | 12 | 143.00 ms | 581 ms | 581 ms | 12/12 pass |
| 1% loss | 12 | 153.33 ms | 367 ms | 367 ms | 12/12 pass |
| 100/20 ms plus 1% loss | 18 | 1,558.06 ms | 2,772 ms | 2,772 ms | 18/18 pass |
| 150/50 ms plus 2% loss | 12 | 2,178.50 ms | 2,376 ms | 2,376 ms | 12/12 pass |
| recovery baseline | 12 | 104.25 ms | 145 ms | 145 ms | 12/12 pass |

The impairment was limited to a temporary namespace/veth pair on the approved
client. Resource evidence recorded the intended bidirectional qdisc in every
impaired probe window and no qdisc in baseline, recovery, or the final
impairment-removed sample. Default route and global DNS hashes were unchanged.
The namespace, veth pair, qdiscs, matching iptables rules, and temporary
`ip_forward` change were removed or restored before acceptance.

Client namespace/veth evidence contains 106 complete samples covering the full
28,802-second run window. Server evidence contains 483 complete samples with
60-61 second gaps and a real Maverick process row in every sample.

## Failure Injection And Recovery

The independent process-level run completed 15/15 expected checks:

- 11 normal baseline or recovery results passed;
- 2 deliberate service-down windows returned controlled SOCKS connection
  failures;
- 1 deliberate upstream stall closed with zero response bytes;
- 1 deliberate fallback-origin outage returned generic HTTP 502;
- authenticated tunnel traffic continued while the fallback origin was down;
- server, client, echo target, fallback origin, and stalled upstream all showed
  explicit bounded recovery.

Client and server each retained six complete resource checkpoints covering
baseline and every recovery stage. Every checkpoint contains a real Maverick
process row. Scenario logs contain no unexpected error, warning, or panic.

## Cleanup And Audit

Collection occurred before final directory cleanup. Independent post-cleanup
checks confirmed:

- every run-owned process and temporary directory was absent;
- all selected test listeners were absent;
- all temporary runtime firewall rules were absent;
- generated configuration, certificates, private keys, and credentials were
  absent;
- netem namespace, veth, qdisc, iptables, and forwarding state had no residue;
- unrelated services and permanent host networking were not changed.

`scripts/s2-evidence-audit.py --require-accepted` accepted all three final
collections. Their SHA-256 manifests verified 883 clean long-haul files, 307
impairment files, and 25 failure-injection files with zero mismatches. Secret
pattern scans reported zero findings.

## Interpretation And Limits

This evidence closes the post-v1 M6 gate for the tested direct TLS/H2 path,
source commit, binaries, topology, durations, and impairment profiles. It also
supports finalizing the documented M7 handshake/fallback decision because no
result changed that decision's assumptions.

It does not prove behavior on an actual restricted network, additional
regions, H3/QUIC, CDN-fronted WebSocket, product TUN, GUI applications,
production rollout, anonymity, censorship resistance, or perfect traffic
indistinguishability. Restricted-network evidence remains optional until a
real path is available and separately approved.
