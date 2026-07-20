# Approved-Host Netem Impairment Evidence - 2026-07-04

Status: diagnostic rerun completed and accepted as approved-host network
impairment evidence for the tested TCP/H2 path.

This document records remote approved-host packet-loss and latency impairment
runs for the TCP/H2 runtime path. It is engineering evidence only. It is not a
production-readiness claim, stable-release claim, anonymity claim,
censorship-resistance claim, or audit result.

Private hostnames, addresses, SSH aliases, interface names, and provider
resource names are intentionally omitted.

## Scope

- server role: approved remote server host
- client role: approved remote client host
- transport: TLS 1.3 + HTTP/2
- relay path: SOCKS5 TCP echo through Maverick
- impairment scope: temporary network namespace and veth pair on the approved
  client host
- server port: non-443 temporary test port
- local developer workstation role: start and later log review only

The runs did not change the developer workstation's system proxy, DNS, route
table, firewall, VPN, or network-service settings.

## Run A Summary: Exploratory 11h Profile

- tested source commit: `61a3b88`
- run id: `netem-20260703T150138Z`
- started UTC: `2026-07-03T15:16:43Z`
- finished UTC: `2026-07-04T02:16:43Z`
- planned duration: 39600 seconds
- interval: 300 seconds
- iterations: 128
- passed: 111
- failed: 17
- cleanup: completed
- namespace/veth residue: absent
- iptables NAT residue: absent
- default route unchanged: true
- global DNS unchanged: true

### Scenario Results

| Scenario | Duration | Netem profile | PASS | FAIL |
| --- | ---: | --- | ---: | ---: |
| baseline | 1800s | none | 6 | 0 |
| latency_50ms_jitter10 | 5400s | 50ms delay, 10ms jitter | 14 | 3 |
| latency_100ms_jitter20 | 5400s | 100ms delay, 20ms jitter | 16 | 2 |
| loss_0_5pct | 5400s | 0.5% packet loss | 15 | 2 |
| loss_1pct | 5400s | 1% packet loss | 13 | 4 |
| combined_100ms_jitter20_loss1 | 7200s | 100ms delay, 20ms jitter, 1% loss | 20 | 3 |
| rough_150ms_jitter50_loss2 | 5400s | 150ms delay, 50ms jitter, 2% loss | 16 | 2 |
| recovery_baseline | 3600s | none | 11 | 1 |

### Interpretation

The run is useful because it proved that the remote detached netem harness can
run for 11 hours, exercise real inter-host Maverick TCP/H2 traffic, and remove
the temporary namespace, veth, qdisc, and NAT state after completion.

The run is not accepted as production-readiness evidence because it reported
17 failed iterations, including one failure in the final no-impairment recovery
baseline. Follow-up review found a harness weakness: the first runner version
tracked the short-lived `sudo ip netns exec` wrapper PID and did not capture
probe failure reasons. Some failed iterations later showed a client listening
log, which makes the failure classification ambiguous.

The harness has been updated to avoid treating the wrapper PID as the client
liveness signal and to record explicit probe failure reasons for future runs.

## Run B Summary: Diagnostic 8h-v2 Profile

- tested source commit: `19e4bba`
- run id: `netem8h-20260704T053301Z`
- started UTC: `2026-07-04T05:46:03Z`
- finished UTC: `2026-07-04T13:46:03Z`
- scenario profile: `8h-v2`
- planned duration: 28800 seconds
- interval: 300 seconds
- iterations: 96
- passed: 96
- failed: 0
- cleanup: completed
- namespace/veth residue: absent
- iptables NAT residue: absent
- client runner residue: absent
- temporary server process residue after review: absent
- temporary test ports after review: not listening
- default route unchanged: true
- global DNS unchanged: true
- probe logs: 96/96 contained staged success records
- probe failure markers: 0

### Scenario Results

| Scenario | Duration | Netem profile | PASS | FAIL |
| --- | ---: | --- | ---: | ---: |
| baseline | 1800s | none | 6 | 0 |
| latency_50ms_jitter10 | 3600s | 50ms delay, 10ms jitter | 12 | 0 |
| latency_100ms_jitter20 | 3600s | 100ms delay, 20ms jitter | 12 | 0 |
| loss_0_5pct | 3600s | 0.5% packet loss | 12 | 0 |
| loss_1pct | 3600s | 1% packet loss | 12 | 0 |
| combined_100ms_jitter20_loss1 | 5400s | 100ms delay, 20ms jitter, 1% loss | 18 | 0 |
| rough_150ms_jitter50_loss2 | 3600s | 150ms delay, 50ms jitter, 2% loss | 12 | 0 |
| recovery_baseline | 3600s | none | 12 | 0 |

### Probe Diagnostics

The diagnostic rerun produced one probe log per iteration. Each successful
probe recorded:

- SOCKS connection to the local client listener succeeded;
- SOCKS method negotiation succeeded;
- SOCKS CONNECT to the remote echo target succeeded;
- echo payload roundtrip succeeded.

No probe failure logs were produced because no iterations failed. Both the
initial baseline and recovery baseline completed with zero failures.

### Interpretation

Run B supersedes Run A for the specific question of whether the current
approved-host netem harness can collect usable packet-loss and latency evidence
for the TCP/H2 path. It passed all initial baseline, impaired-profile, and
recovery-baseline iterations, while also proving cleanup of the temporary
namespace, veth, qdisc, NAT, client runner, server process, and test-port state.

This is accepted as approved-host network-impairment evidence for the tested
runtime path and tested parameter set. It still does not claim general
production readiness, anonymity, censorship resistance, native server-side ECH,
multi-region resilience, long-term operator rollout safety, or behavior outside
the recorded latency/loss profiles.

## Next Action

Keep Run B as the current approved-host network-impairment evidence for the
tested TCP/H2 scope. Before broadening any production-scope claim, add separate
evidence for longer durations, more network paths, operator rollout/rollback,
and any claimed platform or transport beyond this exact test scope.
