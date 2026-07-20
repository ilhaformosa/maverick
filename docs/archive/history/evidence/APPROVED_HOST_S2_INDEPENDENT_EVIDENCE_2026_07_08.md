# S2 Independent Evidence - 2026-07-08

Status: evidence report for the `v0.1.0-beta.2` S2 gate.
This is engineering evidence only. It is not a production-readiness,
formal security-audit, anonymity, or censorship-resistance claim.

Private hostnames, IP addresses, SSH aliases, usernames, provider
resource names, certificate paths, generated secrets, and raw logs are
intentionally omitted from this public report.

## Scope

- stable target: `maverick-tls-h2-cli-v1`
- tested commits/builds: see per-run provenance below
- server role: approved remote server VM
- client role: second approved remote client VM
- local workstation role: SSH orchestration and evidence collection only
- transport: TLS 1.3 + HTTP/2
- relay path: SOCKS5 TCP echo through Maverick

The S2 runs did not change the developer workstation's system proxy, DNS,
route table, firewall, VPN, or other network-service settings.

## Run Provenance

- longhaul: `6bf0d1b`
- netem: `db36251`
- failure-injection: `b14ee2e`

## Long-Haul Result

- run_id: `reverse443-24h-20260706T092158Z`
- tested_commit: `6bf0d1b`
- started_utc: `2026-07-06T09:27:14Z`
- finished_utc: `2026-07-07T09:27:14Z`
- duration_secs: `86400`
- interval_secs: `300`
- iterations: `288`
- passed: `288`
- failed: `0`

## Network Impairment Result

- run_id: `netem-8h-reverse443-20260707T101110Z`
- tested_commit: `db36251`
- started_utc: `2026-07-07T10:17:17Z`
- finished_utc: `2026-07-07T18:17:18Z`
- scenario_profile: `8h-v2`
- duration_secs: `28800`
- interval_secs: `300`
- iterations: `96`
- passed: `96`
- failed: `0`
- default_route_unchanged: `true`
- global_dns_unchanged: `true`
- remote_residue: `absent`

## Failure-Injection Result

- run_id: `failure-reverse443-v2-20260707T183119Z`
- finished_utc: `2026-07-07T18:36:58Z`
- server_commit: `b14ee2e`
- client_commit: `b14ee2e`
- server_binary_version: `maverick 0.1.0-beta.1`
- client_binary_version: `maverick 0.1.0-beta.1`
- checks: `15`
- pass_results: `11`
- controlled_connect_failures: `2`
- controlled_stall_results: `1`
- controlled_fallback_failures: `1`

## Event Log Counts

| Run | Lines | PASS/result=pass | FAIL/probe_failed | Controlled connect failures | Controlled stall results | Controlled fallback failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| longhaul | 288 | 288 | 0 | 0 | 0 | 0 |
| netem | 132 | 96 | 0 | 0 | 0 | 0 |
| failure-injection | 35 | 11 | 0 | 2 | 1 | 1 |

## Interpretation

This report can support `v0.1.0-beta.2` only after the reviewed counts
show zero unexpected failures for the claimed profiles and the remote
evidence confirms the client host is distinct from the developer machine.

It does not prove production readiness, anonymity, censorship resistance,
native server-side ECH, GUI/App behavior, H3/QUIC stability, or behavior
outside the recorded latency/loss profiles.

## Reproduction Shape

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=REPLACE_WITH_APPROVED_SERVER_ADDRESS \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME=REPLACE_WITH_APPROVED_SERVER_NAME \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT=1 \
MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 \
./scripts/s2-evidence-preflight.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST

MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
MAVERICK_LONGHAUL_DURATION_SECS=86400 \
./scripts/approved-vm-detached-tcp-longhaul.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST

MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 \
MAVERICK_NETEM_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
./scripts/approved-vm-netem-impairment-smoke.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST

MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
./scripts/approved-vm-failure-injection-smoke.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST
```
