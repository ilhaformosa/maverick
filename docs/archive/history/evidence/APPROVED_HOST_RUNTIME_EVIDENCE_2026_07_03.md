# Approved-Host Runtime Evidence 2026-07-03

Status: pre-stable runtime evidence. This is not a production-readiness,
security-audit, stable-release, anonymity, or censorship-resistance claim.

## Scope

This run exercised the current stable-scope TCP relay path on explicitly
approved remote hosts. The original approved-host names, public IP address,
SSH labels, usernames, certificate paths, generated secrets, and raw
credential material are intentionally omitted from the public source tree.

- Maverick server on an approved remote server VM.
- Maverick client loop on an approved remote client VM.
- TLS 1.3 plus HTTP/2 carrier.
- SOCKS5 TCP echo flow through Maverick.
- Public server port `24443/tcp`.
- Loopback echo target port `24444/tcp` on the approved server VM.
- Loop interval: 300 seconds.
- Total duration: 86400 seconds.
- Per-run generated test certificate trusted only by the temporary client
  configuration.

It did not exercise H3/QUIC, native server-side ECH, Cloudflare-fronted
WebSocket, TUN apply, GUI/App runtime behavior, restart recovery, failure
injection, packet loss, latency impairment, production rollout, or rollback.

## Version And Provenance

- Runtime binary version: `maverick 0.1.0-alpha.1`.
- The remote source directories used for this run did not retain `.git`
  metadata, so this evidence does not claim exact commit provenance.
- The local source diff after `v0.1.0-alpha.1` and before this evidence note
  contained release-hygiene docs and scripts only, not runtime crate changes.

This should be treated as 24-hour approved-host baseline evidence for the
`v0.1.0-alpha.1` stable-scope runtime path, not as evidence that an alpha.2
tagged artifact has been exercised for 24 hours.

## Result

- Run id: `longhaul-24h-20260702T070654Z`
- First passing iteration: 2026-07-02T07:07:24Z
- Last passing iteration: 2026-07-03T07:03:04Z
- Finished: 2026-07-03T07:07:24Z
- Duration: 86400 seconds
- Interval: 300 seconds
- Iterations: 288
- Passed: 288
- Failed: 0

The client-side summary on the approved client VM reported:

```text
iterations: 288
passed: 288
failed: 0
```

The follow-up audit verified:

```text
client_passes=288
client_failures=0
client_suspicious=0
auth_sessions=288
echo_peers=288
server_log_errors=0
```

The client event log contained a continuous `PASS 1` through `PASS 288`
sequence. The server log showed one successful authenticated Maverick session
for each client iteration. The echo target log showed 288 echo connections,
each with a 26-byte payload. No failed iteration, panic, permission error,
connection refusal, or timeout was recorded in the reviewed logs.

## Cleanup

After evidence collection:

- the client orchestrator had exited;
- the temporary Maverick server and echo target processes were stopped;
- `24443/tcp` and `24444/tcp` were no longer listening on the approved server
  VM;
- generated test certificate private keys, CA private keys, temporary client
  config, and temporary server config were removed from the approved hosts;
- redacted summary and operational logs were left on the approved hosts for
  short-term operator review.

## Detached Harness

This run used the detached approved-host harness shape:

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=REPLACE_WITH_APPROVED_SERVER_IP \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME=api.example.com \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
MAVERICK_PUBLIC_SMOKE_REMOTE_REPO=maverick-longhaul-current \
MAVERICK_PUBLIC_SMOKE_CLIENT_REPO=maverick-longhaul-current \
MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT=1 \
MAVERICK_PUBLIC_SMOKE_PORT=24443 \
MAVERICK_PUBLIC_SMOKE_TARGET_PORT=24444 \
MAVERICK_LONGHAUL_DURATION_SECS=86400 \
MAVERICK_LONGHAUL_INTERVAL_SECS=300 \
MAVERICK_DETACHED_RUN_ID=longhaul-24h-20260702T070654Z \
./scripts/approved-vm-detached-tcp-longhaul.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST
```

The detached harness starts the server process on the approved server VM and
the client loop on the approved client VM. The local developer machine only
starts and later audits the run; local Codex or macOS restarts do not stop the
remote test after the remote orchestrator has started.

## Interpretation

This evidence is enough to say the stable-scope TCP/H2 runtime path has passed
a 24-hour approved-host baseline under the tested conditions. It is appropriate
for public alpha, pre-stable readiness tracking, and a narrow stable-candidate
evidence pack.

It is not enough for production readiness. The project still needs controlled
failure-injection evidence for server restart, client reconnect, upstream
target failure, upstream stall or timeout, and any packet-loss or latency
impairment that a future release chooses to claim.
