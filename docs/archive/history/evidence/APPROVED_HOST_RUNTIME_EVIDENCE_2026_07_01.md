# Approved-Host Runtime Evidence 2026-07-01

Status: pre-stable runtime evidence. This is not a production-readiness claim.

## Scope

This run exercised the current stable-scope TCP relay path. The original
approved-host names, public IP address, and certificate paths are intentionally
redacted from the public source tree; they are retained only in local operator
notes.

- Maverick server on an approved remote server VM.
- Maverick client loop on an approved remote client VM.
- TLS 1.3 plus HTTP/2 carrier.
- SOCKS5 TCP echo flow through Maverick.
- Public server port `24443/tcp`.
- Loop interval: 300 seconds.
- Total duration: 3600 seconds.

It did not exercise H3/QUIC, native server-side ECH, Cloudflare-fronted
WebSocket, TUN apply, GUI/App runtime behavior, or production deployment
rollout.

## Result

- Run id: `onehour-20260701T043233Z`
- Started: 2026-07-01T04:32:55Z
- Finished: 2026-07-01T05:32:55Z
- Duration: 3600 seconds
- Interval: 300 seconds
- Iterations: 12
- Passed: 12
- Failed: 0

The client-side summary on the approved client VM reported:

```text
iterations: 12
passed: 12
failed: 0
```

The server log on the approved server VM showed one successful authenticated
Maverick session for each client iteration. The echo target log showed 12 echo
connections, each with a 26-byte payload. No failed iteration was recorded.

The temporary server and echo processes were manually stopped after evidence
collection, and `24443/tcp` plus `24444/tcp` were no longer listening.

## Detached Harness

This run used:

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=REPLACE_WITH_APPROVED_SERVER_IP \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME=api.example.com \
MAVERICK_PUBLIC_SMOKE_REMOTE_CERT=/path/to/fullchain.pem \
MAVERICK_PUBLIC_SMOKE_REMOTE_KEY=/path/to/privkey.pem \
MAVERICK_PUBLIC_SMOKE_REMOTE_REPO=maverick-remote-lab \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
MAVERICK_PUBLIC_SMOKE_CLIENT_REPO=maverick-remote-lab \
MAVERICK_PUBLIC_SMOKE_PORT=24443 \
MAVERICK_PUBLIC_SMOKE_TARGET_PORT=24444 \
MAVERICK_LONGHAUL_DURATION_SECS=3600 \
MAVERICK_LONGHAUL_INTERVAL_SECS=300 \
MAVERICK_DETACHED_RUN_ID=onehour-20260701T043233Z \
./scripts/approved-vm-detached-tcp-longhaul.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST
```

The detached harness starts the server process on the approved server VM and
the client loop on the approved client VM. The local developer machine only
starts and polls the run; local Codex or macOS restarts do not stop the remote
test once the remote orchestrator has started.

## Interpretation

This evidence is enough to say the stable-scope TCP/H2 runtime has passed a
one-hour approved-host smoke under the tested conditions. It is appropriate for
public alpha and pre-stable readiness tracking.

It is not enough for a broad stable or production claim. Before a stable tag,
the project should still run a longer approved-host test, preferably at least
24 hours, and add failure-injection coverage for restart, reconnect, packet
loss, upstream timeout, and rollback behavior.
