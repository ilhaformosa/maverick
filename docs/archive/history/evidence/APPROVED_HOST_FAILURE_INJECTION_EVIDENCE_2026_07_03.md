# Approved-Host Failure Injection Evidence 2026-07-03

Status: pre-stable process-level failure evidence. This is not a
production-readiness, security-audit, stable-release, anonymity, or
censorship-resistance claim.

## Scope

This run exercised process-level failure and recovery behavior for the current
stable-scope TCP relay path on explicitly approved remote hosts. The original
approved-host names, public IP address, SSH labels, usernames, certificate
paths, generated secrets, and raw credential material are intentionally omitted
from the public source tree.

Covered scenarios:

- Maverick server restart while the client process remained configured.
- Client process restart and reconnect.
- Upstream loopback echo target stop and recovery.
- Upstream loopback target stall or timeout and recovery.

It did not exercise host-level packet loss, latency impairment, traffic-control
rules, DNS mutation, route mutation, firewall mutation, VPN behavior, TUN apply,
GUI/App runtime behavior, production rollout, or rollback.

## Version And Provenance

- Harness commit: `d2ae6bc`.
- Server checkout commit: `d2ae6bc`.
- Client checkout commit: `d2ae6bc`.
- Server runtime binary version: `maverick 0.1.0-alpha.1`.
- Client runtime binary version: `maverick 0.1.0-alpha.1`.
- The run used a per-run generated test CA and server certificate trusted only
  by the temporary client configuration.

## Result

- Run id: `failure-process-20260703T073000Z`
- Started: 2026-07-03T07:31:46Z
- Finished: 2026-07-03T07:34:10Z
- Public server port: `24443/tcp`
- Loopback target port: `24444/tcp`
- Checks: 11
- Pass results: 8
- Controlled connect failures: 2
- Controlled stall results: 1

The approved-client event summary reported:

```text
CHECK scenario=server_restart phase=baseline expected=pass result=pass
CHECK scenario=server_restart phase=server_down expected=connect_fail result=connect_fail socks_code=5
CHECK scenario=server_restart phase=recovered expected=pass result=pass
CHECK scenario=client_restart phase=before_restart expected=pass result=pass
CHECK scenario=client_restart phase=after_restart_one expected=pass result=pass
CHECK scenario=client_restart phase=after_restart_two expected=pass result=pass
CHECK scenario=upstream_echo_failure phase=baseline expected=pass result=pass
CHECK scenario=upstream_echo_failure phase=echo_down expected=connect_fail result=connect_fail socks_code=5
CHECK scenario=upstream_echo_failure phase=recovered expected=pass result=pass
CHECK scenario=upstream_stall_timeout phase=stalled expected=stall result=stall_closed bytes=0
CHECK scenario=upstream_stall_timeout phase=recovered expected=pass result=pass
```

The follow-up audit verified:

```text
auth_sessions=9
echo_peers=8
stall_peers=1
post_cleanup_ports=free
```

No generated Maverick secret, private key marker, panic, missing-file error,
permission error, or segmentation-fault marker was found in the retained
redacted server evidence directory. The retained server log was restarted with
the server process, so `auth_sessions=9` is the count in the retained
post-restart server log rather than a total across every process generation.
The client event log is the authoritative scenario result list.

## Cleanup

After evidence collection:

- the temporary client process was stopped;
- the temporary Maverick server, echo target, and stall target processes were
  stopped;
- `24443/tcp` and `24444/tcp` were no longer listening on the approved server
  VM;
- generated test certificate private keys, CA private keys, temporary client
  config, and temporary server config were removed from the approved hosts;
- the temporary Git bundle used to create exact-commit remote checkouts was
  removed;
- redacted summary and operational logs were left on the approved hosts for
  short-term operator review.

## Harness

This run used:

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=REPLACE_WITH_APPROVED_SERVER_IP \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME=REPLACE_WITH_APPROVED_SERVER_NAME \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
MAVERICK_PUBLIC_SMOKE_REMOTE_REPO=maverick-failure-injection-current \
MAVERICK_PUBLIC_SMOKE_CLIENT_REPO=maverick-failure-injection-current \
MAVERICK_FAILURE_RUN_ID=failure-process-20260703T073000Z \
MAVERICK_FAILURE_TIMEOUT_SECS=900 \
./scripts/approved-vm-failure-injection-smoke.sh REPLACE_WITH_APPROVED_SERVER_SSH_HOST
```

The harness starts only temporary test processes and uses process control to
inject failures. It does not run `tc netem`, change host routes, change DNS,
change firewall state, configure VPNs, modify network interfaces, or mutate a
developer workstation.

## Interpretation

This evidence is enough to say the stable-scope TCP/H2 runtime path has passed
the minimal process-level failure-injection pack for server restart, client
restart, upstream target failure, and upstream stall or timeout.

It is not enough for production readiness. Packet-loss and latency impairment
evidence should remain a production-readiness input unless an approved isolated
test host is available. Operator rollout, rollback, observability, and external
security review remain separate gates.
