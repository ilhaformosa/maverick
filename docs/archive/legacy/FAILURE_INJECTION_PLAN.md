# Failure Injection Evidence Plan

Status: execution plan plus completed process-level evidence. This is not a
production-readiness claim, stable-release claim, or audit result.

`docs/PLAN_POST_V1.md` owns the current M6 gate. This file supplies the focused
failure scenarios and evidence format, not a separate execution order.

Maverick needs failure-injection evidence before stronger stable or production
claims. This work should run separately from long-haul baseline tests so the
project can distinguish ordinary runtime stability from controlled failure and
recovery behavior.

## Safety Rules

- Do not mutate a developer workstation's system proxy, DNS, route table,
  firewall, VPN, or other network-service settings.
- Use loopback tests for local coverage and explicitly approved VMs for
  host-level failure injection.
- Prefer process-level failures before network-level failures.
- Keep generated credentials, real hostnames, IP addresses, certificate paths,
  cloud resource names, and local private paths out of committed evidence.
- Record cleanup and residue checks for every approved-host run.
- When an approved server blocks the high test port, use only the runner's
  explicit temporary-firewall gate. It refuses existing rules, creates an
  auto-expiring runtime rule, records the change, and removes it after the
  synchronous failure-injection run.

## Evidence Classes

### Server Restart And Client Recovery

Purpose: prove clients recover after the Maverick server process restarts.

Suggested run:

- start server, echo target, and remote client loop on approved hosts;
- pass at least two baseline iterations;
- stop the server process;
- restart the server with the same config and credential;
- continue the client loop;
- record how many iterations failed during the restart window and whether later
  iterations recovered.

Expected evidence:

- one or more controlled failures during the restart window are acceptable;
- later iterations must pass without manual client reconfiguration;
- no stale server process remains after cleanup;
- server port and echo port cleanup is verified.

### Client Restart And Reconnect

Purpose: prove local client process restart does not require server-side manual
repair.

Suggested run:

- start approved-host server and echo target;
- run a remote client iteration successfully;
- stop the client process;
- start a fresh client process with the same config;
- repeat several times.

Expected evidence:

- each fresh client process can establish a new authenticated tunnel;
- server metrics/logs show separate authenticated sessions;
- generated client configs and logs remain redacted.

### Upstream Echo Failure And Recovery

Purpose: prove relay behavior is bounded when the target service disappears and
recovers.

Suggested run:

- start Maverick server and client loop;
- pass baseline iterations while the echo target is running;
- stop the echo target only;
- confirm client iterations fail as controlled connect failures;
- restart the echo target;
- confirm later iterations pass.

Expected evidence:

- failures are limited to target-connect behavior;
- Maverick server stays alive;
- no protocol details or secrets are exposed in logs;
- recovery does not require changing credentials or restarting the client.

### Upstream Timeout Or Stall

Purpose: prove idle and connect timeout behavior is bounded.

Suggested run:

- replace the echo target with a target that accepts a connection and then
  stalls;
- run one or more client flows;
- confirm configured idle/connect timeouts end the flow;
- restore the normal echo target and confirm recovery.

Expected evidence:

- client flow fails within the configured timeout window;
- server process remains healthy;
- later normal echo flows pass.

### Packet Loss And Latency

Purpose: gather network impairment evidence without touching a developer
workstation.

Preferred approach:

- run only on explicitly approved Linux VMs;
- use a namespace or veth-scoped impairment when possible;
- if host-level `tc netem` is required, use a dedicated throwaway VM and record
  operator approval, exact interface, baseline, rollback command, and residue
  checks before starting.

Expected evidence:

- latency/loss parameters are recorded;
- baseline route and DNS state are checked before and after;
- impairment is removed and verified after the run;
- results are described as engineering evidence, not censorship-resistance or
  anonymity proof.

### Fallback Target Failure

Purpose: prove ordinary web fallback behavior remains controlled when the
fallback origin is unavailable.

Suggested run:

- configure reverse-proxy fallback to an approved-host test origin;
- confirm ordinary fallback request succeeds;
- stop the fallback origin;
- confirm fallback failure is bounded and does not expose tunnel protocol
  details;
- restore the fallback origin and confirm recovery.

Expected evidence:

- unauthenticated tunnel-like requests still avoid protocol-specific detail;
- fallback failures do not affect authenticated tunnel flows unless explicitly
  sharing the same target.

## Minimal Stable-Candidate Evidence Pack

Before a narrow stable-scope candidate, collect at least:

- server restart and client recovery evidence;
- client restart and reconnect evidence;
- upstream echo failure and recovery evidence;
- upstream stall/timeout evidence;
- one approved-host long-haul baseline of at least 24 hours. This baseline was
  collected on 2026-07-03 for the TCP/H2 runtime path; see
  `docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_03.md`.

The process-level failure-injection pack was collected on 2026-07-03 for the
TCP/H2 runtime path; see
`docs/history/evidence/APPROVED_HOST_FAILURE_INJECTION_EVIDENCE_2026_07_03.md`.

Packet-loss and host-level network impairment evidence is useful, but it should
remain a production-readiness input unless an approved isolated test host is
available.

An exploratory approved-host netem run completed on 2026-07-04, but the first
run was not accepted because it had failed iterations and exposed a harness
diagnostics weakness. A follow-up diagnostic 8-hour profile passed 96/96
iterations with zero baseline, impaired-profile, or recovery-baseline failures.
See `docs/history/evidence/APPROVED_HOST_NETEM_IMPAIRMENT_EVIDENCE_2026_07_04.md`.

The post-v1 M6 evidence package supersedes those earlier runs for the current
tested direct TLS/H2 source scope. Its 24-hour clean run, eight-hour impairment
run, and process-level failure-injection run all passed and completed strict
cleanup and evidence audits. See
`docs/history/evidence/APPROVED_HOST_POST_V1_M6_EVIDENCE_2026_07_11.md`.

## Evidence Format

Each evidence document should include:

- date and UTC start/finish times;
- tested commit or binary version;
- approved-host role labels, redacted before commit;
- command shape with placeholders;
- duration, interval, iteration count, pass count, and fail count;
- expected failure window;
- cleanup commands and residue checks;
- explicit non-claims.

Do not commit raw logs if they contain private hostnames, addresses, paths,
tokens, generated credentials, HMAC tags, or provider-specific resource names.
