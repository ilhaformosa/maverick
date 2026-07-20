# Reference Client Controller

Status: unprivileged controller implemented in `maverick-sdk` for the
experimental Linux reference-client path. The controller itself does not open a
TUN, run commands, change routes or DNS, install a service, or authorize
privileged execution. A separate reference-client project now binds this
controller to the real helper and SDK runtime behind an explicit default-off
platform-mutation gate.

## Purpose

The controller is a small traffic director between two replaceable adapters:

```text
platform helper transport
    -> preflight / apply / rollback
reference-client controller
    -> start / stop packet runtime
```

The controller owns ordering and coarse state. The separate Linux project owns
the authenticated local transport, packet handle, helper, packaging, and
service lifecycle.

## States

- `disconnected`: clean and eligible to connect;
- `connecting`: preflight/apply/runtime start is in progress;
- `connected`: packet runtime is active and rollback state is retained;
- `disconnecting`: runtime stop and rollback are in progress;
- `cleanup_required`: helper rollback or local packet-runtime cleanup must be
  proven before reconnect;
- `recovering`: rollback is in progress.

Only coarse state and a fixed error class are serializable. The controller
snapshot omits the journal root, request prefix, helper details, destinations,
credentials, packet metadata, and raw errors.

## Connect Order

1. Require clean disconnected state.
2. Send helper `preflight` and require a matching `ready` response.
3. Send helper `apply` and require a matching `applied` response with retained
   cleanup state.
4. If an `apply` transport or protocol result is uncertain, require rollback
   before reconnect. A validated rejection may report an authoritative clean
   state when no mutation occurred.
5. Start the packet runtime.
6. If packet startup fails, stop it and request rollback. A stop error remains
   cleanup-required even when helper rollback succeeds.
7. Report connected only after every required step succeeds.

## Disconnect And Recovery

Disconnect stops the packet runtime before requesting rollback. Rollback still
runs if runtime stop reports failure. A successful rollback returns to clean
disconnected state only when runtime stop also succeeded. Any stop failure
remains cleanup-required and blocks reconnect until a later recovery retries
the idempotent stop and rollback successfully.

Cold start with a retained helper journal begins cleanup-required. Connect is
rejected until explicit recovery successfully stops any residual packet runtime
and completes rollback.

If a caller cancels `connect` or `disconnect` while it is waiting, the retained
`connecting`, `disconnecting`, or `recovering` state also permits explicit
recovery. Recovery retries local stop and the fixed idempotent rollback instead
of allowing a new connection to assume that the interrupted operation had no
effect.

## Current Tests

- 32 repeated connect/disconnect cycles with exact operation ordering;
- cold-start retained-journal recovery;
- packet-runtime startup failure followed by rollback;
- partial packet-runtime startup plus failed stop blocking reconnect;
- packet-runtime stop failure with rollback still completed but reconnect
  blocked until a successful recovery retry;
- rollback failure preserving cleanup-required state;
- helper rejection and helper transport failure;
- uncertain apply transport results requiring rollback, while a validated clean
  rejection remains disconnected;
- cancellation after an apply effect, after a runtime-start effect, during
  runtime stop, and after a rollback effect, all followed by explicit recovery;
- mismatched response request ID and invalid lifecycle transitions;
- invalid applied/recovery combinations classified as protocol errors, with no
  packet-runtime start and a retained rollback path;
- fixed coarse errors and snapshot redaction.

All adapters in this repository's tests are in-memory fakes. No listener, TUN,
route, DNS, firewall, proxy, VPN, service manager, or remote host is touched by
those tests. Separately collected approved-host evidence now covers the real
helper-to-SDK connect/disconnect order and retained-journal recovery after the
ordinary client exits abruptly.

## Remaining Boundary

The controller preserves a recoverable state across cancellation, but it cannot
prove when an adapter's already-started operating-system work reaches a terminal
result. Recovery therefore retries stop and fixed idempotent rollback. Process
death still relies on the durable helper journal. The separate Linux project now
provides authenticated local IPC, peer authorization, single-operation locking,
replay handling, durable journal rules, one-descriptor packet-handle transfer, a
real packet adapter, and initial approved-system lifecycle evidence.
The tested installed IPv4 TCP/UDP/DNS and route-separation matrix is accepted.
The current signed package also passes default-inactive install, active-session
upgrade rollback, downgrade rejection, failed-upgrade containment, valid retry,
purge, and independent zero residue. Before real use it still needs power-loss,
broader transition leak/coexistence, sustained resource, and daily-use
validation.
