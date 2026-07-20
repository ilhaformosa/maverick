# Platform Helper IPC Contract

Status: version-1 data contract implemented in `maverick-sdk` for the
experimental Linux reference-client path. This document does not implement or
authorize platform mutation. A separate reference-client project implements the
socket, helper, and Linux platform transaction behind an explicit default-off
mutation gate.

## Purpose

The unprivileged reference client needs a small way to ask a future privileged
helper to preflight, apply, inspect, or roll back platform network state. The
helper must never receive Maverick credentials, packet payloads, destinations,
transport internals, or free-form application logs.

## Version And Encoding

- protocol version: `1`;
- encoding: one bounded JSON message per authenticated local transport frame;
- maximum encoded request or response: 16 KiB;
- unknown fields: rejected at both the message and nested recovery levels;
- request identifier: 1-64 ASCII letters, digits, `_`, or `-`;
- free-form remote error text: not allowed.

A stream implementation that dedicates one connection to one exchange must
require write EOF immediately after the single frame. Bytes after that frame
are a protocol error: the helper must reject a trailing request before
execution, and the client must reject a trailing response before acceptance.

The schema does not require a socket type or peer-authorization mechanism. The
separate reference-client project uses a bounded Unix transport, verifies peer
identity, enforces the one-frame/EOF boundary, rejects replay, serializes
mutation, and transfers exactly one TUN descriptor only after a matching
successful apply response.

The checked-in compatibility vectors live at
`test-vectors/reference-client/platform-helper-ipc-v1.json`. SDK tests decode,
validate, and re-encode every accepted vector, and require every rejected
vector to stay rejected. This makes accidental version-1 schema drift fail the
local harness before it can reach a helper implementation. The vectors also
exhaust the finite recovery-state matrix: all 4 valid and all 14 invalid
combinations of status, reason, and helper-journal presence are represented.

## Operations

Only these operation names exist:

- `preflight`: read-only readiness and conflict check;
- `apply`: journal-first platform apply request;
- `rollback`: idempotent rollback request;
- `status`: read-only coarse recovery state.

No generic command, argument list, environment map, shell text, or plugin
operation is accepted.

## Journal Path

The caller supplies one approved absolute journal root. The only accepted
journal path is its direct child:

```text
maverick-recovery.json
```

The request cannot select another filename, parent directory, relative path,
or traversal path. The future helper must additionally protect the directory
with platform ownership and permission checks and must reject symlink or owner
changes before use.

## Responses

Responses contain:

- matching version and request identifier;
- one fixed outcome;
- coarse clean, cleanup-required, or recovering state;
- whether a helper journal exists;
- one optional fixed error class only when the outcome is `rejected`.

Outcomes and recovery states must agree. Successful ready/rollback responses
are clean. An applied response must retain an ordinary helper journal and must
not report a prior rollback failure. Cleanup-required responses retain either
ordinary rollback state or a recorded rollback failure; recovering responses
report recovery in progress. Rejected responses may use only these coarse error
classes: invalid request, permission, conflict, apply failed, rollback failed,
or internal.

## Remaining Gate

The separate reference client now has authenticated local transport and peer
authorization, replay handling, one-operation locking, strict journal safety,
bounded timeouts, installed IPv4 TCP/UDP/DNS and route-failure evidence, signed
package transaction coverage, and independent residue checks. Before real use
it must still complete:

- machine-restart and power-loss recovery evidence;
- broader network-transition leak and coexistence evidence;
- repeated and sustained resource/lifecycle evidence;
- production credential-root, package-publication, and daily-use gates.

The data contract passing unit tests is not proof of a secure privileged helper
or a production reference client.
