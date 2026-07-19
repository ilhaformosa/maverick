# Integration Recovery Controller Qualification

Status: the readiness component passed locally on 2026-07-19, but the first
whole IRP execution package was then rejected by a no-cost preflight because
its real stage executables were missing. A corrected executable package has
since passed a new local-only qualification. Its single authorized integration
run then stopped during provider preflight before resource creation. No server
run is active or authorized. These tool results do not change the final Phase
3 `NO_GO` decision.

## What Passed

The recovery controller now uses one bounded deadline instead of a one-shot
health request. It waits for three signals to agree:

1. the service-manager state;
2. the exact operating-system resource, such as a listening socket or TUN;
3. the exact application-health assertion.

A connection refusal while the deadline remains means "not ready yet." A
terminal service state, probe error, interruption, or deadline expiry has its
own result and cannot be reported as a product failure.

The actual readiness code passed local real-process checks for delayed startup,
permanent non-readiness, early process exit, interruption, and cleanup. It also
passed a repeated twenty-run timing batch with no process, listener, or
run-owned-directory residue. The fixed controller's ordering, fail-stop,
receipt, collection, destruction, and four-way classification rules passed
their unit checks.

The corrected package also exercises its actual fixed stage entrypoints rather
than only a simulated runner. Local fixtures cover complete success, qualified
product rejection, unqualified-label rejection, controller interruption,
partial resource creation, collection replay, destruction replay, and parsing
of every rendered remote command. An independent hard-deadline guard stops the
active process group before collection and destruction.

## Result Firewall

Every future integration run must end with exactly one of:

- `TOOL_FAILURE`;
- `ENVIRONMENT_FAILURE`;
- `PRODUCT_FAILURE`;
- `PRODUCT_PASS`.

`PRODUCT_FAILURE` is impossible until the measurement tool has qualified on
both fresh hosts and an exact product assertion has a diagnostic receipt.
`PRODUCT_PASS` requires the complete product, collection, cleanup, and resource
destruction path in one run. Partial runs are never combined.

## What Remains

The corrected proposal received one exact authorization. The controller armed
its safety deadline and began read-only provider preflight, but a truncated
response escaped the adapter's safe GET-retry path. It stopped before any
resource-create request. No host, SSH session, upload, package installation,
Maverick process, fault action, product result, or spending occurred.

The one-run allowance is consumed and closed. No automatic replacement is
authorized. Any future return requires a new project-level decision, a new run
identity, corrected and requalified adapter behavior, and fresh exact owner
authorization. It still cannot be called Phase 3 attempt 5 or authorize a
successor candidate, production audit, deployment, release, or Go by itself.
