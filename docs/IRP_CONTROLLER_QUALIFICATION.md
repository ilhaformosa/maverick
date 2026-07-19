# Integration Recovery Controller Qualification

Status: the local-only IRP-0 controller qualification passed on 2026-07-19.
No server run is active or authorized. This result does not change the final
Phase 3 `NO_GO` decision.

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

IRP-0 is only a local tool result. It did not query a provider, create a host,
use SSH, upload inputs, install a package, start Maverick, inject a fault, or
spend money.

A private exact IRP-1 proposal exists, but it has no authorization. If the
owner later approves that exact proposal, two fresh direct disposable Ubuntu
hosts must first pass harmless delayed-start, never-ready, early-exit,
interruption, cleanup, and zero-residue calibration. Product inputs cannot be
uploaded before both calibrations pass.

IRP-1 would have one resource run and no automatic replacement. It would not be
Phase 3 attempt 5, would not alter the frozen candidate, and would not by itself
authorize a successor candidate, production audit, deployment, release, or Go.
