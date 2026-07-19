# Integration Recovery Controller Qualification

Status: the readiness component passed locally on 2026-07-19, but the first
whole IRP execution package was then rejected by a no-cost preflight because
its real stage executables were missing. A corrected executable package has
since passed a new local-only qualification. Its single authorized integration
run then stopped during provider preflight before resource creation. No server
run is active or authorized. A separately established transport-recovery
package then passed a new local-only gate and consumed its single authorized
run during read-only provider plan preflight, also before resource creation.
A later remote-first package consumed its single run after creating exactly two
disposable hosts, but stopped before SSH or product upload. All resources are
now confirmed absent. These tool results do not change the final Phase 3
`NO_GO` decision.

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
authorized.

The independent Integration Transport Recovery package used a new run
identity and proposal. Its real-loopback tests truncate the declared HTTP body
or disconnect before the status line, then prove GET/DELETE retry at most once,
POST retry zero, bounded fail-stop, redacted attempt logging, and all inherited
controller/cleanup gates.

Its single authorized run confirmed that the bounded retry path caught the
provider plan-list transport failure and retried once. The second attempt also
failed with the persisted broad class `transport`, so the controller stopped
before resource creation. The journal did not persist the underlying exception
class, so the precise cause is undetermined. No host, remote access, package
action, product process, product result, or spending occurred. The one-run
allowance is consumed; no replacement or successor is authorized.

The later remote-first package removed account, region, plan, OS, and full
instance catalog requests. Its local gate passed real streaming, bounded retry,
uncertain-create reconciliation, readiness, interruption, package-alignment,
entrypoint, and cleanup tests. In its one authorized run, all narrow collision
checks passed and exactly two hosts plus one run-owned key were created, with
one POST per resource and no POST retry. A subsequent host-readiness GET ended
with `remote_disconnect`; its one safe retry ended the same way.

Fail-stop happened before an accepted host address, SSH, upload, installation,
or product process. The provider temporarily rejected immediate deletion while
the new hosts were locked for provisioning. After that lock cleared, the same
exact cleanup deleted both hosts and the run-owned key, removed the local key,
and confirmed zero resources. The run is closed and authorizes no replacement.
