# Phase 3 Closeout And Integration Recovery Boundary

Status: Phase 3 closed incomplete on 2026-07-19. The frozen candidate has a
final `NO_GO` decision. The separate recovery route has a corrected local
execution package, but no replacement remote run is active or authorized.

## Product Result

Phase 3 did not produce an accepted two-host product result. The final bounded
engineering rehearsal built the rehearsal server and verified the signed
reference-client package, but a controller readiness race stopped the run
before the client package was installed. Later service readiness did not
retroactively satisfy the rejected step.

The positive tunnel smoke, expected invalid-credential rejection, service
restart recovery, normal package purge, and the planned follow-up engineering
acceptance were therefore not completed. This is not evidence that the
protocol or package failed, but it is also not product acceptance.

## Preserved Results

The following remain accepted only within their recorded boundaries:

- the frozen Maverick and reference-client candidate identity;
- the Phase 3-B package, reproducibility, signature, source-binding, and freeze
  inputs;
- the public candidate control record and exact-source release-candidate CI;
- earlier narrow lifecycle and sustained evidence tied to their exact source;
- the fail-closed collection, cleanup, and resource-destruction result from the
  final rehearsal.

None of these results supplies the missing Phase 3-A input or a production
claim. Rejected or incomplete runs are not combined into a pass.

## Final Boundary

- Phase 3 is closed as incomplete; its final decision is `NO_GO`.
- The frozen candidate is parked. It is not released, published, deployable, or
  production-ready.
- The planned Phase 3 follow-up acceptance did not start.
- Production audit, remediation, deployment approval, and a stable release are
  not activated as a successor merely because Phase 3 ended.
- The former large formal execution framework remains historical material and
  is not the active route.

## Conditional Successor: Integration Recovery Program

There is no active server-recovery run. The project has created a separate
Integration Recovery Program (`IRP`) for any possible return to disposable
servers. IRP cannot be recorded as another Phase 3 rehearsal attempt and cannot
change the Phase 3 result.

### IRP-0: local recovery gate

Before any provider query or server authorization, the local-only gate had to:

1. preserve one root-cause ledger for every stopped Phase 3 server run;
2. replace one-shot readiness checks with a bounded state machine that checks
   service state, socket readiness, and application health until one deadline;
3. test delayed readiness, permanent non-readiness, early service exit,
   interruption recovery, and cleanup with harmless local substitutes;
4. review every previously unreached install, smoke, reject, restart, collect,
   purge, and destruction transition without creating another general-purpose
   framework;
5. choose exact source, package, signature, controller, and acceptance inputs;
6. produce one human-readable proposal and exact manifest for owner review.

The readiness component passed with real local processes for delayed startup,
permanent non-readiness, early exit, interruption, and cleanup, including a
repeated timing batch. A later no-cost preflight then correctly rejected the
first whole execution package because its real stage executables were missing;
that proposal was closed without external action. A corrected revision now
passes actual-entrypoint, four-way classification, partial-state, collection,
cleanup, and destruction checks locally. This remains a tool/readiness result,
not a product result. See `IRP_CONTROLLER_QUALIFICATION.md`.

### IRP-1: separately authorized integration qualification

The corrected local gate has produced a new private exact proposal, but it is
not authorized. The earlier proposal cannot be reused. The owner must
separately approve the corrected exact hash before any external action. That
approval must cover the provider and account, region, host roles, platform and
size, resource count, maximum cost, expected and hard time limits, stop
thresholds, destruction action, and fresh lease/run identity.

IRP-1 has one resource run and no automatic replacement or retry run. It must
again use fresh disposable hosts, collect before cleanup, destroy all
run-owned resources, and preserve the Phase 3 record regardless of outcome.

### IRP-2: outcome decision

If IRP-1 passes the complete product path, the project may separately decide
whether to create a new candidate and a small acceptance gate. If IRP-1 fails,
the program stops and returns to a candidate or architecture decision. Neither
outcome automatically starts production audit or release work.

## Authorization Boundary

The local recovery result authorizes no external work. It does not authorize
credentials, provider queries, remote access, resource creation, spending, CI,
tags, publication, or release operations.
