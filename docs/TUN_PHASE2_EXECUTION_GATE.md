# Product TUN Phase 2 Execution Gate

Status: accepted on 2026-07-12 for the tested IPv4 matrix on one approved
disposable Linux VM. This acceptance does not extend to the development
machine, a VM carrying protected services, host-global route/DNS/firewall
changes, native IPv6, cross-platform clients, resource deletion, or cloud
spending.

## Objective

Connect the Phase 1 packet runtime to a real namespace-local Linux TUN device
and prove that supported TCP, DNS, and UDP traffic traverses Maverick while the
host control plane, default route, global resolver, existing services, and
unrelated networking remain unchanged.

This is an experimental end-to-end gate, not a production-readiness claim.

## Approval Inputs

Before any remote command, record privately:

- the approved disposable Linux client host and whether it may be rebuilt;
- the approved Maverick server host, if a second host is used;
- permission for noninteractive `sudo`, network namespace, veth, TUN, route,
  namespace-scoped resolver, and process-failure tests;
- protected services, ports, interfaces, routes, and resolver state that must
  not change;
- bandwidth or cost limits;
- the exact source commit, Linux artifact hashes, unique run id, temporary
  names, ports, and automatic expiry time.

Private host labels, addresses, usernames, paths, and raw logs must not enter
git, public reports, commit messages, or CI artifacts.

## Required Implementation Boundary

The Phase 2 bridge must:

- live outside `maverick-tun`; the engine crate continues to accept only
  `PacketReader` and `PacketWriter`;
- open or receive exactly one run-owned `IFF_TUN | IFF_NO_PI` packet endpoint;
- keep any platform FFI or unsafe code in one reviewed Linux-only module or use
  one pinned maintained crate after a license/unsafe review;
- expose no generic shell callback to the packet engine or SDK;
- use the existing approval, rollback-journal, and residue-check boundaries;
- keep namespace network setup separate from the unprivileged Maverick process;
- fail closed if the control-plane preservation route, baseline inventory,
  unique resource names, or rollback journal cannot be established.

The selected evidence bridge is the feature-gated
`maverick-tun-phase2` Linux runner in `maverick-tests`. It uses one reviewed
Linux-only module with one documented `unsafe` block for `TUNSETIFF`; the
dependency is the exact already-audited `libc 0.2.186`. All packet reads and
writes use Tokio `AsyncFd`. The runner only attaches to a pre-created
`IFF_TUN | IFF_NO_PI` endpoint and cannot create links or change routes, DNS,
firewall, or namespaces. This is an approved-host evidence tool, not a product
network helper.

## Execution Order

1. Read-only inventory: OS/kernel, tools, privileges, interfaces, routes,
   resolver, listeners, firewall, services, free space, and clock.
2. Verify the commit-bound Linux artifacts and hashes before any mutation.
3. Confirm all proposed namespace/link/device names and ports are absent.
4. Write the rollback journal and an automatic-expiry cleanup path.
5. Create only a run-owned namespace, veth pair, namespace-local TUN, preserved
   control-plane route, and namespace-scoped resolver material.
6. Start the server and packet runner with exhaustive private logs and periodic
   child-process resource samples.
7. Run baseline TCP, DNS, supported UDP, IPv4/IPv6 policy, MTU, and bounded
   concurrency checks.
8. Run fragmentation/extension and unsupported-protocol fixtures, recording
   exact supported or rejected behavior without promoting gaps to passes.
9. Run failure stages separately: target refusal, packet runner termination,
   client termination, server interruption, stalled flow, and retained-journal
   recovery.
10. Collect every source log and inventory snapshot before cleanup.
11. Analyze counts, latency, resources, task/flow/buffer peaks, route/DNS
    invariants, failures, recovery, and all timestamp gaps.
12. Clean only run-owned resources, verify residue and protected-service
    invariants, then hash the complete private evidence package.

## Evidence Requirements

The private package must retain:

- launch command provenance with secrets redacted;
- exact source commit, version, toolchain, artifact hashes, and dependency lock;
- preflight and post-cleanup host/network inventories;
- packet-runtime snapshots over time, including engine and connector tasks,
  flows, queues, current bytes, conservative component-peak sums, and
  configured capacity; connector bytes are full active-duplex reservations,
  not measured queue occupancy;
- operating-system RSS for the actual Maverick child process, kept distinct
  from the runtime's payload-buffer capacity because shared H2 state, task
  metadata, allocator overhead, and other process allocations are not included
  in that capacity;
- per-case start/end timestamps, result, failure stage, latency, and byte counts;
- full client/server/runner stderr and structured event logs;
- resource samples for the actual Maverick and packet-runner child processes;
- intended failure windows and observed recovery times;
- namespace, veth, TUN, route, qdisc, firewall, resolver, process, unit, port,
  file, and rollback-journal cleanup checks;
- a SHA-256 manifest covering every retained file.

Collection always precedes cleanup. A short summary without source logs is not
acceptable evidence.

## Acceptance Gate

Phase 2 passes only when:

- supported TCP, DNS, and UDP traverse the real TUN path with every case
  reconciled;
- IPv4/IPv6, MTU, fragmentation, extension-header, and ICMP behavior are
  explicitly supported or explicitly blocked;
- configured flow/task/queue/buffer ceilings are never exceeded;
- cancellation and each injected failure recover within the documented bound;
- SSH/control-plane reachability and protected services remain available;
- host default route, global resolver, firewall baseline, and unrelated
  listeners are unchanged;
- cleanup removes every run-owned resource and a second independent residue
  check agrees;
- private evidence is complete, internally consistent, and hash verified;
- public documentation contains only redacted aggregate facts and non-claims.

Any unexplained failure, sampling gap, provenance mismatch, protected-state
change, or cleanup residue blocks acceptance. Rerun only the affected layer
after diagnosis; do not discard failed evidence.

## Accepted Evidence

The final commit-bound run retained full private source logs and passed the
acceptance gate with these public, redacted facts:

- 26 case records were reconciled with no unexpected failure;
- TCP, DNS, supported UDP, IPv4 fragmentation, and a 1 MiB TCP echo at MTU 1280
  traversed the namespace-local real TUN path;
- 12 of 12 within-limit flows succeeded, while pressure reached the configured
  16-flow ceiling without exceeding the 32-entry queue ceilings or configured
  buffer capacity;
- target refusal, graceful and forced runner termination, server interruption,
  stalled-flow cancellation, retained-journal recovery, and final TCP/DNS
  recovery behaved as expected;
- 53 timestamped operating-system resource samples had no gap over 1.5 seconds,
  and every structured runner event had a timestamp;
- the host default route, global resolver, firewall, forwarding values, and
  unrelated networking matched their pre-run baselines;
- explicit cleanup reported zero residue, and a second independent check
  agreed before the remote run-owned files were removed.

IPv6, IPv6 fragmentation, extension-header, and ICMPv6 cases were explicitly
policy-blocked because IPv6 was already disabled on the host. They are not
exercised passes. This acceptance is limited to the recorded experimental IPv4
matrix and is not a production-readiness, censorship-resistance, formal-audit,
or cross-platform claim.

## Stop Conditions

Stop before mutation if approval, inventory, artifact provenance, uniqueness,
rollback, automatic expiry, or control-plane preservation is uncertain. Stop
during the run if an unrelated service, host-global route/resolver/firewall
state, or operator access changes. Preserve logs first, then clean only
run-owned resources.
