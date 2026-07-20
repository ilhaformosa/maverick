# Product TUN And Ecosystem Execution Plan

Status: active post-v1 implementation plan. M6 and M8 Phases 0-2 are complete
for their recorded scope. The fixed comparison selected `smoltcp 0.13.1`; the
experimental bounded packet runtime is locally verified, and the approved-host
Phase 2 IPv4 real-TUN matrix is accepted. IPv6 is not scheduled; cross-platform
product clients and production readiness remain open. Phase 3 selects an
experimental Linux CLI/service reference client through
`docs/REFERENCE_CLIENT_SELECTION.md`. This document does not authorize new
network changes on a developer workstation or any remote host.

## Decision

Maverick will take an engine-boundary-first path:

1. select and integrate a proven packet/TCP-IP engine instead of writing a new
   TCP/IP stack;
2. expose a small TUN and lifecycle boundary through the Rust SDK;
3. prove one usable reference-client path on explicitly approved test systems;
4. then decide which external client ecosystem adapter has enough demand to
   justify maintenance;
5. expand standardization and community governance only after real adoption and
   an independent implementation exist.

Maverick remains a protocol and reference runtime first. It will not attempt to
build unrelated native applications for every platform at once.

## Address-Family Scope

The current product path is IPv4-only. IPv6 is not part of the short-term,
medium-term, or current long-term execution plan. Existing experimental
dual-stack code and synthetic fixtures remain regression inputs only. Future
IPv6 support is possible, but it requires a new explicit product decision and
evidence plan rather than being inherited by the current milestones.

## Product Goal

The first product outcome is simple:

> A user can start one reviewed client, route ordinary device traffic through
> Maverick, stop it, and recover the original network state without manual
> repair or secret leakage.

This requires more than creating a TUN device. The product path must cover:

- packet ingestion and return traffic;
- TCP, DNS, and the documented UDP boundary;
- route and DNS ownership;
- control-plane bypass so the tunnel does not route into itself;
- MTU, fragmentation, and IPv4 behavior;
- startup, sleep/resume, reconnect, shutdown, crash, and rollback;
- leak and coexistence checks;
- redacted diagnostics and secure profile storage.

## Current Starting Point

Already implemented:

- route-plan and apply-safety models;
- synthetic IPv4/IPv6 TCP/UDP packet classification;
- abstract apply/rollback actions;
- approved-host helper preflight and rollback journal handling;
- namespace-scoped runtime and policy smokes;
- service-manager and leak/coexistence smokes;
- a Rust SDK with client/server lifecycle, profile metadata separation, secret
  storage contracts, and redacted diagnostics;
- a separate application boundary that prevents UI code from reimplementing
  Maverick protocol behavior;
- the exact, machine-checked Phase 0 engine comparison and rejection record;
- a `#![forbid(unsafe_code)]` packet crate using pinned `smoltcp 0.13.1` with
  host-facing PHY features excluded;
- caller-supplied packet I/O, dual-stack TCP, port-53 DNS interception, bounded
  generic UDP, lifecycle, backpressure, and coarse resource snapshots;
- a direct connector that shares the existing flow semaphore, H2 pool, auth,
  TCP, DNS, and UDP paths;
- SDK build/runtime gates and local real-Maverick loopback integration tests.

Still missing:

- platform packet I/O between a real TUN device and Maverick flows;
- product route/DNS adapters;
- a tested app-to-helper IPC contract;
- real-device lifecycle and leak evidence;
- a daily-use reference client.

The completed helper smokes prove rollback discipline. They do not prove a
full-device proxy runtime.

The preparation, decision, and Phase 1 contract are recorded in:

- `docs/TUN_ENGINE_RESEARCH.md`;
- `docs/TUN_PACKET_ADAPTER_CONTRACT.md`;
- `docs/TUN_SYNTHETIC_TEST_MATRIX.md`;
- `docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`;
- `docs/TUN_ENGINE_COMPARISON.md`.

These prove an unprivileged experimental runtime, not a real-device product
implementation.

## TUN Engine Selection

Do not select a dependency from popularity alone. Run a bounded comparison
spike against a fixed adapter contract.

Required capabilities:

- accepts packets from an injected TUN file descriptor or equivalent stream;
- supports IPv4 and IPv6 TCP;
- exposes DNS and UDP behavior that can map to current Maverick flows;
- handles TCP state, retransmission, windows, FIN/RST, and backpressure;
- has explicit MTU and fragmentation behavior;
- can run without changing host routes or DNS itself;
- has bounded memory and connection state;
- supports deterministic tests without privileged networking;
- has an active maintenance history and a compatible license;
- has no hidden telemetry or unrestricted plugin hooks;
- permits clear separation between unprivileged protocol code and privileged
  platform setup.

Spike measurements:

- adapter code size and unsafe-code boundary;
- dependency size and supported platforms;
- TCP connect, transfer, half-close, reset, timeout, and cancellation behavior;
- DNS and UDP mapping behavior;
- 1, 10, 100, and bounded-concurrency flow tests;
- memory, CPU, throughput, and shutdown latency;
- malformed and truncated packet handling;
- testability with synthetic packets and an isolated Linux namespace.

Selection exit gate:

- one written comparison with reproducible commands;
- one small loopback prototype for the leading candidate;
- no route, DNS, firewall, proxy, or VPN mutation on the development machine;
- dependency, license, unsafe-code, and maintenance review;
- an explicit rejection reason for every non-selected candidate.

This gate passed on 2026-07-12. `smoltcp 0.13.1` is the one selected Phase 1
dependency. `ipstack`/`tun2proxy` and the gVisor sidecar boundary were rejected
with recorded reasons. The selection does not authorize platform setup or a
stronger support claim.

## Runtime Architecture

The intended ownership boundary is:

```text
application UI
    -> Maverick SDK lifecycle and redacted diagnostics
    -> unprivileged TUN packet adapter
    -> existing Maverick TCP/DNS/UDP flows
    -> narrow privileged platform helper for device/routes/DNS only
```

Rules:

- the UI never parses protocol frames or stores raw runtime configs;
- the packet engine never owns system route or DNS mutation;
- the privileged helper never receives Maverick user secrets or payloads;
- every privileged mutation is journaled before apply and has idempotent
  rollback;
- control-plane routes are installed before any default-route capture;
- the existing SOCKS5 and HTTP CONNECT modes remain available for recovery;
- TUN remains explicit until product evidence supports a safer default.

## Implementation Phases

### Phase 0: Engine And Contract Spike

Status: complete.

Scope:

- define the packet-engine adapter trait;
- compare maintained engines against the selection criteria;
- run synthetic and loopback-only tests;
- record resource and unsafe-code boundaries.

No privileged system mutation is allowed.

Exit:

- one engine selected or a documented no-selection result;
- adapter contract reviewed;
- performance and correctness baseline recorded.

### Phase 1: Unprivileged Packet Runtime

Status: complete locally; experimental and default-off.

Scope:

- add a separate crate or module behind an explicit build/runtime gate;
- accept an already-open packet stream supplied by tests;
- map TCP and DNS first, then the documented UDP boundary;
- reuse existing client lifecycle, connection pool, auth, and flow limits;
- expose coarse, redacted runtime counters.

No route or DNS mutation is allowed in local tests.

Exit:

- synthetic IPv4/IPv6 TCP round trips;
- DNS round trip;
- bounded UDP behavior;
- close/reset/backpressure and cancellation tests;
- no unbounded task, flow, or buffer growth;
- existing SOCKS5, HTTP CONNECT, DNS, and UDP tests remain green.

Closeout:

- all listed Phase 1 exit conditions pass;
- `maverick-tun` has 21 bounded config/packet/lifecycle tests and the embedded
  connector has two feature-gated close/reset tests;
- the real Maverick loopback integration has two tests and reuses one H2
  connection across TCP, DNS, and UDP;
- the combined engine-plus-connector buffer ceiling is validated before start;
- default client builds do not link the runtime, stable mode rejects it, and
  the runtime has no TUN creation or host-network mutation API;
- sustained performance baselines and product-client lifecycle evidence remain
  later gates; IPv6 is unscheduled rather than an active blocker.

### Phase 2: Disposable Linux End-To-End Gate

Status: accepted on 2026-07-12 for the recorded approved-host IPv4 matrix.

The prepared approval inputs, execution order, evidence depth, acceptance gate,
and stop conditions are in `docs/TUN_PHASE2_EXECUTION_GATE.md`.

Scope:

- use only an explicitly approved disposable Linux system;
- connect the unprivileged packet runtime to a temporary namespace-local TUN;
- preserve the SSH/control-plane path;
- exercise default route and namespace DNS only inside the disposable scope;
- test success, intentional failure, process kill, and retained-journal recovery.

Exit:

- TCP, DNS, and supported UDP traverse the real packet runtime;
- IPv4 policy is explicit and IPv6 is recorded as unsupported and unscheduled;
- no host-global DNS or default-route drift;
- leak sentries pass;
- every temporary namespace, link, route, process, unit, and journal is absent
  after cleanup;
- full private logs and hashes are retained.

Closeout:

- TCP, DNS, supported UDP, IPv4 fragmentation, MTU 1280, bounded concurrency,
  and resource ceilings passed through a namespace-local real TUN;
- target refusal, graceful and forced runner termination, server interruption,
  stalled-flow cancellation, and retained-journal recovery passed;
- host route, resolver, firewall, forwarding, and unrelated-network invariants
  matched the baseline;
- collection preceded cleanup, retained manifests verified, cleanup reported
  zero residue, and a second independent residue check passed;
- IPv6-family cases were policy-blocked by pre-existing host configuration,
  were not counted as exercised passes, and are not a scheduled follow-up;
- this result does not select a product client or establish production,
  cross-platform, or native-IPv6 readiness.

### Phase 3: One Reference Client

Status: Linux CLI/service path selected. The local SDK recovery contract and
unprivileged lifecycle controller are implemented in this repository. A
separate reference-client project now implements the initial Linux platform
boundary and has accepted lifecycle and ordinary-client crash evidence.

Scope:

- choose one first platform based on actual operator need and test-device
  availability;
- integrate through the SDK/helper boundary;
- provide connect, disconnect, profile selection, coarse health, and recovery;
- keep advanced transports and protocol internals out of ordinary controls.

Exit:

- cold start, repeated connect/disconnect, sleep/resume, network change,
  reconnect, crash recovery, and uninstall/disable recovery pass;
- secret storage and diagnostics are verified;
- DNS and traffic leak tests pass on an explicitly approved test device;
- packaging/signing gates for that platform are documented separately;
- the client is described as experimental until real daily-use evidence exists.

Selection closeout:

- Linux is selected because it matches the Rust SDK and packet-I/O boundary,
  reuses the accepted isolated Linux evidence path, and can be tested on an
  explicitly approved disposable system without mutating the development Mac;
- macOS and mobile clients remain possible later consumers, not rejected
  platforms or current milestones;
- platform UI, installer, service-manager, privileged helper, and packaging
  code remain outside the Maverick protocol repository;
- the Maverick SDK now exposes a coarse helper-journal recovery snapshot so a
  platform client can block reconnect while cleanup is required;
- the version-1 helper IPC data contract bounds message size, operation names,
  request identifiers, journal location, and response error detail;
- the unprivileged controller orders preflight, apply, packet-runtime start and
  stop, rollback, and cold-start recovery through replaceable adapters;
- fake adapters cover repeated lifecycle, retained recovery, partial failure,
  fail-closed protocol matching, and coarse error reporting;
- the separate reference-client project implements peer-authorized bounded IPC,
  replay handling, one-operation locking, durable journal-first IPv4 TUN/route/
  DNS transactions, exact one-descriptor transfer, systemd credential
  references, and candidate service/sysusers/tmpfiles assets;
- after a global-capture sustained attempt affected management routing, the
  current local implementation adds a dedicated capture UID, fail-closed
  fallback guard, connection-bound transient application units, capture-only
  DNS, a rollback session lock, and root-only atomic systemd-credential import;
  fresh bounded privileged and host-key-posture evidence is accepted, while
  production credential-root protection remains open;
- approved disposable-host evidence covers route/DNS failure recovery, a real
  helper-to-SDK namespace lifecycle, helper-only service installation and
  cleanup, and retained recovery after abrupt ordinary-client termination;
- active client/helper process recovery and four route-only installed-service
  cycles with encrypted credentials are accepted;
- bounded installed IPv4 TCP/UDP/DNS, route separation, TUN-loss restart,
  route-loss fail-closed behavior, and exact cleanup pass on the corrected
  capture-UID implementation;
- the current-source package also passes signed active upgrade, downgrade
  rejection, failed-upgrade containment, valid higher-version retry, reconnect,
  purge, and independent zero residue without publishing a package;
- broader transition leak/coexistence, power-loss recovery, sustained resources,
  production credential-root protection, package publication, and daily use
  remain open.

### Phase 4: SDK And Ecosystem Adapter

Scope:

- stabilize only the SDK surface used by the reference client;
- choose C ABI, Swift, Kotlin, or another binding from a real integration need;
- evaluate one established proxy-client ecosystem at a time;
- prefer a thin adapter over duplicating an entire client platform.

Adapter entry gate:

- a maintainer or adopter is identified;
- the host project license and contribution model are compatible;
- Maverick auth, frames, TLS policy, and non-claims can remain intact;
- integration tests can run without private infrastructure;
- maintenance ownership exists beyond a one-time proof of concept.

Do not create speculative adapters for multiple ecosystems simultaneously.

### Phase 5: Independent Implementation And Standardization Readiness

This phase is evidence-triggered, not date-triggered.

Entry requires:

- one real reference client in repeated use;
- one credible adopter or independently maintained implementation;
- public wire documentation that matches runtime behavior;
- compatibility and migration evidence across at least two implementations;
- a private security-reporting path and resolved high-severity findings;
- contribution volume that exceeds what one maintainer can coordinate
  informally.

Only then consider:

- a versioned interoperability profile;
- a small proposal process for wire changes;
- multiple maintainers or reviewers with explicit ownership;
- external standardization discussion.

The existing governance and conformance documents remain reference material.
They must not grow into a process burden before these entry conditions exist.

## Ecosystem Position

The recommended sequence is:

1. Maverick reference runtime and SDK boundary;
2. one first-party or tightly controlled reference client;
3. one demand-backed external ecosystem adapter;
4. an independent implementation;
5. community governance and possible standardization.

Why not ecosystem-first:

- the Phase 2 IPv4 matrix exists, but a single namespace run does not stabilize
  a daily-use product TUN lifecycle or its platform SDK;
- forcing an experimental protocol into an established client can spread an
  unstable interface;
- no external maintainer currently owns that adapter.

Why not first-party-everywhere:

- platform networking, UI, signing, updates, and support would multiply faster
  than protocol evidence;
- most code would not improve Maverick's distinguishing resistance;
- a small SDK plus one reference client teaches the required contract first.

## Measurement And Release Gates

Every product TUN candidate records:

- exact commit and dependency lock;
- platform, kernel/OS, and adapter version;
- flow success/failure counts and failure stage;
- connection setup and steady-state latency;
- throughput, CPU, memory, task, and buffer bounds;
- DNS route and resolver behavior;
- address-family policy and IPv4 MTU/fragmentation behavior;
- reconnect and recovery time;
- leak and control-plane bypass results;
- cleanup and residue results;
- known gaps and non-claims.

Release claims remain weaker than the evidence. A passing namespace smoke is not
a daily-use client result, and one test device is not cross-platform support.

## M6 Preparation Closeout

The following work was completed without invalidating the M6 binary evidence:

- this plan and architecture documentation;
- engine-selection criteria and read-only dependency research;
- adapter trait sketches that are not merged into runtime code;
- synthetic test-case design;
- reference-client workflow and SDK boundary review;
- ecosystem and governance entry-gate definition.

Preparation closeout:

- architecture and implementation sequencing: complete;
- engine-selection criteria and read-only candidate research: complete;
- then-unmerged adapter-contract sketch: complete;
- synthetic comparison matrix and result schema: complete;
- reference-client workflow and SDK boundary review: complete;
- ecosystem and governance entry gates: complete;
- active-plan, release-checklist, and legacy platform-document consistency
  review: complete.

M6 is now accepted. The preparation package is the input to Phase 0; it is not
itself an engine selection or permission for privileged platform work.

Phase 0 closeout on 2026-07-12:

- the fixed isolated comparison package is complete;
- `ipstack` plus `tun2proxy` and the gVisor sidecar boundary are rejected with
  explicit reasons;
- `smoltcp 0.13.1` is selected only for unprivileged Phase 1;
- the adapter dependency and fixed comparison decision are complete;
- no real TUN device or host network mutation was used.

Phase 1 closeout on 2026-07-12:

- the separate packet crate, embedded connector, SDK surface, dual gates,
  resource accounting, lifecycle, and local integration tests are complete;
- all Phase 1 work used memory or loopback-only packet I/O;
- no route, DNS, interface, firewall, proxy, VPN, or remote-host state changed;
- this is no product-readiness claim.

Still gated during Phase 3 maturation:

- sustained resource and repeated daily-use evidence;
- broader transition/leak and installed-process recovery evidence;
- abrupt power-loss recovery and production credential-root protection;
- package publication and cross-platform client evidence;
- production, formal-audit, censorship-resistance, or IPv6 support claims;
- claims that product-TUN code was covered by the completed M6 binaries.

## First Execution Slice After M6

M6 long-haul, impairment, and failure evidence is accepted. Steps 1-7 and the
separately authorized Phase 2 run are complete:

1. promote the reviewed adapter sketch into an internal contract and implement
   the fixed comparison harness;
2. refresh the research snapshot and pin no more than three maintained
   candidates;
3. run the unprivileged synthetic comparison matrix;
4. select one candidate or record why none is acceptable;
5. implement Phase 1 behind an explicit build/runtime gate;
6. run the full local harness and focused resource tests;
7. request separate approval before any new privileged remote Phase 2 run.

The later separate Linux project has also completed the initial reference-client
implementation, bounded current-source safety matrix, and signed package
lifecycle matrix. The next product work is sustained resources, repeated use,
transition/leak and installed-process recovery, abrupt power loss, production
credential-root protection, and package publication. Each privileged evidence
run remains separately gated by explicit operator approval, host inventory,
bounded disposable scope, rollback and control-plane preservation, private
evidence collection, and residue verification.

This keeps the first implementation small, reversible, and useful while
preserving the current stable H2/TLS path.
