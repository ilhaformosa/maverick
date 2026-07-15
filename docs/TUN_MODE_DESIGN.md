# TUN Mode Design

Status: privileged-helper safety baseline, unprivileged packet runtime Phase 1,
and the approved-host Phase 2 IPv4 matrix are complete; real-device product
integration is not. The active product
sequence is `docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md`, with the engine decision in
`docs/TUN_ENGINE_COMPARISON.md` and the implemented contract in
`docs/TUN_PACKET_ADAPTER_CONTRACT.md`. Local-only route-plan modeling, apply
safety gates, CLI dry-run reporting, synthetic packet classification, and
approved-host helper smokes are implemented. Approved-VM smoke has exercised
temporary TUN creation,
documentation-prefix route mutation, namespace-scoped DNS configuration, and
rollback on Linux. The CLI helper Phase A smoke has exercised temporary TUN
creation, documentation-prefix route mutation, route probing, rollback, and
residue checks with a structured rollback journal on `approved-linux-vm`. The CLI
rollback recovery path has also consumed a retained journal and removed a
temporary TUN plus documentation-prefix route on `approved-linux-vm`. The CLI
preflight path has checked approved-host readiness without mutation on
`approved-linux-vm`. The Phase A helper and retained-journal recovery also verify
that default route and global DNS resolver baselines remain unchanged. No TUN
apply testing should run on the user's everyday machine.
These helper and namespace smokes are evidence for isolated-host safety
boundaries. The later Phase 1 packet runtime is integrated only with synthetic
and loopback packet I/O; neither evidence set proves a real-device product.
`scripts/approved-vm-tun-runtime-smoke.sh` has exercised Phase B namespace
runtime behavior on `approved-linux-vm`: temporary network namespace, veth data path,
namespace-local TUN, namespace policy route, namespace-scoped DNS, leak
sentries, rollback, residue checks, and unchanged host default-route/global-DNS
baselines. `scripts/approved-vm-tun-policy-smoke.sh` has exercised Phase C
namespace policy behavior on `approved-linux-vm`: production-route preserve semantics,
namespace-local default route to TUN, namespace DNS route selection to TUN,
control-plane bypass over veth, rollback, residue checks, and unchanged host
default-route/global-DNS baselines. Service-manager lifecycle smoke and
leak/coexistence smoke have also passed on `approved-linux-vm`, covering transient
systemd success/failure cleanup, preserved control-plane routing, TUN-selected
default/DNS probes, host listener baselines, rollback, residue checks, and
unchanged host default-route/global-DNS baselines.
`scripts/approved-vm-tun-full-helper-smoke.sh` has exercised the current
prototype's full privileged-helper integration gate by chaining the runtime,
policy, service-manager, and leak/coexistence smokes and performing an
independent final residue check. This is not a production full-device TCP/IP
relay claim.

## Goals

- Provide a future full-device routing mode without changing the Maverick
  protocol identity.
- Keep SOCKS5 and HTTP CONNECT as the safe default local modes.
- Make TUN setup explicit, reversible, and observable.
- Avoid touching system DNS, routes, firewall, VPN, or other network-service settings during ordinary
  development.

## Non-Goals

- Transparent system-wide interception in the current prototype.
- Kernel extension work.
- Mobile VPN profile implementation.
- Running privileged route changes in the local harness.

## Architecture

The future TUN runner should be a separate binary or subcommand:

```text
maverick tun --config client.yaml --dry-run
maverick tun --config client.yaml --apply
```

The implemented safe CLI surface today is intentionally narrower:

```text
maverick tun-plan --include-route 10.0.0.0/8 --abstract-runtime-plan
maverick tun-helper-preflight --approved-host-label approved-linux-vm --rollback-journal /tmp/maverick-preflight-rollback.json
maverick tun-helper-smoke --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked
MAVERICK_TUN_HELPER_APPROVED=1 maverick tun-helper-smoke --apply --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked --rollback-journal /tmp/maverick-phase-a-rollback.json
maverick tun-helper-rollback --rollback-journal /tmp/maverick-phase-a-rollback.json --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked
```

`tun-plan` prints local-only dry-run steps, apply blockers, and optional
abstract runtime apply/rollback actions. It never applies OS network changes.
`tun-helper-preflight` performs read-only approved-host checks for Linux,
`ip`, noninteractive privileges, existing test device/route state, and rollback
journal path availability. It never applies OS network changes and does not
create the rollback journal.
`tun-helper-smoke` is approved-host-only. Without `--apply` and
`MAVERICK_TUN_HELPER_APPROVED=1`, it reports blockers and does not apply
system changes. With approval on Linux, it is limited to temporary TUN device
creation, assigning `10.255.0.1/30`, adding an RFC 5737 documentation /24
route to that device, probing that route, rolling back the route and device,
writing a structured rollback journal before mutation, removing the journal
after successful rollback, checking for residue, and verifying unchanged
default-route and global-DNS baselines. It does not add a default route, modify
global DNS, alter firewall rules, or touch proxy/VPN or other network-service settings.
`tun-helper-rollback` consumes a retained Phase A rollback journal. It is also
approved-host-only, idempotently removes the journal's documentation-prefix
route and TUN device when present, verifies residue, and removes the journal
after successful cleanup. It also verifies unchanged default-route and
global-DNS baselines during recovery.

Core pieces:

- platform adapter for TUN device creation;
- route planner that can produce a dry-run plan;
- DNS planner that never mutates system DNS without explicit apply;
- packet classifier that maps TCP and UDP packets to existing tunnel flows;
- rollback manager that records every applied system change;
- health reporter for UI/tray integration.

Implemented baseline:

- `TunRoute` and `TunRoutePlan` in `maverick-core`;
- dry-run step generation;
- apply safety-gate decision model requiring completed dry-run, explicit
  operator approval, approved test host/device, supported platform, confirmed
  privileges, proxy/VPN conflict check, and writable rollback plan;
- device-name validation;
- IPv4/IPv6 prefix validation;
- IPv4/IPv6 synthetic packet classifier for direct TCP/UDP packets;
- unit tests for disabled plans, invalid routes, invalid names, and reversible
  dry-run steps;
- unit tests for TCP, UDP, IPv6, fragmented IPv4, and truncated packet handling.
- approved-VM smoke script for temporary Linux TUN device creation,
  documentation-prefix route apply/rollback, namespace-scoped DNS
  apply/rollback, and residue checks.
- `TunRuntimePlan` plus abstract apply/rollback actions for approved,
  include-route, exclude-route, default-route, and DNS plans. The model records
  rollback before mutation actions and rejects route-exclusion, default-route,
  DNS, control-plane-bypass, and leak-sentry-sensitive plans until the
  production policy gate marks those controls ready.
- CLI `tun-plan` reports dry-run steps, safety blockers, and optional abstract
  runtime actions with `system_apply: false`.
- `docs/history/manifests/tun-helper-approval.json` records the allowed approved-host-only smoke
  slices and blocked local/global-DNS slices. Its checker is metadata
  validation and is not part of the default local gate.
- `docs/history/manifests/tun-runtime-blockers.json` records the next-stage blocker execution plan.
  Its checker is metadata validation and is not part of the default local gate.
  It does not authorize local or remote mutation. It records Phase B namespace
  runtime smoke, Phase C namespace policy smoke, service-manager lifecycle
  smoke, and leak/coexistence smoke as completed on an approved VM while
  also recording the full-helper aggregate integration smoke as completed.
- `scripts/approved-vm-tun-runtime-smoke.sh` implements the approved-host-only
  Phase B namespace runtime smoke. It refuses localhost, requires
  `MAVERICK_TUN_RUNTIME_APPROVED=1`, runs leak sentries inside the namespace,
  and verifies rollback plus unchanged host default-route/global-DNS baselines.
- `scripts/approved-vm-tun-policy-smoke.sh` implements the approved-host-only
  Phase C namespace policy smoke. It refuses localhost, requires
  `MAVERICK_TUN_POLICY_APPROVED=1`, verifies namespace-local default-route and
  DNS route selection to the TUN device while preserving the veth control-plane
  route, and verifies rollback plus unchanged host default-route/global-DNS
  baselines.
- `scripts/approved-vm-tun-service-smoke.sh` implements the approved-host-only
  service-manager lifecycle smoke. It refuses localhost, requires
  `MAVERICK_TUN_SERVICE_APPROVED=1`, starts transient systemd units only,
  verifies privileged helper success and intentional-failure cleanup paths, and
  verifies rollback plus unchanged host default-route/global-DNS baselines.
- `scripts/approved-vm-tun-leak-coexistence-smoke.sh` implements the
  approved-host-only leak/coexistence smoke. It refuses localhost, requires
  `MAVERICK_TUN_LEAK_APPROVED=1`, verifies namespace default/DNS probes select
  the TUN path, verifies preserved control-plane traffic stays on veth, checks
  host listener/default-route/global-DNS baselines, and verifies rollback.
- `scripts/approved-vm-tun-full-helper-smoke.sh` implements the
  approved-host-only aggregate full-helper integration smoke for the current
  prototype scope. It refuses localhost, requires
  `MAVERICK_TUN_FULL_HELPER_APPROVED=1`, chains the runtime, policy,
  service-manager, and leak/coexistence smokes, and verifies final residue
  absence. It does not claim production full-device TCP/IP relay behavior.
- CLI `tun-helper-preflight` implements read-only approved-host readiness
  checks for the Phase A helper scope.
- CLI `tun-helper-smoke` implements the gated Linux Phase A helper smoke for
  temporary TUN and documentation-prefix route apply/rollback on an approved
  host only. It writes a JSON rollback journal before mutation and removes it
  only after successful rollback. It verifies that default route and global DNS
  resolver baselines are unchanged.
- CLI `tun-helper-rollback` reads a retained JSON rollback journal and performs
  approved-host-only idempotent route/device cleanup. It also verifies that
  default route and global DNS resolver baselines are unchanged.
- `TunRuntimeReadinessSnapshot` records completed route-plan, apply-safety, and
  approved-VM smoke baselines plus the runtime-helper plan model, preflight,
  rollback journal, retained-journal recovery, network-baseline checks, Phase B
  namespace runtime smoke, Phase C namespace policy smoke, service-manager
  lifecycle smoke, leak/coexistence smoke, and full-helper aggregate smoke.

## Safety Model

`--dry-run` is mandatory for first implementation. The core
`evaluate_tun_apply_safety` model now treats `--apply` as blocked unless:

- config explicitly enables TUN mode;
- dry-run has completed;
- operator approval is explicit;
- the target is a separate VM or explicitly approved device;
- process has required privileges;
- target platform is supported;
- no unsupported VPN/proxy conflict is detected;
- rollback plan can be written.

The model returns blockers only. It does not create TUN devices or mutate
routes, DNS, firewall, proxy, VPN, or other network-service settings. The approved-VM smoke is
a separate SSH-only harness and is not called by the local harness or CLI.

## Runtime Readiness

`TunRuntimeReadinessSnapshot` is runtime-ready for the current prototype's
privileged-helper safety harness. This readiness does not claim production
full-device TCP/IP relay behavior.

The snapshot's historical `runtime_ready` name refers to the helper-safety
scope. Product readiness additionally requires a selected packet engine, the
adapter contract, an integrated packet-to-flow runtime, SDK lifecycle, and real
reference-client evidence.

## Test Plan

Allowed on this machine:

- route-plan unit tests;
- config validation;
- apply safety-gate unit tests;
- runtime plan model unit tests;
- CLI `tun-plan` parse/report tests and local harness smoke;
- CLI `tun-helper-preflight` parse/report tests, local read-only tests, and
  rollback-journal availability tests;
- CLI `tun-helper-smoke` parse/report tests, local dry-run tests, and local
  apply-without-approval refusal checks, including rollback-journal report and
  JSON serialization checks;
- CLI `tun-helper-rollback` parse/report tests, local dry-run tests,
  apply-without-approval refusal checks, retained-journal validation tests, and
  forbidden default-route journal rejection tests;
- TUN helper approval manifest checker tests;
- packet classifier tests with synthetic packets.

Requires separate VM or approved device:

- TUN device creation;
- route and DNS apply/rollback;
- coexistence testing with system proxy/VPN software;
- leak checks against real interfaces.

Completed on approved VM:

- `scripts/approved-vm-tun-apply-smoke.sh` passed on `approved-linux-vm` on
  2026-06-27. It did not add a default route or modify global DNS; DNS
  coverage used a temporary Linux network namespace.
- `maverick tun-helper-preflight` passed on `approved-linux-vm` on 2026-06-27. It
  reported Linux, `ip`, privileges, absent `mavtun0`, absent `192.0.2.0/24`,
  available rollback journal path, and `preflight_ready: true` without creating
  residue.
- `maverick tun-helper-smoke --apply` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_HELPER_APPROVED=1`. It created a temporary
  `mavtun0` device, assigned `10.255.0.1/30`, added and probed
  `192.0.2.0/24`, wrote `/tmp/maverick-phase-a-rollback.json`, rolled back the
  route and device, removed the journal, verified no residue, and verified
  unchanged default route and global DNS baselines.
- `maverick tun-helper-rollback --apply` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_HELPER_APPROVED=1`. It consumed a retained
  `/tmp/maverick-rollback-recovery.json` journal, deleted `192.0.2.0/24`,
  deleted `mavtun0`, removed the journal, verified no residue, and verified
  unchanged default route and global DNS baselines.
- `scripts/approved-vm-tun-runtime-smoke.sh` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_RUNTIME_APPROVED=1`. It created a temporary
  namespace, veth pair, namespace-local TUN, namespace policy route,
  namespace-scoped DNS, verified no namespace default route or public internet
  route, ran a namespace-to-host veth TCP echo, rolled back namespace/TUN/veth
  and DNS state, verified no residue, and verified unchanged host default route
  and global DNS baselines.
- `scripts/approved-vm-tun-policy-smoke.sh` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_POLICY_APPROVED=1`. It created a temporary
  namespace, veth pair, namespace-local TUN, namespace-scoped DNS, preserved a
  control-plane route to the host veth peer, added a namespace-local default
  route to the TUN device, verified default-route and DNS probes selected the
  TUN path, verified the preserved control-plane route still carried a TCP echo,
  rolled back namespace/TUN/veth/DNS state, verified no residue, and verified
  unchanged host default route and global DNS baselines.
- `scripts/approved-vm-tun-service-smoke.sh` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_SERVICE_APPROVED=1`. It ran transient systemd
  units for privileged helper success and intentional-failure cleanup paths,
  verified no namespace/link/unit/script residue, and verified unchanged host
  default route and global DNS baselines.
- `scripts/approved-vm-tun-leak-coexistence-smoke.sh` passed on
  `approved-linux-vm` on 2026-06-27 with `MAVERICK_TUN_LEAK_APPROVED=1`. It verified
  namespace default/DNS probes selected the TUN path, preserved control-plane
  routing stayed on veth, TCP echo coexistence worked, host listener baselines
  remained unchanged, rollback completed, no residue remained, and host default
  route/global DNS baselines were unchanged.
- `scripts/approved-vm-tun-full-helper-smoke.sh` passed on `approved-linux-vm` on
  2026-06-27 with `MAVERICK_TUN_FULL_HELPER_APPROVED=1`. It chained the Phase B
  runtime, Phase C policy, service-manager lifecycle, and leak/coexistence
  smokes, then performed an independent final residue check.

## Current Decisions

- `smoltcp 0.13.1` is selected for the unprivileged packet engine. Exact
  selection/rejection evidence and hashes are in
  `docs/TUN_ENGINE_COMPARISON.md`.
- The implemented engine-neutral boundary and current/open synthetic cases are
  recorded in `docs/TUN_PACKET_ADAPTER_CONTRACT.md` and
  `docs/TUN_SYNTHETIC_TEST_MATRIX.md`.
- M6 and M8 Phases 1-2 are closed for their recorded scope. Phase 2 passed an
  approved-host namespace-local IPv4 matrix with private evidence and complete
  cleanup. IPv6 is unscheduled, product-client integration remains open, and
  this acceptance does not authorize another remote run.
- `docs/history/manifests/tun-helper-approval.json` is not a per-run approval and does not name a real
  test host. Real apply runs still require explicit operator approval and a
  separate approved host.
- `docs/history/manifests/tun-runtime-blockers.json` is also not a per-run approval. It records
  `approved-linux-vm` as the host where Phase B and Phase C completed, keeps
  `remote_mutation_allowed=false`, and does not authorize further mutation
  runs.
- `maverick-core` owns route planning, safety-gate decisions, abstract runtime
  action planning, and packet classification only. CLI `tun-plan` is read-only
  reporting over those models. CLI `tun-helper-preflight` is a read-only
  approved-host readiness check, CLI `tun-helper-smoke` is a Phase A Linux
  helper smoke, and CLI `tun-helper-rollback` is a retained-journal recovery
  helper; none of these is the full runtime TUN service. A full TUN device
  runtime should still live in a future platform-specific helper crate or
  binary, with CLI integration as a thin caller.
- GUI/tray approval must not perform privileged mutation directly. It should
  collect explicit operator approval, display the safety-gate blockers, and hand
  off to the future privileged helper only after the core gate allows apply.
