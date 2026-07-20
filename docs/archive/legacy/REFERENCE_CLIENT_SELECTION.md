# Reference Client Selection

Status: Linux CLI/service selected as the first experimental IPv4 reference
client path for `v1.2.0`.

This decision selects one narrow evidence path. It does not claim production,
cross-platform, GUI, mobile, IPv6, anonymity, censorship-resistance, or formal
security-audit readiness. It does not authorize network changes on the
development Mac or any remote system.

## Decision

The first reference client will be a Linux CLI plus optional service wrapper
that consumes the Maverick Rust SDK and a narrow privileged helper. Product UI,
platform setup, packaging, and service-manager code remain outside the
Maverick protocol repository.

## Candidate Comparison

| candidate | strengths | current blockers | result |
| --- | --- | --- | --- |
| Linux CLI/service | Rust-native integration, direct packet-stream fit, isolated namespace testing, disposable test-system path | power-loss, broader transition leak/coexistence, sustained-use, production credential-root, package-publication, and daily-use evidence still needed | selected and in progress |
| macOS app/Packet Tunnel | strong native UX and secure storage, existing boundary document | Network Extension entitlement, signing, separate app integration, dedicated test device | retained for later |
| mobile app | useful long-term product path | two platform stacks, store/signing work, larger lifecycle surface | deferred |

Linux wins the first slice because it produces the missing lifecycle evidence
with the least new platform machinery and without requiring system-network
changes on the development Mac. This is a sequencing decision, not a statement
that Linux is the final or only product platform.

## Ownership Boundary

Maverick owns:

- protocol, auth, frames, carriers, packet-runtime contract, and conformance;
- Rust SDK lifecycle, profile/secret-reference contract, diagnostics, resource
  snapshots, and coarse platform recovery state;
- loopback and unprivileged integration tests.

The reference client owns:

- TUN opening and packet-handle adaptation;
- privileged helper IPC, route/DNS apply, journal, rollback, and recovery;
- service-manager integration, packaging, installation, updates, and uninstall;
- platform leak, coexistence, sleep/resume, crash, and daily-use evidence.

The helper receives no Maverick credentials, payloads, or destination logs. The
ordinary client UI receives no raw packet, auth, carrier, or helper-command
details.

## First Implementation Slices

1. Add a coarse SDK recovery snapshot that reports reconnect as disallowed
   while a retained helper journal requires cleanup.
2. Freeze a versioned local IPC request/response schema with strict path,
   operation, and size limits. Complete in `maverick-sdk`.
3. Build an unprivileged Linux client controller against fake packet/helper
   adapters. Complete in `maverick-sdk`.
4. Add the real Linux helper in the separate reference-client project with
   authenticated bounded IPC, journal-first apply, idempotent rollback, and a
   default-off platform-mutation gate. Complete for the current IPv4 design.
5. Run privileged lifecycle, leak, DNS, route, crash, residue, and uninstall
   tests only on an explicitly approved disposable test system. Earlier
   global-capture revisions passed bounded layers, but a sustained attempt
   exposed management-route interference. The corrected capture UID, fallback
   guard, isolated DNS, transient-unit, and rollback-lock implementation passes
   local and bounded privileged gates. Root-only fixed-name systemd-credential
   import and the affected current-package transaction/signing matrix also pass;
   production credential-root, sustained, power-loss, and broader-transition
   evidence remains open.
6. The bounded package lifecycle is complete. Collect sustained and repeated-use
   evidence before considering a `v1.2.0` stable tag.

## Release Gate

The selected client remains experimental until all Phase 3 evidence in
`docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md` passes. A single namespace run is not
daily-use evidence, one Linux system is not cross-platform support, and no
fixed wait substitutes for an active test or deployment that produces data.
