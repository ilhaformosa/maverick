# Reference Client And SDK Boundary Review

Status: boundary review refreshed after the Phase 3 bounded lifecycle and
package gates on 2026-07-13. The Rust SDK exposes the feature-gated unprivileged
packet-runtime boundary and a coarse platform-recovery snapshot. Linux
CLI/service is the first reference-client path, and its separate implementation
uses replaceable helper and packet-runtime adapters. This review does not add
language bindings, start a TUN, or authorize privileged network work.

## Reviewed Material

- `docs/PLAN_POST_V1.md`
- `docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md`
- `docs/TUN_MODE_DESIGN.md`
- `docs/TUN_PACKET_ADAPTER_CONTRACT.md`
- `docs/SDK_PLAN.md`
- `docs/GUI_TRAY_ARCHITECTURE.md`
- `docs/MACOS_APP_BOUNDARY.md`
- `crates/maverick-sdk/src/lib.rs`
- current client TCP, DNS, UDP, H2-pool, lifecycle, and diagnostics interfaces

## Conclusion

The components now represent four different readiness levels that must not be
combined into one claim:

1. the privileged-helper safety baseline can plan and test reversible device,
   route, and DNS operations on approved isolated systems;
2. the default Rust SDK can start and stop the existing local proxy runtime,
   separate profile metadata from secrets, and return redacted diagnostics;
3. the optional `tun-runtime` SDK build can accept caller-supplied packet I/O,
   run the selected packet engine, reuse the real Maverick flow connector, and
   return bounded packet-runtime snapshots;
4. the separate Linux reference client now passes a bounded current-source
   route/DNS, failure, package, and cleanup matrix, while sustained resources,
   power loss, broader transition/leak, and daily-use evidence remain open.

The correct sequence remains engine boundary, unprivileged packet runtime,
approved disposable-system evidence, one reference client, then a narrow
binding or ecosystem adapter justified by that client.

## Drift Found And Resolved In Documentation

### Release-plan authority

The general release checklist still pointed at the completed v1.0 plan. It must
use `docs/PLAN_POST_V1.md` for post-v1 milestones while preserving the old plan
and release train as historical v1.0 evidence.

### Helper readiness versus product readiness

`docs/TUN_MODE_DESIGN.md` describes extensive helper and namespace evidence.
That evidence proves rollback discipline and isolated platform setup, not a
userspace TCP/IP engine or product packet relay. The document now points to the
M8 product sequence and uses helper-specific readiness language.

### GUI platform history versus M8 selection

`docs/GUI_TRAY_ARCHITECTURE.md` records an earlier macOS-first local GUI
baseline. `docs/MACOS_APP_BOUNDARY.md` records how a separate Apple-native app
could consume Maverick. Neither record selects the M8 reference-client
platform. M8 makes that choice only after the packet runtime exists and actual
operator need, test-device access, lifecycle evidence, and packaging cost can
be compared.

### SDK baseline versus packet API

With the `tun-runtime` feature, the SDK exposes `PacketIo`, bounded packet
config/snapshots, `MaverickClient::start_tun_runtime`, and read-only runtime
snapshots. Concrete engine and connector types remain internal. Route apply,
DNS apply, platform handles, and helper commands remain absent, which is the
required Phase 1 boundary rather than product TUN readiness.

## Repository Ownership

| responsibility | Maverick protocol repository | reference-client repository |
| --- | --- | --- |
| wire, auth, replay, carriers, TCP/DNS/UDP frames | owns | consumes |
| packet-engine adapter contract | owns | consumes |
| engine comparison and selected adapter | owns | does not fork |
| SDK lifecycle and redacted diagnostics | owns | wraps |
| profile schema and secret-reference contract | owns shared contract | owns platform storage UX |
| TUN route/apply safety model | owns generic policy | supplies platform implementation |
| platform Packet Tunnel or TUN lifecycle | provides boundary only | owns |
| signing, entitlements, notarization, packaging | does not own | owns |
| product UI and permission workflow | does not own | owns |
| protocol conformance fixtures | owns | runs or imports |

A product client must not parse Maverick frames or reimplement auth. Maverick
must not absorb platform UI, signing, installer, or permission-flow code merely
to make one client easier to build.

## Product Workflow

The minimum reference-client workflow is operational:

```text
import or create profile metadata
    -> store secret through platform secret store
    -> validate profile through Maverick SDK
    -> request connect
    -> platform opens packet flow and applies approved network settings
    -> SDK starts packet engine and Maverick flow connector
    -> display coarse health and recovery state
    -> request disconnect
    -> stop new flows and drain within bound
    -> close packet engine and Maverick pool
    -> roll back platform settings
    -> verify disconnected state
```

The application may display profile name, connection state, policy mode,
coarse transport health, last coarse error class, and recovery requirement. It
does not display target destinations, raw credential ids, packet payloads,
auth details, or internal carrier switches in ordinary mode.

## SDK Surface Review

### Keep now

- `MaverickClient` and `MaverickServer` start/shutdown ownership;
- config parsing and validation helpers;
- builder-style profile construction;
- `StoredClientProfile`, `ProfileSecretRef`, and `ProfileSecretStore`;
- native secret-store boundary without real credential-store writes in tests;
- redacted GUI diagnostics and coarse error classes;
- read-only helper safety and readiness snapshots.

### Added In Phase 1

- caller-supplied `PacketReader` and `PacketWriter` through `PacketIo`;
- feature-gated packet-runtime start, snapshot, and ordered client shutdown;
- engine-neutral bounded configuration and coarse counters;
- build gate `tun-runtime` plus runtime gate `advanced.experimental_tun`;
- default-off behavior and stable-mode rejection.

### Kept Outside The SDK

The selected Linux binding now lives in the separate reference-client project.
Platform packet-flow handles, route/DNS apply, rollback, and recovery commands
remain outside the protocol SDK instead of becoming general SDK authority.

### Added For Phase 3

- `PlatformRecoverySnapshot` maps only coarse helper-journal state;
- reconnect can be blocked while cleanup is required or recovery is running;
- inconsistent helper state is rejected;
- no helper-journal path, command, destination, credential, or raw error is
  exposed through the SDK snapshot.
- `ReferenceClientController` orders preflight, apply, packet-runtime start and
  stop, rollback, and recovery without owning platform commands;
- helper and packet-runtime traits allow deterministic fake-adapter testing
  before any privileged implementation exists.

### Keep internal

- concrete packet-engine types and candidate names;
- `ClientTunnelPool`, H2 request senders, frame types, and auth transcripts;
- route, resolver, firewall, and service-manager commands;
- packet capture callbacks;
- raw destination and packet metadata;
- experimental carrier and cryptography internals.

## Phase 1 API Resolution

`maverick-client` now has a crate-private `MaverickTunConnector`. It opens TCP
through the extracted tunnel-open/stream-relay functions, resolves DNS through
the existing pool path, and opens UDP through `UdpAssociation`.

The extraction:

- reuse one existing pool and flow semaphore;
- expose TCP, DNS, and UDP operations without exposing frames;
- retain current timeout and close/reset behavior;
- let SOCKS5, HTTP CONNECT, DNS listener, and product TUN share the same logic;
- preserves the first-party no-unsafe boundary and includes connector tasks and
  both directions of duplex buffers in the runtime resource snapshot.

It does not make transport, auth, or packet-engine selection an ordinary SDK or
configuration choice. `smoltcp` stays behind the internal packet crate.

## Reference-Client Selection Gate

Phase 2 approved-host IPv4 evidence enabled the platform comparison. Linux
CLI/service is selected in `docs/REFERENCE_CLIENT_SELECTION.md` after scoring
candidates on:

- an explicitly available test device;
- operator need and expected repeated use;
- packet-flow API compatibility with the selected adapter contract;
- secure secret storage;
- connect/disconnect, sleep/resume, network-change, and crash-recovery testability;
- DNS, IPv4, leak, and coexistence testability;
- signing, entitlement, packaging, and update cost;
- ability to keep platform code outside the protocol repository.

The existing Apple-native boundary keeps an Apple client credible, but Linux is
the narrower first evidence path. The selection does not turn one Linux result
into cross-platform readiness.

## Minimum Reference-Client Evidence

- repeated connect/disconnect without stale listeners or packet flows;
- cold start, app restart, engine crash, and forced disconnect recovery;
- sleep/resume and network-interface change;
- IPv4 TCP;
- DNS and supported UDP behavior;
- route and control-plane bypass correctness;
- no traffic or DNS leak under defined failure states;
- secret-store and diagnostic redaction checks;
- install, disable, uninstall, and rollback behavior;
- exact app, SDK, engine, and Maverick revisions in private evidence.

One device passing once is not daily-use or cross-platform evidence.

## Ecosystem Boundary

After one reference client stabilizes the SDK surface, evaluate one external
ecosystem at a time. An adapter is justified only by a real adopter or
maintainer. It must use public SDK or conformance boundaries and must not gain
special access to auth, secret, or packet internals.

Independent implementations and governance work remain later gates. They do
not block the reference client, and the reference client alone does not prove
standardization readiness.

## Review Result

The engine comparison, unprivileged SDK/runtime boundary, recorded Phase 2 IPv4
matrix, first-platform selection, separate Linux implementation, and bounded
current-source lifecycle/package gates are complete. IPv6 was policy-blocked,
was not exercised, and is not scheduled. Sustained resources, power loss,
broader transition/leak, daily use, language bindings, and GUI/app work remain
later work; the bounded Linux result is not a product-readiness claim.
