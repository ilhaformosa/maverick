# macOS App Boundary

Status: planning boundary for the separate Atlas macOS app.

This document describes a possible Apple-native consumer. It does not select
the M8 reference-client platform; that decision waits for the product packet
runtime and the gate in `docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`.

Maverick remains the protocol and reference-runtime repository. Atlas should be
a separate Apple-native product repository that consumes Maverick through a
small SDK or FFI boundary instead of reimplementing protocol behavior.

## Repository Ownership

`maverick` owns:

- wire format, authentication, replay, padding, DNS, TCP, UDP, and transport
  behavior;
- reference client/server runtimes and loopback integration tests;
- `maverick-sdk` lifecycle, config parsing, diagnostics, profile metadata, and
  secret-redaction contracts;
- conformance vectors and verifier expectations for downstream clients;
- blocker manifests for protocol readiness, experimental transports, TUN, and
  ECH.

`atlas` owns:

- SwiftUI application UI, menu bar behavior, settings, and product workflows;
- macOS Network Extension lifecycle and `NEPacketTunnelProvider` integration;
- App Group files, Keychain access, app/extension IPC, signing, notarization,
  packaging, and installer/update mechanics;
- local profile import/export UI and user-facing diagnostics;
- test-device Packet Tunnel QA once explicitly approved.

Atlas must not fork or silently modify Maverick protocol semantics. If Atlas
needs protocol behavior that is missing, the behavior should be added to
Maverick first and exposed through the SDK, C ABI, or conformance vectors.

## Non-Overlap Rule

The GUI/tray code in this repository is not the product macOS app. It is a
headless SDK and diagnostics contract that future apps can consume.

Maverick GUI-facing code may expose:

- local client start/stop lifecycle helpers;
- profile metadata and secret-store contracts;
- redacted diagnostics and runtime-readiness snapshots;
- read-only TUN safety state;
- conformance fixtures for app-side import and validation tests.

Maverick GUI-facing code must not own:

- SwiftUI layout;
- macOS Packet Tunnel preferences;
- app signing, notarization, packaging, or auto-update;
- user onboarding, menu bar UX, or platform-specific permission flows.

## Integration Phases

### Phase 0: Local-Safe App Shell

Atlas may run as a local-safe SwiftUI app that controls a loopback Maverick
client or simulation mode only. This phase must not mutate system proxy, DNS,
route, firewall, VPN, Network Extension preferences, or other local
network-service state on the primary development Mac.

Expected evidence:

- SwiftUI app builds and tests with SwiftPM;
- profile metadata is saved without raw secrets;
- diagnostics are redacted;
- local connect/disconnect is simulated or loopback-only;
- no real Packet Tunnel is installed or started.

### Phase 1: SDK/FFI Candidate

Maverick should expose a small stable SDK or C ABI surface for Atlas:

- parse and validate client profiles;
- start and stop local client runtimes;
- return redacted diagnostics;
- materialize runtime config only after secrets are supplied by the app;
- report coarse error classes suitable for UI.

Swift should wrap this boundary. It should not parse raw protocol frames or
reimplement authentication logic.

### Phase 2: Packet Tunnel Test Device

Real `NEPacketTunnelProvider` paths belong on a dedicated test Mac or explicitly
approved test device. This phase may install VPN preferences, start/stop a
Packet Tunnel, apply network settings, and run leak/coexistence tests only after
the target device is confirmed.

The primary development Mac remains off limits for real system-network mutation.

### Phase 3: Release Packaging

Release work belongs to Atlas:

- Developer ID signing;
- notarization;
- app/extension entitlements;
- packaged installer or update path;
- troubleshooting and privacy-policy drafts.

Maverick release gates still apply to protocol claims. Atlas packaging does not
turn experimental Maverick behavior into a stable security claim.

## Current Readiness

Atlas can continue private local-safe Phase 0 work because Maverick already has
SDK lifecycle scaffolding, profile metadata separation, redacted diagnostics,
TUN safety diagnostics, and conformance vectors. This does not make Atlas the
selected Maverick reference client and does not authorize product TUN or Packet
Tunnel operation.

Atlas should not be presented as a production VPN client yet. Native
server-side ECH remains blocked on TLS-stack support, and GUI release gates
still include signing/notarization and packaging.

## Adapter Policy

Maverick support is the first-class path. Other open-source protocols may be
added later through explicit adapters, but Atlas should not reimplement many
protocols in Swift. Prefer a reviewed engine boundary, compatible licenses,
and separate adapter tests.

Protocol adapters must preserve the same safety defaults:

- no raw secrets in exported profiles;
- redacted diagnostics by default;
- no system-network mutation without explicit test-device approval;
- no unsupported experimental feature exposed as an ordinary user option.
