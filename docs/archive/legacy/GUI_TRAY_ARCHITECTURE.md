# GUI and Tray Architecture

Status: v4 design complete. A reusable redacted diagnostics snapshot model and
GUI/tray runtime-readiness snapshot are implemented in `maverick-core`,
including debug-only transport diagnostics. The initial UI scope and
macOS-first platform target are decided, and the Rust SDK now exposes a
GUI-facing local client lifecycle wrapper. These gates are tracked in
`docs/history/manifests/gui-runtime-blockers.json`; actual GUI/tray applications remain future work.
This is the earlier local-safe GUI baseline, not the M8 reference-client
selection. The active sequence and boundary review are in
`docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md` and
`docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`. The separate macOS app boundary
is defined in `docs/MACOS_APP_BOUNDARY.md`.

The GUI/tray should be a control surface for existing safe local modes first,
not a separate protocol implementation.

Earlier local-safe baseline target:

- macOS-first;
- local Maverick loopback client control only;
- no system proxy, DNS, route, firewall, VPN, or other network-service settings privileged TUN
  mutation;
- cross-platform GUI work deferred until macOS storage, lifecycle, and smoke
  gates are implemented.

## Goals

- Start, stop, and observe the local Maverick client.
- Import/export redacted profiles.
- Show connection health without exposing destination metadata by default.
- Keep advanced transports and privacy internals out of ordinary user choices.

## First Screen

The first usable view should be operational:

- connection state;
- selected profile name;
- local SOCKS5 address;
- optional DNS and HTTP CONNECT listener state;
- last coarse error class;
- start/stop control.

No marketing landing page is needed for the product app.

## Process Model

Preferred model:

- GUI process owns presentation and secure profile storage;
- embedded SDK or child process owns networking;
- privileged TUN helper is separate and unavailable until TUN mode is ready;
- logs are redacted before crossing into UI.

## Tray Menu

Minimum tray actions:

- connect/disconnect;
- open main window;
- copy SOCKS5 address;
- import profile;
- show diagnostics;
- quit.

## Privacy Defaults

- Do not show target hosts in the main UI by default.
- Do not show payload sizes in normal mode.
- Redact credential ids except short display aliases.
- Require explicit debug mode for verbose local diagnostics.

## Tests

- UI can start and stop a loopback client.
- Profile import rejects invalid secrets.
- Disconnect releases local listeners.
- Diagnostics omit secrets, server address, and full credential ids.
- TUN controls remain disabled unless the platform safety gate is satisfied.

Implemented baseline:

- `GuiDiagnosticsSnapshot` carries first-screen operational state without
  target host metadata.
- First-screen state includes the user-facing policy mode and coarse transport
  status, not H2/H3 transport choices.
- `GuiTransportDebugSnapshot` is an explicit debug-only payload for active
  transport, H2 fallback, H3 candidate enablement, and cooldown state.
- `GuiRuntimeReadinessSnapshot` records completed core diagnostics, SDK runtime
  baseline, redaction-test baselines, UI scope decision, macOS-first platform
  target, and SDK service lifecycle integration while keeping product runtime
  blockers explicit.
- `GuiClientRuntime` in `maverick-sdk` starts, stops, observes, and cleans up
  a loopback-only local client for future GUI integration.
- `StoredClientProfile` in `maverick-sdk` separates serializable profile
  metadata from raw active and next credential secrets through a
  `ProfileSecretStore` contract.
- `NativeProfileSecretStore` in `maverick-sdk` provides the platform
  credential-store backend for future macOS GUI profile secrets; local tests
  avoid writing the user's Keychain.
- `GuiTunSafetySnapshot` consumes core TUN runtime readiness as read-only GUI
  state while keeping GUI controls, GUI apply, and local-machine mutation
  disabled.
- `scripts/gui-runtime-smoke.sh` runs a headless local GUI runtime smoke over
  the SDK lifecycle, profile storage contract, redacted diagnostics, read-only
  TUN state, and GUI blocker manifest.
- Credential ids are redacted through the shared `redact_id` helper.
- Unit tests verify ordinary output omits secret strings, full credential ids,
  server addresses, H2/H3 labels, and cooldown details.

## Runtime Readiness

`GuiRuntimeReadinessSnapshot` is not runtime-ready today. Completed decisions:

- UI scope decision: local Maverick loopback client control surface;
- platform target decision: macOS-first;
- secure profile storage: metadata/secret separation plus native credential
  store backend;
- service lifecycle integration: SDK-level local client start, stop,
  diagnostics, idempotent disconnect, and listener cleanup.
- TUN safety integration: read-only core readiness is exposed to GUI
  diagnostics while GUI apply remains disabled.
- UI smoke tests: headless local smoke over the GUI-facing SDK runtime and
  diagnostics contract.

Remaining blockers:

- signing and notarization;
- release packaging.
