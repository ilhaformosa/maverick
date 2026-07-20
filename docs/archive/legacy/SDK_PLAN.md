# SDK Plan

Status: v4 Rust SDK baseline implemented. The SDK exposes client/server
start-stop wrappers, config parsing helpers, builder-style Rust profiles, and
a GUI-facing local client lifecycle wrapper. Language bindings and actual GUI
applications remain future work. Product TUN SDK sequencing and the completed
boundary review are in `docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md` and
`docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`. The cross-repository boundary
for a separate macOS app is captured in `docs/MACOS_APP_BOUNDARY.md`. The
optional `tun-runtime` feature now exposes the unprivileged Phase 1 packet I/O,
config, snapshot, lifecycle, and coarse helper-journal recovery boundary; it
does not expose platform setup.

The SDK should expose Maverick as a library for applications that want embedded
local proxy behavior without depending on CLI process management.

## Goals

- Keep protocol behavior shared with the existing client/server crates.
- Provide a small stable API before exposing advanced internals.
- Preserve config validation and secret redaction.
- Make test fixtures reusable by downstream implementations.

## Initial Rust API

Current crate layout:

```text
crates/maverick-sdk
  src/lib.rs
```

Public API:

```rust
let config = client_config_from_yaml(input)?;
let client = MaverickClient::start(config).await?;
client.shutdown().await?;

let config = client_config_builder()
    .server_address("127.0.0.1:443")
    .server_name("localhost")
    .credential("u_example", SecretString::generate())
    .build()?;

let mut gui_runtime = GuiClientRuntime::new("primary", config)?;
gui_runtime.connect().await?;
let snapshot = gui_runtime.diagnostics();
gui_runtime.disconnect().await?;

// With feature `tun-runtime` and advanced.experimental_tun=true:
let mut packet_client = MaverickClient::start(packet_config_with_gate).await?;
packet_client
    .start_tun_runtime(packet_runtime_config, packet_io)
    .await?;
let packet_snapshot = packet_client.tun_runtime_snapshot();
packet_client.shutdown().await?;
```

Implemented:

- `MaverickClient::start` and `shutdown`;
- `MaverickServer::start` and `shutdown`;
- `local_addr` accessors for loopback runtime tests;
- `client_config_from_yaml` and `server_config_from_yaml`;
- `ClientConfigBuilder` and `ServerConfigBuilder`;
- `GuiClientRuntime` for GUI-facing local client connect, disconnect,
  diagnostics, idempotent shutdown, and loopback listener cleanup;
- `StoredClientProfile`, `ProfileSecretRef`, and `ProfileSecretStore` for
  separating serializable profile metadata from raw active and next credential
  secrets;
- `NativeProfileSecretStore` for platform secure storage integration, with
  tests that avoid touching the user's real Keychain;
- shared exports for GUI diagnostics, GUI TUN safety, and runtime-readiness
  snapshot types;
- shared exports for common config types;
- optional `PacketIo`, packet config/snapshot, runtime start, and snapshot APIs
  behind `tun-runtime`;
- ordered client shutdown of packet flows, connector tasks, and the shared H2
  pool.
- `PlatformRecoverySnapshot` for clean, cleanup-required, and recovering
  states without exposing helper paths or raw platform errors.
- versioned bounded JSON request/response types for a future local platform
  helper, with fixed operations and journal location.
- `ReferenceClientController` plus replaceable helper/packet-runtime traits for
  ordered, unprivileged lifecycle and recovery orchestration.

## Boundaries

The SDK should not expose:

- raw secrets through Debug;
- direct transport selection for ordinary callers;
- pre-auth protocol error details;
- system TUN setup before the TUN safety model exists;
- concrete packet-engine, flow-connector, route, DNS, firewall, or helper
  command types;
- raw profile secrets in serialized GUI profile metadata.

## Future Language Bindings

Potential bindings after the Rust SDK and one reference-client need stabilize:

- Swift for macOS/iOS UI integration;
- Kotlin for Android UI integration;
- C ABI for simple desktop wrappers.

Bindings should wrap the Rust SDK rather than reimplementing protocol logic.
The narrow Phase 2 IPv4 evidence exists and Linux CLI/service is the selected
first reference-client path. No language binding is selected until that client
creates a real integration need.

## Tests

- SDK starts a loopback SOCKS5 client with generated config.
- SDK validates configs identically to CLI.
- SDK shutdown releases listeners.
- SDK logs remain redacted.
- GUI-facing SDK lifecycle diagnostics omit raw secrets, full credential ids,
  and server addresses.

Implemented:

- loopback client start/stop test;
- loopback server start/stop test with generated test certificate;
- SDK client/server builder tests;
- GUI client runtime lifecycle and idempotent disconnect tests;
- stored client profile tests proving active and next credential secrets remain
  out of serialized metadata and require a secret store for materialization;
- native profile secret store construction tests that do not touch the system
  credential store;
- GUI TUN safety diagnostics tests proving core TUN readiness is read-only and
  does not enable GUI apply or local-machine network mutation;
- headless GUI runtime smoke script covering lifecycle, profile storage
  contract, redacted diagnostics, read-only TUN state, and blocker metadata;
- config parsing error test;
- secret-redaction sanity test for SDK-local errors.
- feature-gated packet-runtime gate and real Maverick TCP/DNS/UDP loopback
  integration tests.
- platform recovery-state consistency, reconnect blocking, and serialization
  redaction tests.
- platform-helper IPC version, size, identifier, path, operation, unknown-field,
  coarse-error, and outcome/recovery consistency tests.
- reference-client repeated lifecycle, retained-journal recovery, startup and
  shutdown failure, rollback failure, invalid transition, response matching,
  and diagnostic-redaction tests.
