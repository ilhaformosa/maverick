# Outer TLS ClientHello record experiment

Date: 2026-11-17
Status: local experiment; no product feature or default change.

This is the initial two-layout snapshot. Subsequent owner-authorized local
development adds feedback, an SNI-position split and QUIC observation; see
[the current experiment report](HANDSHAKE_EXPERIMENTS.md). The original source
is preserved as `runtime-evidence/tls-clienthello-20261117/initial-tls_record_fragmentation.rs`
with the SHA-256 recorded below. The current test command exercises the expanded
matrix; the initial counts below are not relabeled as later results.

## Question and scope

Can the existing Maverick H2 client and server complete verified TLS,
exporter-bound authentication and bidirectional TCP forwarding when the first
ClientHello is split across two TLS records?

The owner authorized this independent local experiment after reviewing
[CircumVolve](https://gfw.report/publications/ccs26/en/). The experiment uses
the product runtime from base `a5b01daad2bae98d264d89bbad964e847fb82a1b`
without modifying its implementation, configuration, dependencies or defaults.
This does not unfreeze protocol/SDK development or authorize field tests.

## Method

The dedicated integration target is
[`tls_record_fragmentation.rs`](../crates/maverick-tests/tests/tls_record_fragmentation.rs).
It reuses `MaverickHarness`, the product `ProxyConnector`, the existing
ClientHello parser and server resource metrics. All network endpoints use
`127.0.0.1` and OS-assigned ports. Certificates and credentials are generated
for the test; no external hostname is resolved. Neither host networking nor
Surge is configured.

Both the reference and candidate use the same test-only transparent TCP relay:

```text
ordinary Maverick H2 client -> loopback record relay -> ordinary Maverick server
                                                     -> loopback TCP target
```

The reference forwards the initial record byte-for-byte. The candidate splits
its payload after two bytes, inside the four-byte TLS handshake header, into
records of length `2` and `N - 2`. Content type and record version are preserved.
The relay does not terminate TLS, possess its session secrets, or generate a
replacement ClientHello. All subsequent traffic passes unchanged.

For every connection, the relay reconstructs the outgoing handshake and checks
exact equality with the incoming bytes, including random values and key shares.
It also parses both representations and requires identical observations apart
from record lengths. Raw handshake bytes remain in memory; output contains only
case labels, lengths, counts and results. Independent handshakes can differ due
to TLS randomness, GREASE and extension permutation; equality is checked within
each connection, not between separate reference/candidate connections.

This narrow fixture requires one complete initial ClientHello record of at most
16384 payload bytes. Unsupported input fails explicitly. It is not a reusable
production record transformer and makes no assertion about TCP packet boundaries.
TLS permits handshake fragmentation subject to its record rules; record headers
are outside the handshake transcript ([RFC 8446 sections 5.1 and 4.4.1](https://www.rfc-editor.org/rfc/rfc8446.html)).

## Coverage and initial focused result

The first focused run passed both integration tests. The matrix covers browser
TLS (BoringSSL) and explicit rustls, authentication v1/v2, and unchanged/split
records: eight successful configurations and 32 independent rejection cases.
Every successful configuration requires a valid certificate chain, hostname,
leaf pin and TLS exporter-bound authentication, using fixed H2 with no automatic
carrier fallback.

| Observation | Unchanged | Split after two bytes |
|---|---:|---:|
| Successful backend/auth configurations | 4/4 | 4/4 |
| Complete verified transfers | 12/12 | 12/12 |
| Verified data per direction, across these transfers | 6 MiB | 6 MiB |
| Target-admitted sessions cancelled and released | 4/4 | 4/4 |
| Wrong CA/name/pin/credential cases rejected | 16/16 | 16/16 |
| Target connections from rejected cases | 0 | 0 |
| Additional bytes per initial handshake | 0 | 5 |

Each successful configuration uses one physical H2 connection for three full
transfers and one cancelled session. Each full transfer verifies distinct
512 KiB payloads in both directions. One transfer runs both directions
concurrently; the other two enforce client-first and target-first half-close.
Pool counts confirm connection reuse. After close, server active connections,
flows, pre-authentication work and fallback work reach zero; the relay completes
and its listener address can be rebound.

The initial successful rustls handshakes had record payload length 1462;
fragmented output was `[2, 1460]`. Browser-profile lengths varied, with 1707 and
1771 observed in successful configurations. These lengths describe this run,
not stable browser fingerprints or required future packet sizes.

## Reproduction and verification

Use the pinned Rust 1.100.0 toolchain and existing cached dependencies:

```sh
CARGO_NET_OFFLINE=true cargo test --locked -p maverick-tests \
  --test tls_record_fragmentation -- --nocapture --test-threads=1
```

The test also runs through the existing workspace suite. The required broader
local verification entry is:

```sh
CARGO_NET_OFFLINE=true ./scripts/local-harness.sh
```

The full local harness passed on native Apple Silicon macOS with Rust 1.100.0:
formatting, strict workspace Clippy, 784 workspace tests (three existing
historical process-matrix cases ignored), the SDK example, explicit rustls
compatibility build, fixed-H2 configuration checks, product smoke and the
existing isolated shell/release/privacy checks. The product smoke separately
passed correct/wrong credentials, TCP forwarding and reliable UDP forwarding.
No CI, Linux execution or release-artifact qualification was performed.

The tested experiment source SHA-256 is
`ff6af853d7b915ea19e63533a081544d581373c49e5a31ce88df256dc8ceb22b`.
Local logs and a verification manifest are retained in the ignored
`runtime-evidence/tls-clienthello-20261117/` directory; logs are private working
evidence and are not publication artifacts. The initial focused run completed
in approximately three seconds after compilation; this is test duration, not
a transport performance comparison.

## Meaning and limits

The experiment establishes local interoperability of this record split with
Maverick's actual H2 TLS/authentication/forwarding path. It preserves ordinary
identity and credential rejection in the tested matrix.

It does not establish censorship evasion, browser equivalence, better latency
or throughput, production transformer correctness, H3 behavior, or compatibility
with a real terminating intermediary. No DPI simulator or real-network test was
run. The five-byte overhead is a TLS byte-stream measurement, not a claim about
additional network packets. No secret logging or packet-capture export was used.

The current product and published RC.6 remain unchanged. Any future product
integration or authorized-network experiment needs a separately scoped decision
and its own applicable verification; this result adds no Stable release gate.
