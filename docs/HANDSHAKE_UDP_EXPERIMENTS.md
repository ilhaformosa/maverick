# UDP coverage through handshake candidates

Date: 2026-11-17
Status: local test follow-up; product behavior remains unchanged.

## Concrete gap

The first [handshake experiments](HANDSHAKE_EXPERIMENTS.md) verified TCP tunnels.
The owner requested committing that work and continuing Maverick improvements.
This follow-up closes the explicitly recorded UDP coverage gap using the same
product connector, existing test relays, generated trust and auth v1/v2. The
first delivery is tracked in [PR #118](https://github.com/ilhaformosa/maverick/pull/118).

All traffic stays on numeric loopback addresses and ephemeral ports. There is
no product option, default change, field test, host/Surge configuration change,
application-data replay or new transport implementation.

## Matrix and assertions

| Path | Matrix | UDP sessions |
|---|---|---:|
| H2 reliable UDP | browser TLS/rustls x auth v1/v2 x unchanged/two-byte/SNI split; explicit close and caller cancellation reuse one H2 connection | 24 |
| H3 native UDP | auth v1/v2 x unchanged/reversed first flight x intact/one missing Initial x explicit close/caller cancellation | 16 |

H2 uses explicit `allow_reliable`; H3 uses `native_required`. Every session
asserts its actual carrier. Both paths retain the real certificate, hostname,
pin and exporter-bound authentication checks before session setup.

For each session the shared helper:

1. Rejects an upload one byte above the advertised packet limit.
2. Sends four verified uploads: empty, one byte, up to 1024 bytes and the
   advertised maximum. All arrive from the same target-facing source port.
3. Sends five independent target replies after those uploads, including empty,
   one-byte and maximum-size packets; verifies their complete content.
4. Checks that no extra upload or replay arrived at the target.
5. Either closes explicitly or drops the session, then verifies the target-facing
   source socket can be rebound. Existing server resource counters drain and
   the test relay releases its listener. H2 also verifies connection reuse and
   release of both logical streams.

The focused run passed all 40 sessions. Advertised maxima were 65507 bytes for
H2 and 1200 bytes for H3 in this fixture. Native UDP packets are consumed one at
a time in this loss-free application phase; the tests do not impose reliability
or ordering guarantees on the native protocol. H3 loss injection affects only
the original handshake packet, and the existing Initial observers confirm
reconstruction through ordinary quiche retransmission.

Maximum-size replies require a larger UDP send buffer than macOS ordinarily
provides. The helper uses `socket2` to size only its own test target socket to
131072 bytes in each direction. That package/version was already locked and
used by the product; the test-only dependency edge is the sole lockfile change.
No package version or product dependency changes.

## Verification and reproduction

```sh
CARGO_NET_OFFLINE=true cargo test --locked -p maverick-tests \
  --features experimental-h3 --test tls_record_fragmentation \
  --test quic_initial_layout udp -- --nocapture --test-threads=1
CARGO_NET_OFFLINE=true ./scripts/check.sh
```

The additional tests run in the existing product/rustls/H3 entries. Prior TCP,
parser-control, RFC-vector, authentication and failure checks remain required.
Local product, rustls, H3 and retained-quiche checks are complete on native Apple
Silicon with Rust 1.100.0. The product workspace passed 786 tests with three
existing historical cases ignored. The expanded TLS target passed with and
without browser TLS; the QUIC target passed all five tests. Formatting and
strict Clippy passed. Existing assertions and deadlines remain unchanged.

The first complete-entry run passed product/rustls, then stopped in an existing
SDK no-downgrade test with `Address already in use`. The old error did not identify
the bind operation. Test-only setup contexts were added; the 17-test SDK group
and complete H3 gate then passed, followed by the retained-quiche gate. The
specific conflicting bind and its cause were not reproduced, so no runtime fix
or root-cause claim is made. The failure and follow-up evidence are retained.
The H3 gate's final dependency metadata predicate was additionally checked with
its own captured successful result. Local evidence is preserved privately under
ignored `runtime-evidence/handshake-udp-20261117/`.

These results cover direct H2/H3 through the test relays. They do not qualify a
real intermediary, a production fragmentation adapter, field censorship
resistance, throughput or latency. The published RC.6 checkpoint is unchanged.
