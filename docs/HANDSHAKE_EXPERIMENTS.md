# Local handshake experiments and feedback

Date: 2026-11-17
Status: test-side development; default product behavior remains unchanged.

The subsequent [UDP coverage follow-up](HANDSHAKE_UDP_EXPERIMENTS.md) extends
these same relays to persistent reliable/native UDP. Counts and source-bound
observations below describe the first-stage TCP delivery.

## Authorized scope

The owner authorized development of three bounded directions: empirical
candidate feedback, outer TLS record fragmentation, and observation followed by
a selected QUIC handshake-layout candidate. The previous loopback-only boundary
continues. No field environment, system networking change, paid model call,
automatic runtime search, new production option or release is included.

All network tests use generated test trust/credentials, numeric loopback
addresses and ephemeral ports. Only the test package, shared test fixtures,
existing check entry points and documentation change. The H3 test feature uses
the already locked BoringSSL dependency for Initial observation. No new package,
product dependency, private quiche patch or session-key logging is introduced.

The runtime base remains `a5b01daad2bae98d264d89bbad964e847fb82a1b`.
The earlier fixed-two-byte TLS experiment is recorded separately in
[the initial report](TLS_CLIENTHELLO_RECORD_EXPERIMENT.md). Its original source
and logs are retained; current experiment source extends that snapshot.

## Feedback driven by explicit observations

The TLS test uses a deliberately simplified local inspection model that blocks
an SNI-bearing ClientHello when its parser can read it. It is not OpenGFW and
does not represent a named deployed censor.

1. Reproduce the unchanged ClientHello's rejection by a first-record-only parser.
2. Only after that observation, evaluate the two bounded fragmentation candidates.
3. Require certificate/name/pin verification, exporter-bound authentication,
   actual target admission and verified duplex data before reporting success.
4. Repeat against a control that reassembles records. That control must block
   both candidates, showing the exact limitation of the successful result.

The candidate cannot edit the evaluator or the identity rules. The test prints
JSON containing the candidate, parser model, decision, record lengths, complete
session result, verified byte count and resource-drain result. Unexpected
failure after a model permits a connection fails the test; it is not scored as
an evasion. This is a fixed hypothesis-driven experiment, not autonomous search.

Both TLS backends passed the ten-case feedback matrix: two unchanged baselines
blocked, four candidate sessions completed, and four reassembly controls blocked.
This supplies local causal feedback while explicitly setting
`real_censor_evidence: false` in the report.

## TLS candidates and compatibility

The transparent TCP test relay offers unchanged records, a split after the first
two handshake bytes, and a split inside the actual SNI hostname. The latter
locates the extension in each generated ClientHello, accommodating extension
permutation. Both candidates preserve the entire handshake byte sequence and
record content type/version, adding exactly one five-byte record header. The
relay neither terminates TLS nor alters subsequent encrypted traffic.

The successful compatibility matrix covers two backends (browser TLS/rustls),
auth v1/v2 and all three layouts: 12 configurations. Each performs concurrent
duplex transfer, both forced half-close orders and an admitted-session
cancellation, using one pooled H2 connection. Each completed flow verifies
512 KiB in each direction. All 48 wrong-CA/name/pin/credential combinations
reject without opening the target. Resource and listener release are checked.

The transformer remains a bounded test fixture requiring a complete initial
ClientHello in one incoming TLS record. It is not a production I/O adapter.
Only TLS record boundaries are controlled; TCP packet boundaries are not claimed.

## QUIC: observe before changing

The first corrected product observation found a 1791-byte ClientHello already
distributed over two 1200-byte UDP datagrams. CRYPTO ranges were `(0, 1137)` and
`(1137, 654)`. The second protected packet was 718 bytes, followed by 482 zero
bytes added by quiche at the datagram level. Handshake lengths and SNI positions
vary between runs; these numbers describe that observation only.

The retained historical outer-packet parser rejected the trailing zeros as an
invalid next packet. That caused the first observation harness to stop and the
client to see a network failure. The diagnostic and original failures remain in
the local evidence. The new test adapter parses the declared packet boundary,
validates the zero suffix separately and records its length. The historical
strict parser and product runtime are unchanged.

The observer uses RFC 9001 public Initial key derivation and the existing
BoringSSL HKDF/AES primitives. It observes only client QUIC v1 Initials, bounded
to 16 datagrams and 16 KiB of reassembled handshake data. It does not inspect
Handshake/1-RTT ciphertext or obtain TLS session secrets. Its known-answer test
uses the public RFC 9001 Appendix A.2 packet, checks CRYPTO offset/length, packet
number and SNI location, and rejects corruption/truncation. A zero-suffix case
covers the concrete quiche padding mismatch. The observer deliberately excludes
Retry, other versions and coalesced non-Initial packets in this first flight.

## Selected QUIC candidate

The observed natural fragmentation made another packet-rewriting mechanism
unnecessary for this stage. The selected candidate buffers the first two
existing client datagrams and emits them in reverse order. It changes no packet
byte, size, number, CRYPTO contents or cryptography. It adds no artificial timer,
but must wait for the second datagram; no latency improvement is claimed.
An unsupported first-flight shape fails the experiment rather than silently
leaving the candidate unapplied.

Separate ingress and delivery observers reassemble ClientHello and require
identical SHA-256 values in memory; the digest, raw bytes, connection IDs and
names are omitted from JSON output. Emission order is checked explicitly.
This measures relay emission, not a universal statement about network arrival
ordering.

The unchanged/reversed comparison passed:

- 12 full-session cases: both auth versions, duplex and both half-close orders.
- Four loss-recovery cases: each layout/auth pair drops original packet 0 once,
  then forwards ordinary quiche retransmissions. The delivery observer verifies
  complete reconstruction and later packet numbers before full transfer succeeds.
- 16 identity/credential rejection cases, with zero target access.
- Server-resource drain and UDP relay listener release in every case.

Retransmission can alter CRYPTO boundaries: one observed recovery carried
`(0, 1131)` and then `(1131, 6)`. The observer reassembles ranges rather than
assuming a lost datagram is retransmitted byte-for-byte. The candidate changes
only the original two-datagram flight; recovery remains entirely quiche-owned.

These results establish local H3 interoperability, not better censorship
resistance. In particular, reversing fragments does not encrypt SNI or defeat
a parser that reassembles the handshake correctly.

## Reproduction and gates

```sh
CARGO_NET_OFFLINE=true cargo test --locked -p maverick-tests \
  --test tls_record_fragmentation -- --nocapture --test-threads=1
CARGO_NET_OFFLINE=true cargo test --locked -p maverick-tests \
  --features experimental-h3 --test quic_initial_layout \
  -- --nocapture --test-threads=1
CARGO_NET_OFFLINE=true ./scripts/check.sh
```

TLS runs in the existing product workspace suite and explicit rustls gate.
QUIC runs in the existing H3 gate, including strict Clippy for that test target.
The shared transfer/resource checks retain actual full-session assertions.
No existing check, failure threshold or ignored-test policy is weakened.

The complete `scripts/check.sh` passed on native Apple Silicon macOS with Rust
1.100.0: product, explicit rustls, H3 and retained quiche-candidate gates. The
product workspace suite passed 785 tests with three existing historical cases
ignored. All three new TLS tests also passed without default features; all four
new QUIC tests and their strict Clippy check passed in the H3 gate. Existing
SDK, native UDP, product smoke, compatibility and historical-fixture checks
remain intact. Candidate traffic assertions in this first-stage delivery use
TCP tunnels; the later UDP follow-up supplies its own results through the relays.

Logs, including the initial observer failures, are retained privately under ignored
`runtime-evidence/handshake-experiments-20261117/`. They are not publication
artifacts. The verification manifest records the base revision, exact source
hashes, log hashes and gate result. No CI, Linux execution, field performance or
release qualification is implied. This first stage changed no runtime or
dependency-lock file; the later UDP follow-up adds only a test dependency edge
to the already locked socket2 package.

## Product decision

Keep both mechanisms test-only for now. The useful delivered result is a
repeatable way to select and reject candidates using full-session evidence,
plus the observation that the current QUIC handshake already fragments.
Product integration needs evidence of a concrete benefit and a scoped design
for that use; a successful local parsing model alone does not justify changing
the default transport or weakening identity/fallback rules.
