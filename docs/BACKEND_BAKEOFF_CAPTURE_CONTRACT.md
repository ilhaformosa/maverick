# B-001 Common QUIC Initial Observation Contract

Date: 2026-08-12
Status: **first observation-contract/parser slice implemented locally; three-subject observation remains RED**

## Result and boundary

This document freezes the smallest common, local-only observation contract for
the later Quinn and quiche bakeoff, with Chrome as the reference subject. Chrome
is not a selectable backend. This slice does not select a backend, run a
capture, compare a fingerprint, or complete B-001. The current-main preflight
must fail before any network work because no common Quinn observer adapter is
implemented, the quiche candidate has no adapter there, and the legacy Chrome
lab explicitly disables QUIC.

This slice adds no QUIC implementation, parser dependency, product API, wire
behavior, config, credential, route, or capture privilege. Raw UDP payloads are
test input only; committed output may contain only the normalized fields below.

## Frozen common workload

Every observation subject must eventually use the same workload without subject-only
patches:

- one fresh candidate process and fresh connection state per sample;
- IPv4 loopback `127.0.0.1` and OS-assigned ephemeral UDP ports only;
- QUIC version 1, 0-RTT disabled, no connection resumption;
- one bodyless `GET /b001` and one empty `204` response;
- five independent connections per exact candidate revision;
- one exact lab-server revision, neutral loopback server identity, SNI,
  temporary certificate and validation policy, ALPN list, Retry policy,
  Version Negotiation policy, request, and response are held constant for all
  three subjects; each subject-specific trust-injection mechanism is recorded
  and must not weaken certificate validation;
- a normalized platform label (for example, target triple), architecture,
  exact subject revision or reference version, and sample count are recorded
  alongside the normalized observations; exact OS build details stay outside
  git;
- Chrome uses a temporary profile, background networking disabled, and an
  explicit loopback QUIC origin; it must not reuse the existing fingerprint
  lab path while that path passes `--disable-quic`;
- a subject that cannot use the same observer and workload is `FAIL`, not a
  reason to loosen the other subjects' method.

The observer receives bytes from a later unprivileged loopback adapter. It does
not open a socket, launch a browser, run packet capture, or infer subject
identity from the packet. Adapter readiness must be checked synchronously
before any of those actions.

The first client-to-server UDP datagram containing a QUIC v1 Initial, observed
before any server response, is the one primary sample for each fresh
connection. Its coalesced packets are observed in wire order. Later client
datagrams, server-to-client datagrams, retransmissions, Retry attempts, Version
Negotiation attempts, and any extra Chrome connections are separate labeled
observations and must not be mixed into that primary-sample comparison. A
connection that never produces the primary sample is `FAIL`.

## Normalized first-slice fields

For each UDP payload, retain only:

- UDP payload length and whether it is at least 1,200 bytes;
- coalesced packet type and packet length in wire order;
- QUIC version for long-header packets;
- destination and source connection-ID lengths, never their bytes;
- Initial token length, or Retry token length excluding the integrity tag,
  never token bytes;
- presence of Version Negotiation or Retry.

The no-dependency parser accepts QUIC v1 long headers, Version Negotiation, and
a final short-header remainder. It fails closed on truncation, impossible
declared lengths, a missing QUIC fixed bit where v1 requires it, a QUIC v1
connection ID longer than 20 bytes, malformed Version Negotiation, short Retry
integrity data, or an unsupported long-header version. Version Negotiation's
unused bits are not interpreted as the v1 fixed bit, and its version-independent
8-bit connection-ID lengths are not capped by the QUIC v1 limit. Parser errors
are fixed categories and do not contain raw packet bytes, addresses, hostnames,
credentials, or backend free-form errors.

## Deliberately UNKNOWN in this slice

The following cannot be learned from unencrypted outer Initial framing and stay
`UNKNOWN` until one neutral, independently reviewed decryption/key-log method
can be applied equally to all subjects:

- TLS ClientHello contents and ordering;
- QUIC transport parameters, ACK/PTO/migration behavior, and decrypted packet
  numbers;
- H3 SETTINGS, QPACK, request headers, response semantics, and close behavior;
- exporter behavior, CONNECT/CONNECT-UDP, application Datagram, PMTU, loss,
  RTT, resource, and supply-chain results;
- Chrome equivalence, privacy resistance, product readiness, or real-network
  behavior.

An unavailable or unequal key-log path stays `UNKNOWN`; it must not be replaced
with a candidate's self-report.

## Deterministic preflight RED

Run:

```sh
cargo run -q -p maverick-tests --bin backend-capture-lab -- preflight
```

Current main must exit nonzero before invoking an observer, binding UDP, or
starting Chrome, and report these exact blockers:

```text
quinn: common loopback observer adapter not implemented
quiche: current main quiche adapter unavailable
chrome: legacy Chrome QUIC disabled
```

Quinn being source-available does not make its observer adapter ready. The two
backend candidates and the Chrome reference form one observation gate, so any
blocker prevents all capture work. The unit test
`current_main_preflight_is_a_network_before_red` proves the guarded observer
closure is not called.

## GREEN for this first slice

GREEN means only that the contract is frozen and the byte-only parser's unit
tests pass for padded Initial, coalesced Initial/Handshake, token-length,
Retry, Version Negotiation, truncation, unsupported-version, and declared-
length cases. The preflight intentionally remains RED until a later bounded
slice supplies equal, reviewable adapters.

## Full B-001 completion gate

This first slice cannot close B-001. The later bakeoff must compare Quinn and
quiche against the same Chrome reference and record `PASS`, `FAIL`, or `UNKNOWN`
for every PLAYBOOK dimension: TLS ClientHello; QUIC Initial and transport
parameters; H3 SETTINGS, QPACK, headers, and close behavior; exporter;
CONNECT; the RFC 9297/9298 capability gate, send/receive behavior, and PMTU
API; bounded weak-network behavior;
maintenance cost; platform buildability; and supply-chain update cost. It must
also publish the normalized Quinn/quiche diffs and maintenance-cost table.
Until then, and until the separate B-002 fork audit also completes, B-003
cannot select Quinn, quiche, or neither.

## Stop and privacy rules

Stop without capturing if any subject needs a product/backend/vendor patch,
a third QUIC implementation, a privileged capture, a system proxy/DNS/route/
firewall/VPN/interface change, or a real network. Also stop if Chrome cannot
produce a stable loopback Initial, subjects cannot use the same observer,
key-log access is unequal, a new dependency is not independently reviewed, or
normalized output would expose raw packets, keys, endpoints, targets, profiles,
credentials, or private environment details.

No `pcap`, key log, temporary browser profile, raw packet, endpoint, or
subject free-form error is a repository artifact. A later result table must
mark every dimension `PASS`, `FAIL`, or `UNKNOWN` and must keep B-003 backend
selection separately owner-gated.

## Compatibility and rollback

This slice changes only the unpublished `maverick-tests` crate and this
contract. It changes no Maverick product API, config/schema, auth/frame wire,
artifact, release, or runtime behavior. Rollback is deletion of this document,
the lab binary, the lab-only module, and its `lib.rs` registration.

`STATUS.md` and `ROADMAP.md` are unchanged because B-001 is still incomplete
and the execution order did not change.
