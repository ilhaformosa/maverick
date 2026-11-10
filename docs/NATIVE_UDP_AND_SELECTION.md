# Native UDP and new-connection selection

Date: 2026-11-10
Status: active implementation contract; current delivery state is in STATUS.md.
The latest owner decision supersedes earlier opt-in generation and TCP-only selection scope.

## Scope and defaults

The protocol defines authentication, authenticated capabilities and wire behavior.
The official client core/SDK owns default selection, reachability state and
session lifecycle. The server owns both listeners and target forwarding.
Integrators supply policy/UI; they do not need to reimplement these core rules.

Complete candidate packages include H2 and H3. New direct generation selects
client auto/server dual, with explicit `udp_policy: allow_reliable`; fixed H2
and fixed H3 remain options, and `native_required` may be selected explicitly.
New protected intermediary generation selects H2 and `allow_reliable`, requiring
owner-supplied origin identity. Existing YAML omission keeps its prior behavior:
H2 legacy UDP exchanges or H3 native datagrams according to the existing carrier.
No implicit migration of saved settings or weakening of protection is allowed.
Explicit UDP policy on a TLS-terminating intermediary requires inner origin
protection; only omitted policy retains the historical trusted-provider path.

The new optional `advanced.udp_policy` has two values:

| Mode | `native_required` | `allow_reliable` |
|---|---|---|
| Fixed H2 / protected H2 | Reject incompatible config | Fixed-target reliable H2 session |
| Fixed H3 | Native H3 only | Native H3 only (fixed carrier is respected) |
| Direct auto | H3 only; fail if unavailable | Prefer H3; eligible setup failures may select H2 |
| Omitted | Preserve the existing carrier's legacy behavior | Not an implicit policy value |

TLS-terminating H3 fronting, new relay/crypto architectures, Atlas work, IP-block
recovery, field trials and publication are excluded. Performance ranking is
frozen (no probing/scoring framework). Active-session migration and seamless
cross-carrier resumption are permanently excluded, with no future reservation.

## Reliable H2 UDP sessions

Keep legacy OpenUdp flags=0 unchanged for older configurations/peers. The new
fixed-target session uses OpenUdp flags=2 with the same address/port and empty
initial-data encoding as native UDP. Auth hello feature bit 62 advertises this
extension; the server selects only offered/supported bits and authenticates its
selection in the existing hello MAC. A missing capability is an explicit
unsupported result before sending an extension request or application data.

WindowUpdate flags=2 admits the target and carries a two-byte maximum payload.
UdpPacket flags=2 carries raw data for that fixed target, preserving empty
packets and packet boundaries. The limit is 65507 bytes (also bounded by the
negotiated frame limit); no fragmentation/reassembly is added. CloseFlow closes
the association. Invalid flags, flow IDs and payloads are protocol errors.

One admitted session holds one connected UDP socket and its user-flow permit.
Replies are accepted only from that target; arbitrary unsolicited UDP ingress
and SOCKS fragmentation are not implemented.
Upload/download run independently, retaining the source port and accepting
multiple replies without requiring another upload. Queues, SOCKS child count,
flow limits and timeouts reuse existing bounds. Target silence is valid and is
not evidence that the tunnel is unreachable. Idle retirement never replays a
packet or migrates a session. Reliable transport may delay later packets while
retransmitting earlier bytes; this is not native unreliable datagram delivery.

## Native UDP

Use the maintained quiche QUIC DATAGRAM implementation (RFC 9221) and HTTP/3
Datagram request association (RFC 9297). One authenticated H3 request owns one
fixed-target UDP association. The existing origin TLS, CA/hostname/pin checks,
auth v1/v2, replay checks, per-user admission and egress policy apply before
target traffic. TLS-terminating H3 intermediaries remain unsupported.

The reliable Maverick control stream uses OpenUdp with flags=1 and an OpenTcp
address/port payload whose initial_data is empty. This is distinct from legacy
H2 OpenUdp. WindowUpdate with flags=1 acknowledges admission and carries a
two-byte network-order maximum UDP payload. CloseFlow ends the association.
Errors never cause fallback to legacy UDP semantics.

HTTP Datagrams use Quarter Stream ID 0 (the sole H3 request), followed by the
unmodified UDP payload. They are enabled only after association approval.
Receive and send operate independently; target responses do not require a new
client packet. Queues are bounded, full queues and oversized packets are
dropped, and lost datagrams are not retransmitted at the application layer.
The first implementation caps payloads at 1200 bytes and additionally respects
the negotiated QUIC/path limit. It adds no fragmentation or reassembly.

SOCKS UDP owns a bounded set of fixed-target children. Each child keeps one
connected target socket and its existing user-flow permit; extra local children
also consume the existing client flow budget. Closing the SOCKS control channel
cancels the children. No task is created per packet. Resolved destinations are
checked against egress policy before target sockets open; replies come only
from the connected peer.

## Dual listeners and selection

A dual server binds TCP/H2 and UDP/H3 at the same configured port and uses the
same certificate, credential store, replay state and user/admission policies.
Both listeners must bind successfully before readiness is reported;
shutdown stops both. Dual mode does not combine protected intermediary H2 with
an H3 trust route. Those remain separate configurations.

Automatic selection applies only to new direct connections/sessions. The shared
client pool prefers H3 with at most one second or half the total setup deadline.
Only a typed network-unavailable result before any peer response permits H2
selection for TCP. UDP additionally requires `allow_reliable`; it may also
select H2 after authenticated setup establishes that native datagram capability
is unavailable, before any application packet is accepted for sending.

Certificate, hostname, pin, authentication, malformed protocol, target rejection
and admission errors are terminal. Generic/partial-handshake timeouts are not
permission to fall back. Each alternative performs full identity/auth checks.
A 30-second reachability avoidance cache is shared by TCP and eligible UDP
opens; a later new open retries after expiry. Native-required UDP never chooses
H2. There is no background probing or performance ranking. Returned sessions
retain their carrier. Send failure or a silent UDP target never triggers carrier
selection or automatic replay. Protected H2 never enters a direct/H3 fallback.

## Acceptance

- Generated relay configs retain origin trust and cannot omit the required pin.
- Real native UDP verifies multiple responses, concurrent targets, empty and
  oversized datagrams, loss/reordering, admission, cancellation and cleanup.
- Authentication, certificate/pin and egress failures never reach targets.
- Dual startup is atomic; both endpoints stop and can reuse the same port.
- New TCP connections select H3 when available and H2 on bounded reachability
  failure; TLS/auth failures contact no H2 fallback. Existing flows continue
  while later connections select independently.
- Reliable H2 UDP verifies stable target/source port, continuous upload without
  replies, multiple independent responses, empty/large/oversize packets,
  concurrent targets, bounded admission and stop/idle/drop cleanup.
- Policy tests cover native-required rejection, eligible reliable selection,
  shared reachability avoidance/retry, missing capability, malformed protocol,
  target silence, no payload replay and security failures with no fallback.
- SDK calls, protected H2, generated defaults, old-config omission, full-package
  build identity and published rollback partner compatibility remain covered.
- Default/rustls/H3, retained candidate, dependency, native artifact/rollback
  and code-scanning checks remain enabled. No field or performance claim follows
  merely from local success.

References: [QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html),
[HTTP Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html).
