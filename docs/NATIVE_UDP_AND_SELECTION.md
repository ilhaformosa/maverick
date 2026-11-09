# Native UDP and new-connection selection

Date: 2026-11-09
Status: implementation contract; current delivery state is in STATUS.md.

## Scope and defaults

New intermediary configuration generation requires a separately supplied origin
certificate/name and enables origin-pinned H2 protection on both endpoints.
Existing direct defaults and explicitly acknowledged legacy configurations do
not silently change. H3, dual listeners and automatic selection remain opt-in
and require the experimental-h3 build. External client development, IP-block
recovery and field trials are excluded.

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

Automatic client selection is explicitly enabled for direct connections. It
prefers H3 for each new TCP flow, with a bounded portion of the existing
connection deadline (at most one second or half that deadline, minimum 1 ms).
It may use H2 only after a typed network unreachability or timeout before any
peer response. Partial-handshake timeouts do not qualify. Certificate, hostname
and pin failures and every failure after TLS establishment are terminal,
including authentication and protocol
errors. A 30-second negative reachability cache avoids probing blocked UDP for
every new flow; it does not change established sessions or trust requirements.
Native UDP has H3 as its only eligible carrier. No active-session migration,
background probe, endpoint discovery or trust downgrade is introduced.

## Acceptance

- Generated relay configs retain origin trust and cannot omit the required pin.
- Real native UDP verifies multiple responses, concurrent targets, empty and
  oversized datagrams, loss/reordering, admission, cancellation and cleanup.
- Authentication, certificate/pin and egress failures never reach targets.
- Dual startup is atomic; both endpoints stop and can reuse the same port.
- New TCP connections select H3 when available and H2 on bounded reachability
  failure; TLS/auth failures contact no H2 fallback. Existing flows continue
  while later connections select independently.
- Default/rustls/H3, retained candidate, dependency, native artifact/rollback
  and code-scanning checks remain enabled. No field or performance claim follows
  merely from local success.

References: [QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html),
[HTTP Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html).
