# UDP Relay

Status: v2 flow mapping baseline implemented.

Maverick UDP relay is still experimental, but it now has explicit flow setup
instead of treating every packet as a standalone tunnel.

## Frame Flow

1. Client opens an authenticated Maverick tunnel.
2. Client sends `OpenUdp` with `OpenUdpPayload { idle_timeout_ms }`.
3. Server validates the requested timeout, caps it to
   `server.advanced.udp_idle_timeout_ms`, and returns `WindowUpdate`.
4. Client sends one or more `UdpPacket` frames on the same flow id.
5. Server relays each packet to the requested target and returns a `UdpPacket`
   response on the same flow id.
6. Either side can send `CloseFlow`; server also sends `CloseFlow` after idle
   timeout.

## SOCKS5 Mapping

One SOCKS5 UDP ASSOCIATE control connection owns one lazy Maverick UDP
association. The first datagram opens the remote UDP flow; later datagrams reuse
that flow while the control connection remains open.

## Bounds

- SOCKS5 UDP fragmentation is rejected.
- Datagram buffers are bounded by the existing SOCKS5 and relay limits.
- `advanced.udp_idle_timeout_ms` defaults to `30000` on both client and server.
- Server-side timeout is the lower of the client request and server cap.

## Current Limits

- UDP relay is request/response oriented and not optimized for lossy or
  high-throughput real-time workloads.
- Packets are serialized per SOCKS5 UDP association.
- No production NAT traversal or roaming claims are made.
