# Maverick Threat Model

Status: current threat model for the narrow `maverick-tls-h2-cli-v1`
engineering release. It is not a formal audit or a production security claim.

## Production Candidate Composition

The pre-freeze `maverick-linux-h2-ipv4-v1` target combines this server/SDK threat
model with the exact public reference-client threat model at its frozen commit.
The combined audit must cover the Linux privileged helper, IPC, journal, route,
private DNS, TUN, credential-root, package, APT, recovery, and removal boundaries.

Only a source-bound disposable Ubuntu 24.04 LTS `amd64` VM or fixture can supply
formal target-platform evidence. A physical host with another OS may test an
orchestration boundary but cannot prove supported-platform behavior.

## Intended Protections

Maverick v1 is designed to help with:

- Passive observers seeing an outer TLS/H2 connection rather than plaintext
  proxy protocol fields.
- Active probing attempts that do not possess a valid user credential.
- Replay of a captured ClientHello within the replay window.
- Direct H2/WebSocket ClientHello replay across a different TLS connection when
  TLS channel binding is negotiated or required.
- Credential guessing when users use generated high-entropy secrets.
- Malformed frame parser attacks that should return errors rather than panic.
- Accidental secret disclosure in ordinary logs and Debug output.
- Basic service-identification risk through static or reverse-proxy fallback
  behavior that avoids Maverick-specific unauthenticated errors.
- Default server egress policy that blocks authenticated relay attempts to
  loopback, private, shared, link-local, multicast, and unspecified addresses.

## Explicit Non-Claims

Maverick v1 does not claim to defend against:

- Global traffic correlation.
- Compromised client or server machines.
- Malicious proxy server operators.
- Browser fingerprinting by destination websites.
- All DNS, IP, certificate-chain, timing, and traffic-volume side channels.
- Guarantees against any specific firewall or censorship system.
- Browser-grade TLS fingerprint mimicry.
- TLS channel binding through experimental H3 or TLS-terminating fronting
  providers.
- Strong traffic shaping or padding.
- Perfect indistinguishability from the configured fallback origin.
- Abuse resistance against high-rate connection or auth attempts.
- Protection from a TLS-terminating fronting provider when an experimental
  Cloudflare-fronted carrier is explicitly enabled.

## Trust Boundaries

The client trusts:

- local applications that connect to the SOCKS5 listener;
- the configured Maverick server;
- the configured TLS CA or public root store.

The server trusts:

- configured user secrets;
- local certificate and key files;
- the configured fallback content directory.
- the configured egress policy and any surrounding host/network isolation.

When an experimental Cloudflare-fronted carrier is enabled, both endpoints also
trust Cloudflare as a TLS-terminating reverse proxy. Cloudflare can observe the
origin request, Maverick auth frames, and tunnel payload carried inside that
fronted connection. This mode is an edge-fronted experiment, not native
server-side ECH.

Remote unauthenticated traffic is untrusted and must never receive
Maverick-specific protocol diagnostics.

Authenticated users are also inside the proxy trust boundary. The default
egress policy blocks common internal and metadata ranges, but operators should
treat broad authenticated egress as sensitive and avoid disabling those blocks
without a deployment-specific reason.

## Abuse Boundaries

This repository is for legal privacy, secure communication, connectivity
research, and protocol engineering. It does not implement malware behavior,
credential theft, scanning, DDoS, spam delivery, backdoors, hidden control, or
targeted intrusion functionality.

## Future Security Work

- External audit before any production use.
- Credential rotation.
- Anonymous or blinded credential lookup.
- Stronger padding and shaping analysis.
- Better HTTP/TLS profile research without brittle impersonation claims.
- Browser TLS profile evidence and traffic-shape evidence strong enough for
  stealth claims.
- Fuzzing beyond the current frame parser property tests.

For the production candidate, the remaining work is tracked as changing state in
`production-readiness.json`; it is not part of the permanent non-claim list.
