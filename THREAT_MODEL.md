# Maverick Threat Model

Status: current threat model for owner-operated Beta evaluation.

Maverick is Beta software. This document is not an audit, production-security
claim, anonymity claim, or guarantee against a specific censorship system.

## Beta Evaluation Basis

The completed owner-operated pilot is the evidence basis for the current Beta
stage. Its first user was the project owner on an owner-controlled spare macOS
laptop, its server was owner-controlled, and its task was ordinary,
non-sensitive browsing on the privately identified lawful client path recorded
in `STATUS.md`. Any later real-network Beta evaluation remains limited to the
current authorization recorded there.

The current adversary model is an access-network observer that can:

- see endpoint IPs, connection timing, volume, and TLS metadata;
- block based on TLS/H2 fingerprint or endpoint reputation;
- connect to and actively probe a public server;
- reset, delay, or drop connections.

Evidence so far observes the behavior of one privately identified,
owner-controlled lawful restricted access network. It does not publish that
network's type or identity and does not name or claim resistance to a particular
country, firewall, provider, or censorship system.

## Intended Protections

On the direct path, Maverick is intended to provide:

- TLS 1.3 encryption between client and server;
- authenticated tunnel access using high-entropy credentials;
- replay resistance for captured authentication messages;
- browser-like client TLS/H2 behavior on supported default builds;
- fallback content instead of Maverick-specific unauthenticated errors;
- bounded parsers, flows, timeouts, and pre-auth work;
- redaction of credentials and payloads from ordinary logs;
- server egress defaults that reject common private and local address ranges.

An authorized Cloudflare-fronted evaluation may run only with Cloudflare Full
(strict), or equivalent origin-authenticated TLS, and H2-to-origin. It then uses
one encrypted connection from the client to Cloudflare and another from
Cloudflare to the origin. It is not end-to-end encrypted against Cloudflare:
the provider can observe Maverick authentication and tunnel payload before
forwarding it.

## Explicit Non-Claims

Maverick does not currently protect against or prove:

- global traffic correlation;
- endpoint-IP blocking;
- all TLS, HTTP/2, timing, volume, DNS, or certificate side channels;
- exact equivalence to any browser version;
- a compromised client or server;
- a malicious server operator;
- destination-site browser fingerprinting;
- a TLS-terminating fronting provider observing tunnel content;
- every active-probe strategy;
- anonymity or resistance to a named censorship system.

## Trust Boundaries

The client trusts the local user, the configured server, and its configured TLS
roots or certificate pin. The server trusts its local certificate/key files,
configured users, fallback content, and egress policy.

For an authorized owner-only provider-fronted evaluation, Cloudflare becomes a
trusted party that can observe Maverick authentication and tunnel payload. The
owner's exact acceptance period and operational boundary are recorded in
`STATUS.md`; this threat model does not create or extend that authorization.

## Safety Boundary

Repository-local tests use `127.0.0.1` and OS-assigned ephemeral ports. They do
not change system proxy, DNS, routes, firewall, VPN, interfaces, or network
services. Real-network testing is limited to the private environment and owner
authorization recorded in `STATUS.md`.

## Evidence Standard

Loopback tests show implementation behavior only. A real-network Beta record
must say:

- who consented to test;
- what user task was attempted;
- what client/server artifact was used;
- what network observations were available;
- what failed or remained unknown;
- whether any system network settings were changed.

One successful evaluation remains one observation, not a universal security
claim.
