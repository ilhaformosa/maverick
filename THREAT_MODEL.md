# Maverick Threat Model

Status: current threat model for the first owner-operated user pilot.

Maverick is alpha software. This document is not an audit, production-security
claim, anonymity claim, or guarantee against a specific censorship system.

## Pilot

The first user is the project owner on an owner-controlled client. The server,
if a real-network pilot is later authorized, must also be owner-controlled. The
first task is ordinary browsing for one workday.

The first adversary model is an access-network observer that can:

- see endpoint IPs, connection timing, volume, and TLS metadata;
- block based on TLS/H2 fingerprint or endpoint reputation;
- connect to and actively probe a public server;
- reset, delay, or drop connections.

A named real-world censor is not in scope until a lawful pilot network is
selected and tested.

## Intended Protections

Maverick is intended to provide:

- TLS 1.3 encryption between client and server;
- authenticated tunnel access using high-entropy credentials;
- replay resistance for captured authentication messages;
- browser-like client TLS/H2 behavior on supported default builds;
- fallback content instead of Maverick-specific unauthenticated errors;
- bounded parsers, flows, timeouts, and pre-auth work;
- redaction of credentials and payloads from ordinary logs;
- server egress defaults that reject common private and local address ranges.

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

If a TLS-terminating fronted carrier is used later, that provider becomes a
trusted party that can observe Maverick authentication and tunnel payload. That
tradeoff must be explicit in the pilot record.

## Safety Boundary

Repository-local tests use `127.0.0.1` and OS-assigned ephemeral ports. They do
not change system proxy, DNS, routes, firewall, VPN, interfaces, or network
services. Real-network testing requires a separately named environment and
authorization.

## Evidence Standard

Loopback tests show implementation behavior only. A real pilot record must say:

- who consented to test;
- what user task was attempted;
- what client/server artifact was used;
- what network observations were available;
- what failed or remained unknown;
- whether any system network settings were changed.

One successful pilot remains one observation, not a universal security claim.
