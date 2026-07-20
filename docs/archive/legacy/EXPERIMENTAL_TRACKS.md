# Experimental Tracks

Status: tracking document backed by the core experimental track registry and
`maverick experimental list`. H3 and the product TUN packet adapter have direct
runtime implementations, the TUN Phase 2 IPv4 matrix is accepted, and the
Cloudflare-fronted WebSocket carrier has an approved-host runtime smoke. All
remain off by default.

Experimental work must be documented, feature-gated where applicable, and
excluded from default security claims until it has focused tests and review.
Experimental work should not expand the minimum stable scope unless it reduces
a concrete current risk in the default path and keeps H2 fallback coverage.

## Matrix

| Track | Status | Gate | Default |
| --- | --- | --- | --- |
| H3/QUIC carrier | Runtime experimental baseline implemented | build `h3`, runtime `advanced.experimental_h3` | off |
| Cloudflare-fronted WebSocket carrier | Approved-host runtime smoke implemented for Cloudflare-origin experiments | runtime `advanced.stealth.cdn_fronting.enabled` on both endpoints; `advanced.experimental_cloudflare_ws` remains a compatibility alias | off |
| WebTransport-like carrier | Research only | future build `webtransport-experimental` | off |
| Native Encrypted ClientHello (ECH) | Core tracking item; config/readiness gate plus feature harness; native handshake not implemented | build `ech`, runtime `advanced.experimental_ech` rejected for now | off |
| HPKE config envelope | Disabled registry entry | future `hpke-experimental`, runtime `advanced.crypto.allow_experimental` | off |
| Noise native mode | Disabled registry entry with feature-gated core session harness; product transport exposure deferred | build `noise-experimental`, runtime `advanced.crypto.allow_experimental` rejected for product config | off |
| ML-KEM hybrid | Disabled registry entry | future `ml-kem-hybrid`, runtime `advanced.crypto.allow_experimental` | off |
| Blinded credential lookup | Research only | future build `blinded-lookup-experimental` | off |
| Native no-domain mode | Research only | future `no-domain-experimental` plus reviewed design | off |
| Multi-hop research | Research only | none | off |
| Plugin system outside core protocol | Product architecture research | none | off |
| Product TUN packet runtime | Phase 2 approved-host IPv4 matrix accepted; IPv6 unscheduled and product integration open | build `tun-runtime`, runtime `advanced.experimental_tun` | off |

The registry must preserve these invariants:

- every track is default-off;
- every track is excluded from default security claims;
- runtime/config-gated tracks declare build and runtime gates;
- DNS, WAN, no-domain, and multi-hop style experiments require an external
  test host before integration testing.
- product TUN may use local synthetic and loopback tests, but any real device,
  route, DNS, leak, or recovery evidence requires an approved external host.

## H3/QUIC

Implemented as an optional carrier with local TCP, DNS, UDP, fallback, replay,
concurrency, and debug-only operational diagnostic coverage. H2 remains the
mandatory default and fallback.

Open work:

- broader operational hardening;
- deployment port guidance;

## WebTransport-Like Carrier

Research only. It must not start until H2/H3 behavior and scheduler policy are
stable enough to avoid multiplying transport complexity.

Minimum entry criteria:

- transport abstraction remains covered by local harness;
- WebTransport API and Rust stack are selected;
- H2 fallback tests remain mandatory.

## Cloudflare-Fronted WebSocket Carrier

Implemented as an explicit CDN-fronted carrier for approved Cloudflare-origin
runtime experiments. It is off by default and does not replace native ECH: in
this mode Cloudflare terminates the external TLS/ECH connection and forwards a
WebSocket connection to the Maverick origin.

Guardrails:

- client `stable` mode rejects the CDN-fronted WebSocket carrier;
- both endpoints must opt in;
- new configs should use `advanced.stealth.cdn_fronting.enabled: true`;
- `advanced.experimental_cloudflare_ws: true` remains a compatibility alias;
- direct H2/TLS remains the default transport;
- Cloudflare is a fully trusted TLS-terminating front in this mode and can
  observe Maverick auth frames and tunnel payload;
- approved-host WAN smoke is required before treating Cloudflare-fronted
  behavior as working.

## Native ECH

Config gates, readiness diagnostics, and an ECH feature harness exist, but
`experimental_ech: true` is rejected until upstream TLS support, ECH config
distribution, and controlled integration coverage are ready. `private` mode
rejects `allow_plain_sni`.

ECH tests that touch DNS records or real network behavior require a dedicated VM
or explicitly approved host.

Native server-side ECH is a core tracking item, not an active initial-release
blocker. The immediate workaround is the Cloudflare-fronted WebSocket carrier,
which is tracked separately because Cloudflare terminates the public ECH/TLS
connection. See `docs/NATIVE_ECH_TRACKING.md` and `docs/ECH_WORKAROUND.md`.

Near-term work should prioritize fallback behavior, active-probing resistance,
and measurable shaping baselines over native ECH runtime work unless upstream
server-side TLS support becomes practical.
See `docs/STEALTH_PRIORITY.md` for the current stealth-first queue.

## Native No-Domain Mode

Research only. This track likely depends on a Noise-style or other non-TLS
design. `maverick-core` now includes a feature-gated Noise XX session harness
for encrypted frame round trips, but native no-domain product transport remains
research-only. It must not replace TLS defaults or ship before an explicit
threat model and conformance story exist.

## Product TUN Packet Runtime

Phase 1 uses exact `smoltcp 0.13.1` features in a separate first-party crate.
It accepts caller-supplied packet I/O, maps bounded dual-stack TCP plus DNS and
UDP through one existing Maverick client pool, and exposes coarse
lifecycle/resource snapshots. Default client builds do not enable it, `stable`
mode rejects it, and the packet crate cannot create interfaces or launch
host-network commands.

The Phase 2 approved-host IPv4 matrix passed through a namespace-local real TUN
with preserved control-plane access, failure recovery, private evidence, and
complete residue cleanup. IPv6 was policy-blocked, was not exercised, and is
not scheduled. This remains experimental evidence, not a shipped full-device
helper or a product-readiness claim.

Phase 3 is active in a separate Linux reference-client project. Its initial
helper, journaled IPv4 platform transaction, SDK lifecycle, client/helper crash
recovery, encrypted credential loading, route-only installed-service cycles,
and bounded installed IPv4 TCP/UDP/DNS plus tested-target route separation have
approved-host evidence. Its current-source package signing, upgrade, downgrade
rejection, failed-upgrade retry, and purge matrix is also accepted. Power loss,
broader network-transition leak/coexistence, sustained use, production
credential-root protection, package publication, and production readiness
remain unproven.

## Blinded Credential Lookup

Research only. Auth v2 currently uses explicit credential hints. A future
blinded or less-identifying lookup design must preserve bounded replay state,
avoid adding a fingerprintable pre-auth discovery endpoint, and include
conformance vectors before any runtime gate exists.

## Crypto Experiments

HPKE, Noise, and ML-KEM are present only as disabled crypto suite registry
entries. `advanced.crypto` defaults to `tls13` and rejects disabled suites before
product transport runtime. Known-answer vectors, explicit runtime approval, and
review evidence are required before any entry can move toward product use.
Noise also has a readiness snapshot, Snow-backed deterministic transcript
evidence, a feature-gated core session harness, and a deferred product
runtime-config gate.

These tracks must not replace the TLS 1.3 default path or enter the minimum
stable scope before external review and a concrete product threat model justify
the added complexity.

## Multi-Hop Research

Research only. Multi-hop adds operator, latency, abuse, and correlation
complexity. It should not be implemented until the single-hop protocol has a
clearer security review path.

## Plugin System

Out-of-core plugin support is product architecture research. Plugins must not
receive raw secrets, payload bytes, TLS key material, or unrestricted network
hooks by default.

## Promotion Criteria

An experimental track can move toward runtime use only after:

- build and runtime gates exist;
- local tests cover default-off behavior;
- failure and downgrade behavior are documented;
- resource bounds are explicit;
- docs explain non-claims;
- security review requirements are identified.
