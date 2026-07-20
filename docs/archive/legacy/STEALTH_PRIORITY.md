# Stealth Priority

Status: active direction. This is not a censorship-resistance or anonymity
claim. `docs/PLAN_POST_V1.md` owns execution order; this document records the
technical rationale and standing regression priorities.

Maverick's next hard problem is not more process. It is making the default path
harder to distinguish from ordinary web traffic.

## Current Truth

- Default TLS uses rustls and does not mimic a browser ClientHello.
- Native server-side ECH is not implemented.
- `advanced.stealth.tls_fingerprint: browser_mimic` is available only in
  `browser-tls` builds. It uses BoringSSL with GREASE, extension permutation,
  TLS exporter channel binding, Chrome-reference ALPN, and Chrome-reference H2
  settings. The pinned Chrome 150 headless/macOS arm64 comparison still differs
  on ALPS and newer signature algorithms, so this is not exact equivalence.
- Fallback behavior has been hardened, and H2 loopback tests now compare
  ordinary static and reverse-proxy fallback shape against bad-auth and
  malformed tunnel-like requests. H2 stream admission exhaustion also returns
  fallback shape when active-probe resistance is enabled.
- `advanced.stealth.cdn_fronting.enabled: true` is now a first-class way to
  select the Cloudflare-fronted WebSocket carrier. The older
  `advanced.experimental_cloudflare_ws` flag remains a compatibility alias.
- CDN-fronted mode requires explicit `advanced.stealth.cdn_fronting`
  acknowledgement because the CDN terminates client-facing TLS.
- Current shaping is bounded padding, batching, pacing, and cover-padding
  baseline work. It is not real traffic-analysis resistance.

## Current Execution Status

- M2 measurement baselines are implemented with recorded browser gaps.
- M3 H2 connection reuse is implemented with bounded lifecycle tests.
- M4 browser-TLS correctness and M5 fallback hardening gates are complete.
- M6 layered two-host evidence is accepted for the tested direct TLS/H2 path.
- M7 has an accepted architecture decision: direct H2 stays the v1.x default,
  CDN WebSocket stays explicit, and handshake-layer work stays in v2 research.
- M8 Phase 2 is accepted for the tested approved-host IPv4 matrix, including a
  namespace-local real TUN, bounded resources, failure recovery, host
  invariants, and cleanup. IPv6 is unscheduled; product-client evidence remains
  open.

## Standing Technical Order

Implemented items remain regression requirements rather than new competing
milestones:

1. Measurement baseline:
   - use `docs/STEALTH_MEASUREMENT.md` to record repeated ClientHello/H2 samples;
   - keep real-browser and direct-origin gaps visible instead of treating missing
     evidence as success.
2. H2 connection reuse:
   - reduce repeated TCP/TLS handshakes without changing the frozen v1 frame or
     authentication formats;
   - keep reconnect, GOAWAY, idle retirement, and resource bounds covered.
3. Active probing resistance:
   - unauthenticated, malformed, rate-limited, and exhausted paths should look
     like the configured fallback site;
   - keep extending response-shape tests beyond the current H2 static and
     reverse-proxy baseline to WebSocket handshake paths, H3, and more
     admission-exhaustion cases;
   - keep auth failure rate limits effective without creating a unique protocol
     error signal.
4. Browser-like TLS fingerprint strategy:
   - keep H2/rustls as the reliable default;
   - use `browser-tls` for the BoringSSL browser-like client path;
   - collect repeatable JA3/JA4 or packet-capture evidence before making any
     stronger browser-equivalence claim.
5. CDN-fronted carrier:
   - treat Cloudflare-fronted WebSocket as the pragmatic near-term path;
   - require operators to acknowledge that Cloudflare terminates TLS and can
     observe Maverick auth frames and payload;
   - improve WebSocket fallback and active-probing behavior before adding new
     carriers.
6. Measurable shaping:
   - use shape-lab traces as regression data;
   - measure overhead and classifier-visible deltas;
   - do not claim anonymity or traffic-analysis resistance without evidence.

## Defer

- Native server-side ECH until upstream TLS support is practical.
- Post-quantum hybrids until upstream TLS and external review justify them.
- Multi-hop, no-domain mode, plugin systems, and standardization until the
  single-hop default path is stronger.
- Product TUN mode until stealth, multiplexing, and lifecycle behavior have
  clearer evidence.
