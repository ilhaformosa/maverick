# Maverick v0.1.0-alpha.4 Release Notes

Status: fourth pre-publication private alpha source snapshot.

Maverick remains an experimental as-is prototype. Alpha.4 is not
production-ready, not a stable protocol freeze, not a stable or production
security sign-off, not a standardization proposal, not an anonymity claim, and
not a censorship-resistance guarantee.

## Highlights

- Direction A stealth controls: add an optional browser-like TLS client path,
  stronger active-probing fallback behavior, and first-class CDN-fronted
  WebSocket configuration.
- Browser-like TLS strategy: `advanced.stealth.tls_fingerprint:
  browser_mimic` is accepted only in builds compiled with the `browser-tls`
  feature. That path uses BoringSSL with GREASE, extension permutation, and H2
  ALPN. It is browser-like, not proof of exact browser equivalence.
- Active-probing resistance: H2 bad-auth, malformed, rate-limited, and
  stream-admission exhaustion paths continue returning fallback-shaped
  responses when active-probe resistance is enabled. Static and reverse-proxy
  fallback shape tests cover the main H2 loopback paths.
- CDN-fronted WebSocket: `advanced.stealth.cdn_fronting.enabled: true` now
  selects the Cloudflare-fronted WebSocket carrier directly. The older
  `advanced.experimental_cloudflare_ws: true` flag remains a compatibility
  alias.
- Release hygiene: alpha.3 post-release audit results are recorded, and
  release notes keep the experimental status and non-claims explicit.

## Version Boundaries

- software release tag: `v0.1.0-alpha.4`;
- package version: `0.1.0-alpha.4`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-alpha.3`.

## Native ECH Status

Native Maverick server-side ECH is not implemented in this alpha. The
Cloudflare-fronted WebSocket carrier is the accepted near-term workaround when
operators explicitly trust the TLS-terminating CDN. This is not native
Maverick server-side ECH, not provider-independent ECH, and not a
censorship-resistance guarantee.

## Known Limitations

- No native server-side ECH.
- No stable protocol or config freeze.
- No production-ready claim.
- No production packaging claim.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- Browser-like TLS support is optional, H2-only, and not exact browser
  fingerprint equivalence.
- CDN-fronted WebSocket requires trusting the CDN because the CDN terminates
  client-facing TLS before forwarding the WebSocket carrier.
- Approved-host evidence supports only the explicitly tested scope and does not
  generalize to every deployment topology, region, provider, platform, or
  network condition.
- Broader production claims still require separate operator rollout/rollback,
  abuse/DoS, observability, deployment hardening, and incident-response
  evidence.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
cargo clippy -p maverick-client --features browser-tls --all-targets -- -D warnings
```

This release does not cite benchmark numbers. Do not attach benchmark artifacts
or quote benchmark results unless the matching benchmark commands are run for
the final tagged commit.

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body.

## Upgrade Notes

No mandatory migration is required from `v0.1.0-alpha.3`.

Operators should still review `COMPATIBILITY.md`, `MIGRATIONS.md`,
`docs/ECH_WORKAROUND.md`, `docs/STEALTH_PRIORITY.md`, and
`docs/RELEASE_TAGGING.md` before upgrading. This alpha may still change config
fields, protocol details, and experimental gates in later releases.
