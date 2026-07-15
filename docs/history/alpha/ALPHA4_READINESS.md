# Alpha.4 Readiness Tracker

Status: completed release tracker for the `v0.1.0-alpha.4` snapshot. This is not a
stable-scope claim, production-readiness claim, security-audit result,
anonymity claim, censorship-resistance claim, or protocol-freeze claim.

`v0.1.0-alpha.4` remains a small alpha focused on the Direction A stealth
controls: browser-like TLS strategy, active-probing resistance, and
CDN-fronted WebSocket as the near-term ECH workaround. The default release
posture remains experimental and as-is.

## Current Boundary

- software release tag: `v0.1.0-alpha.4`;
- package version: `0.1.0-alpha.4`;
- default `protocol_version: 1` remains unchanged;
- config `version: 1` remains unchanged;
- no mandatory migration is planned;
- rustls/H2 remains the default client path;
- browser-like TLS is optional and requires the `browser-tls` build feature;
- Cloudflare-fronted WebSocket remains explicit and requires trusted CDN
  acknowledgement.

## Alpha.3 Follow-Up Snapshot

The alpha.3 post-release follow-up pass found no urgent correction:

- `v0.1.0-alpha.3` points to commit
  `45d88614b0d4a1a341f3782e26314941eeba8ac1`;
- the GitHub Release is published as a Pre-release and not a Draft;
- the release was not returned by the default latest-release lookup;
- attached artifact checksum verification passed;
- internal artifact `SHA256SUMS` verification passed;
- the artifact binary reported `maverick 0.1.0-alpha.3`;
- `BUILDINFO` recorded the alpha.3 commit;
- artifact and release-body privacy scans found no local repository path, home
  path, local developer username, known private approved-host label, known
  private approved-host address, PEM private-key header, or bearer-token shaped
  string;
- open public issues and pull requests remained empty after publication.

See `docs/history/release/POST_RELEASE_AUDIT_v0.1.0-alpha.3.md`.

## Alpha.4 Release Snapshot

The alpha.4 release follow-up pass found no urgent correction:

- `v0.1.0-alpha.4` points to commit
  `83f68f7d4b6f2c0b515c9c61dc472a62d741922e`;
- the GitHub Release is published as a Pre-release and not a Draft;
- the default latest-release lookup did not return this tag;
- attached artifact checksum verification passed;
- internal artifact `SHA256SUMS` verification passed;
- the artifact binary reported `maverick 0.1.0-alpha.4`;
- `BUILDINFO` recorded the alpha.4 commit;
- artifact and release-body privacy scans found no local repository path, home
  path, local developer username, known private approved-host label, known
  private approved-host address, PEM private-key header, bearer-token shaped
  string, or generated Maverick secret string.

See `docs/history/release/POST_RELEASE_AUDIT_v0.1.0-alpha.4.md`.

## Candidate Work Items

| Area | Alpha.4 action | Local status | Stable-scope impact |
| --- | --- | --- | --- |
| Browser-like TLS | Add optional BoringSSL H2 client path behind `browser-tls` | Implemented and feature-Clippy checked | Provides a real path for fingerprint evidence without changing default rustls |
| Active probing | Keep H2 bad-auth, malformed, rate-limited, and stream-admission exhaustion responses fallback-shaped | Implemented and covered by static/reverse-proxy shape tests | Reduces obvious protocol signals on unauthenticated paths |
| CDN-fronted carrier | Promote `advanced.stealth.cdn_fronting.enabled` as first-class selection | Implemented with loopback WebSocket relay coverage | Keeps the ECH workaround explicit and documented |
| Compatibility | Preserve default protocol version `1` and config version `1` | Documented here | Reduces accidental version drift |
| Migration | Preserve no-mandatory-migration posture | Documented here | Keeps config `version: 1` policy explicit |

## Stable-Candidate Gaps

The first narrow candidate remains `maverick-tls-h2-cli-v1`. Alpha.4 improves
the evidence path for stealth controls, but it should not claim stable or
production status.

High-signal remaining gaps:

- repeatable TLS fingerprint evidence for `browser-tls` before making any
  stronger browser-equivalence claim;
- WebSocket and H3 active-probing shape coverage beyond the current H2 tests;
- operator rollout and rollback evidence for the exact deployment scope being
  claimed;
- abuse and denial-of-service evidence for auth attempts, connection caps,
  memory pressure, and fallback load;
- redacted observability evidence for metrics and logs;
- deployment hardening evidence for service users, file permissions,
  certificates, restart behavior, and rollback;
- incident-response and vulnerability-handling readiness.

Network-impairment evidence exists for the tested TCP/H2 latency and loss
profiles, but that evidence should not be generalized to every provider,
region, platform, topology, or production rollout model.

## Verification Before Tagging

Minimum local alpha.4 gates:

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

Run benchmark scripts only if alpha.4 release notes cite benchmark results:

```sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
```

Approved-host evidence must be collected only on explicitly approved hosts and
must be redacted before being committed. The developer workstation must not be
used for system proxy, DNS, route, firewall, VPN, TUN, or other
network-service mutation tests.

## Non-Goals

Do not use alpha.4 to claim or ship:

- native Maverick server-side ECH;
- stable protocol or config freeze;
- exact browser fingerprint equivalence;
- audited, production-ready, anonymity, or censorship-resistance status;
- GUI/App runtime behavior;
- production binary distribution for every platform;
- workstation network-service mutation tests.
