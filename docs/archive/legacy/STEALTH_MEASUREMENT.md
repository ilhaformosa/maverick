# Stealth Measurement Labs

Status: loopback-only measurement tooling. It does not prove browser
equivalence, perfect origin indistinguishability, censorship resistance,
anonymity, or traffic-analysis resistance.

## Safety Boundary

All listeners bind to `127.0.0.1` with OS-assigned ephemeral ports. The labs do
not use `sudo`, packet-capture privileges, DNS changes, routes, firewall rules,
system proxy settings, VPN settings, or real remote hosts.

Generated reports default to ignored `runtime-evidence/`. Do not commit raw
packet data, TLS secrets, hostnames, addresses, certificate paths, or private
infrastructure metadata.

## TLS/H2 Fingerprint Lab

The fingerprint lab records two client-visible layers without capturing a real
network interface:

- the raw TLS record stream is observed by a loopback test server and normalized
  into ClientHello fields;
- the TLS-decoded byte stream is observed by the same test server and normalized
  into the initial HTTP/2 preface, SETTINGS, and connection-window behavior.

Default rustls samples:

```sh
./scripts/fingerprint-lab.sh runtime-evidence/fingerprint-lab rustls --samples 5
```

Current rustls plus feature-gated BoringSSL samples:

```sh
MAVERICK_FINGERPRINT_BROWSER_TLS=1 \
./scripts/fingerprint-lab.sh runtime-evidence/fingerprint-lab all --samples 5
```

The browser build is intentionally explicit because compiling BoringSSL is a
larger and less portable operation than the default rustls build.

Optional imported browser reference:

```sh
./scripts/fingerprint-lab.sh runtime-evidence/fingerprint-lab rustls \
  --reference-clienthello /path/outside/repo/clienthello-records.bin \
  --reference-label browser-family-version-platform
```

The imported file must begin with TLS records containing a complete
ClientHello. Keep raw captures outside the repository. The report records only
the supplied neutral label and normalized fields, never the source path or SNI
value.

Preferred real-browser loopback reference:

```sh
MAVERICK_FINGERPRINT_BROWSER_TLS=1 \
./scripts/fingerprint-lab.sh runtime-evidence/fingerprint-lab all --samples 5 \
  --reference-browser-binary /path/to/chrome \
  --reference-label "Google Chrome 150.0.7871.115 headless / macOS arm64"
```

The lab launches the explicitly supplied browser binary with a fresh temporary
profile, disables its background networking, and points it only at a temporary
`localhost` TLS/H2 listener. It terminates the process after each sample. The
browser path and temporary profile are never serialized. Only normalized TLS
and H2 observations, the neutral label, and comparison results enter reports.

Outputs:

- `fingerprint-report.json`: full normalized samples for investigation;
- `fingerprint-summary.json`: compact machine-readable baseline;
- `fingerprint-report.md`: human-readable summary.

Interpretation:

- `ja3_input` is the canonical JA3 input text. The lab does not add an MD5
  dependency merely to print the traditional JA3 hash.
- `ja4_inputs` records relevant normalized inputs, not a canonical JA4 hash.
- GREASE values are retained in raw observations and removed from normalized
  comparison-set hashes.
- TLS extension ordering may vary between samples. The report therefore keeps
  both observed variants and order-insensitive normalized-set hashes.
- H2 SETTINGS/ACK/WINDOW_UPDATE ordering may race slightly. The report keeps the
  observed sequence and a normalized SETTINGS/window hash separately.
- A missing real-browser reference is reported as `not_provided`, never as a
  passing comparison.
- Schema v2 records real-browser sample count, normalized TLS/H2 hashes, and a
  field-level browser-mimic comparison.

The first target is Google Chrome `150.0.7871.115` in headless mode on macOS
arm64. Current browser-mimic measurements match the target's TLS cipher list,
supported groups, ALPN, H2 SETTINGS order/values, and H2 connection window. The
normalized H2 hash matches. TLS still differs because the current BoringSSL
Rust API does not expose Chrome's ALPS application-settings extension and does
not provide Chrome's three newer signature algorithms. These are release-gate
residuals, not permission to claim exact browser equivalence.

The current evidence-backed browser-tls build targets are
`aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`. Other targets are not
silently treated as equivalent; private-mode browser profile validation remains
closed until a target-specific build and measurement gate is added.

Before any stronger browser-like claim:

1. pin a browser family, version, and platform;
2. capture several real-browser samples;
3. compare normalized TLS fields, ALPN, H2 SETTINGS, and observed ordering;
4. explain every remaining difference;
5. repeat on every supported release target;
6. keep the public claim weaker than the measured evidence.

## Active-Probe Lab

The active-probe lab compares ordinary reference behavior with unauthenticated
Maverick behavior through deterministic loopback static and reverse-proxy
fallbacks:

```sh
./scripts/active-probe-lab.sh runtime-evidence/active-probe-lab
```

Outputs:

- `active-probe-report.json`: machine-readable response observations and gaps;
- `active-probe-summary.json`: compact scenario and coverage baseline;
- `active-probe-report.md`: scenario and coverage summary.

Response comparison includes status, normalized headers, trailers, body length,
and body SHA-256. A separate 12-sample loopback distribution records minimum,
median, p95, and maximum elapsed microseconds. Timing remains excluded from
response-shape equality and has no parity threshold.

The current matrix measures 13 deterministic response-shape scenarios:

- static same-path ordinary, malformed, and bad-auth H2 behavior;
- direct origin versus reverse proxy across GET, HEAD, POST, PUT, PATCH, DELETE,
  and OPTIONS, including paths, queries, selected headers, and request bodies;
- malformed, bad-auth, and auth-rate-limited reverse-proxy fallback;
- a generic `502 Bad Gateway` shape for failed upstream connections.

The report also keeps non-equivalent surfaces visible: admission exhaustion has
a bounded generic `503`; the explicit WebSocket carrier rejects a wrong upgrade
path instead of invoking HTTP fallback; H3 remains feature-gated; HTTPS
upstreams are unsupported; and fallback bodies remain bounded and buffered
without trailer forwarding. TLS/ALPN measurements remain in the separate
fingerprint lab rather than being converted into an origin-parity claim.

The lab is allowed to report differences. A failing comparison is evidence for
the hardening queue, not a harness failure and not permission to claim the
overall fallback is indistinguishable.

## Checked-In Baselines

`test-vectors/stealth/fingerprint-baseline.json` was regenerated from revision
`7169e2009587` with five samples per Maverick profile and five real-browser
samples. It records:

- stable order-insensitive TLS variants for rustls, browser-mimic, and the
  pinned browser reference;
- BoringSSL TLS exporter channel binding availability;
- an exact normalized H2 match between browser-mimic and the pinned reference;
- the two remaining TLS field differences instead of an equivalence claim.

`test-vectors/stealth/browser-tls-chrome-150-macos-arm64.json` adds the target,
capture/privacy boundary, residual explanations, supported build targets, and
explicit false claims. `scripts/check-browser-tls-baseline.py` turns those
facts into a mechanical gate and can compare a newly generated browser-mimic
summary against the checked-in hashes.

`test-vectors/stealth/active-probe-baseline.json` was regenerated from revision
`bc77f182d9e0`. All 13 comparable response-shape scenarios pass, including the
two rejected-tunnel body cases that failed the initial baseline. The file also
records the 12-sample timing diagnostic and nine explicit coverage/residual
states. `scripts/check-active-probe-baseline.py` rejects scenario regressions,
hidden residuals, timing-parity claims, or stronger privacy claims.

These compact files contain no raw packets, SNI values, hostnames, addresses,
certificate paths, credentials, or private infrastructure metadata.
