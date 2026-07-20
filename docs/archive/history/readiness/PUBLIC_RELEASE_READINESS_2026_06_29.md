# Public Release Readiness - 2026-06-29

Status: superseded pre-publication readiness assessment. The later complete
history audit found that the private repository could not safely be made
public; see `docs/OPEN_SOURCE_PHASE1_GO_NO_GO_2026_07_15.md`.

This is not a stable release, production-readiness claim, formal audit result,
protocol freeze, standardization claim, anonymity claim, or censorship-
resistance guarantee.

## Release Boundary

This historical assessment considered a personal open-source protocol
prototype under Apache-2.0. It did not include the later complete history and
tag-archive audit, so its publication conclusion is no longer active.

- experimental Rust prototype;
- not audited;
- not production-ready;
- no browser-grade TLS fingerprint mimicry claim;
- no strong anonymity or traffic-analysis resistance guarantee;
- Native ECH remains a core tracking item, not implemented runtime support.

## Native ECH Boundary

Native Maverick server-side ECH is tracked in
`docs/NATIVE_ECH_TRACKING.md`. The immediate workaround is the
Cloudflare-fronted WebSocket carrier documented in `docs/ECH_WORKAROUND.md`.
That workaround is acceptable for current experimental work, but it must not be
described as native, provider-independent, stable, audited, or production-ready
ECH support.

## Verification Run

Commands completed on 2026-06-29:

```sh
./scripts/local-harness.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

Additional pre-release dependency and unsafe-code inventory was added on
2026-06-30:

```sh
./scripts/security-dependency-inventory.sh
```

Relevant results:

- local harness OK;
- H3 harness OK;
- ECH feature harness OK;
- benchmark baseline OK for 64 KiB payloads with concurrency 1 and 4;
- benchmark dashboard updated;
- dependency advisory and first-party unsafe-code inventory gate added;
- roadmap blockers OK: 0 blocked, 0 deferred;
- security review package OK: 50 artifacts;
- freeze readiness remains blocked for stable/frozen claims, as intended.

## Known Public Limitations

- No native server-side ECH.
- No formal third-party human security audit.
- No stable protocol freeze.
- No production packaging.
- No GUI/mobile app in this repo.
- Experimental transports and crypto remain default-off.

## Decision

It is reasonable to make the GitHub repository public after committing the
current changes, provided the repository description and announcement preserve
the experimental as-is status and do not imply stable, audited, production, or
native ECH support.
