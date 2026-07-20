# Roadmap Blockers

Status: no active Maverick protocol-roadmap blockers remain.

The machine-readable registry is `roadmap-blockers.json` and is checked by
`scripts/check-roadmap-blockers.py`. This file explains how the former blockers
are now handled. It is not a stability, audit, production, or standardization
claim. It also is not a censorship-resistance claim.

The current handling plan is tracked in `docs/BLOCKER_RESOLUTION_PLAN.md`.

## Active Blockers

None.

## Non-Blocking Tracks

- `native_ech_upstream_dependency` (former `ech_handshake_integration`):
  native Maverick server-side ECH still depends on upstream server-side TLS
  backend support. The immediate workaround is the Cloudflare-fronted WebSocket
  carrier documented in `docs/ECH_WORKAROUND.md`. Cloudflare handles
  client-facing ECH; Maverick runs as the origin. This is useful, but it is not
  native Maverick server-side ECH. This remains a core long-term tracking item
  and is indexed in `docs/NATIVE_ECH_TRACKING.md`.
- `macos_app_product_release` (former `gui_tray_runtime`): GUI/App release,
  Packet Tunnel signing, notarization, and packaging belong to the separate
  macOS app product track. Maverick keeps SDK, diagnostics, profile, and
  conformance boundaries.
- `community_security_review_after_public_release` (former
  `external_security_review`): no formal human audit is expected before the
  initial public as-is release. Third-party AI review is acceptable pre-release
  engineering input. Human/community review can happen after public release.
  Maverick must not claim audited, production-ready, stable, or formally
  reviewed security status without matching evidence.
## Completed Prototype Scope

- `tun_device_apply`: approved-VM coverage on `approved-linux-vm` includes helper
  apply/rollback, retained-journal recovery, namespace runtime smoke,
  default-route/DNS policy smoke, service-manager lifecycle smoke,
  leak/coexistence smoke, and full-helper aggregate smoke. This is not a
  production full-device TCP/IP relay or stability claim.
- `noise_transcript_runtime`: Snow 0.10.0 is selected as the candidate
  implementation, implementation-backed transcript/prologue vectors and
  downgrade rejection tests exist, and the core feature-gated Noise XX session
  harness supports encrypted Maverick frame round trips. Product config
  exposure remains deferred, and Noise is not a default transport or security
  claim.

## Harness

The checker validates this registry when the registry is edited. It is metadata
validation, not default runtime proof.
