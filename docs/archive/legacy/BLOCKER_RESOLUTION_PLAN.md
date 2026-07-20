# Blocker Resolution Plan

Status: no active roadmap blockers remain after the current scope decisions.

This document records how the former blockers are resolved, downgraded, or
moved out of the Maverick protocol repo. It is not a production, audit,
stable-release, censorship-resistance, or standardization claim.

## Current State

`roadmap-blockers.json` has an empty `blockers` list and tracks former blockers
under `non_blocking_tracks`.

## Resolved Or Downgraded Tracks

### Native ECH Runtime

Current status: tracked upstream dependency with an immediate workaround.

Decision:

- keep native `advanced.experimental_ech` rejected until a reviewed
  server-side ECH TLS backend exists;
- use the Cloudflare-fronted WebSocket carrier as the immediate workaround;
- document clearly that Cloudflare-fronted ECH is not native Maverick
  server-side ECH.

Evidence:

- `docs/ECH_NATIVE_TLS_LIMITATION.md`
- `docs/NATIVE_ECH_TRACKING.md`
- `docs/ECH_UPSTREAM_STATUS.md`
- `docs/ECH_RUNTIME_PLAN.md`
- `docs/ECH_WORKAROUND.md`
- `docs/history/manifests/ech-runtime-blockers.json`
- `docs/history/manifests/ech-runtime-approval.json`

User action currently required: none. A future native ECH push would require
upstream rustls server-side ECH support, sponsoring that upstream work, or a
separate TLS-stack replacement research spike.

### GUI/App Runtime

Current status: moved to separate app product track.

Decision:

- do not keep GUI/App release as a Maverick protocol-roadmap blocker;
- keep protocol repo responsibilities limited to SDK, diagnostics, profile,
  service lifecycle, and conformance boundaries;
- keep Packet Tunnel, signing, notarization, packaging, and product UI release
  in the macOS app project.

Evidence:

- `docs/MACOS_APP_BOUNDARY.md`
- `docs/GUI_TRAY_ARCHITECTURE.md`
- `docs/SDK_PLAN.md`
- `docs/history/manifests/gui-runtime-blockers.json`
- `scripts/gui-runtime-smoke.sh`

User action currently required: none for Maverick. Future app release work may
require Apple Developer account, certificates, signing identities, and a test
Mac, but that belongs to the app project.

### External Security Review

Current status: downgraded to release-note and community-review gate.

Decision:

- no formal third-party human audit is required before the initial public
  as-is release;
- third-party AI review is acceptable pre-release engineering input;
- human/community review is expected only as a post-public possibility;
- the project must not claim audited, production-ready, stable, formally
  reviewed, or proven censorship-resistant status without matching evidence.

Evidence:

- `docs/SECURITY_REVIEW_PLAN.md`
- `docs/history/review/SECURITY_REVIEW_TRIAGE_2026_06_28.md`
- `docs/history/review/AI_SECURITY_REVIEW_PROMPT_2026_06_28.md`
- `security-review-package.json`
- `SECURITY.md`

User action currently required: none unless a future release wants stronger
security claims.

## Rule For Future Blockers

A former blocker must not be reintroduced as an active roadmap blocker unless:

- it blocks a concrete Maverick protocol repo deliverable;
- the required evidence is source-tracked;
- the checker or harness validates the evidence;
- no local workstation network settings are mutated;
- no production, audit, stable-release, or censorship-resistance claim is
  introduced without matching evidence.
