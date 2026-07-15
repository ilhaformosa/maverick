# Long-Term Direction: After v1.0.0

Status: long-term direction reference. `docs/PLAN_POST_V1.md` is the active
execution plan and decides when a track is reactivated. Each track ships only
behind its own review and evidence, and only when it reduces a concrete risk
without weakening the frozen default path.

The long-term goal is to become a genuinely stealthy, self-hostable single-hop
privacy proxy and then grow into an open protocol with independent
implementations, standardization work, and community governance. Tracks remain
reorderable so this destination does not force premature process or weaken 1.0.

## Standing Invariants (never traded away)

- The frozen `maverick-tls-h2-cli-v1` default path stays small, boring, and the
  mandatory fallback.
- No experimental transport or cryptography in the default path.
- No host-network mutation during development on this machine.
- No new security claim without matching evidence and, for strong claims,
  independent review.
- User-facing complexity stays low: `auto`/`stable`/`private` policy modes, not
  raw transport switches.

## Track A: Stealth as a Real Claim (highest value)

The v1 planning process pulled the measurement and honest-claim work forward,
and the post-v1 M2-M6 sequence implements the next evidence layers. This track
now supplies long-term rationale only; `docs/PLAN_POST_V1.md` owns execution
order and current status.


The current honest position: default TLS does not mimic a browser, shaping is
"engineering baseline," fingerprinting is best-effort. Turning stealth into a
defensible claim is the single most valuable long-term investment.

Milestones (gated, sequential):
1. Reproducible fingerprint evidence: automated JA3/JA4 + packet-capture
   comparison of the `browser-tls` path vs. real browsers; publish deltas.
   Only after this may any "browser-like" claim strengthen.
2. Active-probing coverage expansion: extend fallback-shape equivalence tests
   from H2 to WebSocket handshake and (gated) H3 admission-exhaustion paths.
3. Measurable traffic-shaping: use `shape-lab` traces to quantify
   classifier-visible deltas and overhead; publish a threat-scoped result
   before any traffic-analysis-resistance language.
4. Native server-side ECH: still the core tracked item
   (`docs/NATIVE_ECH_TRACKING.md`). Blocked on a reviewed server-side TLS
   backend; keep Cloudflare-fronted WebSocket as the acknowledged workaround
   until then. Do not claim provider-independent ECH before native support.

Exit: a stealth claim that a skeptical reviewer accepts, backed by published
captures — not marketing language.

## Track B: Deployment Reach

Grow *how* people run the frozen protocol without changing the protocol.

1. Server production profiles: hardened Linux packaging, upgrade/rollback,
   monitoring integration, multi-user operations at scale.
2. Client reach: promote the H3/QUIC carrier from experimental to a reviewed,
   evidence-backed optional transport (never replacing H2 fallback).
3. Product TUN mode: only after stealth/multiplexing/lifecycle are stronger;
   requires the missing integrated TUN packet-I/O adapter plus a real
   product-TUN runtime story. Keep all system-mutation testing on approved
   hosts.
4. GUI/tray app: ship an actual client app (currently SDK/diagnostics only).
   Separate release scope, signed/notarized, with its own verification.

Each item is a separate release scope with separate notes; none is a 1.0
prerequisite.

## Track C: Cryptographic Agility

Framework exists (registry/policy); all entries are disabled experiments.

1. Keep TLS 1.3 as the security foundation; never replace it with unaudited
   custom crypto.
2. Mature HPKE/Noise experiments only as feature-gated, reviewed alternatives.
3. Post-quantum hybrid: adopt when upstream TLS support lands and review
   justifies it — as an additive hybrid, not a default swap.

## Track D: Ecosystem and Standardization

This is an explicit long-term goal, activated once there is real external usage
or a credible second implementation.

1. Spec/conformance: keep frozen vectors authoritative; publish the wire format
   for third-party implementers.
2. Second implementation: the strongest signal the protocol is real; actively
   court or seed one.
3. Governance: lightweight, activated by contributor volume — do not front-load
   process before there are contributors.

## Track E: Sustainability

The long-term risk is not features; it is maintenance load.

1. Keep the doc/manifest debt low (the S0 cleanup must not re-accumulate).
2. Public feedback + triage loop (`docs/PUBLIC_FEEDBACK_PROCESS.md`) kept live.
3. CI cost and flake budget managed as the harness grows.

## Sequencing Principle

Prefer depth on Track A (stealth) before breadth on Track B (reach). A proxy
that is easy to run but trivially fingerprinted fails its own purpose;
strengthen the core privacy story first, then expand deployment surface. Revisit
this ordering with the owner once the long-term goal is defined.

## Reviewer Role (ongoing)

For every long-term track the same loop applies as in the short-term plan:
owner selects a track/milestone -> engineers implement behind a gate -> AI
reviewer audits scope, evidence, and claim honesty before it graduates from
experimental. No track weakens the frozen default path or its invariants.
