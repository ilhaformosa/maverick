# Spec Freeze Process

Status: v6 design complete. The first narrow stable-scope candidate is defined
in `docs/STABLE_SCOPE_CANDIDATE.md`. Only the narrow
`maverick-tls-h2-cli-v1` scope is frozen for v1.0.0; no production,
formal-audit, anonymity, censorship-resistance, standardization, or
browser-fingerprint-equivalence claim is made. A freeze-readiness checker
records current blockers, and a frozen-release vector immutability checker
protects the current conformance vector snapshots. An implementation-registry
checker records the Rust prototype plus no-network Python verifier without
making normative claims.

Maverick should not freeze a public protocol specification until the
implementation, tests, security review, and migration story are stable enough
to support other implementers.

## Freeze Levels

```text
draft      -> implementation may change wire behavior
candidate  -> wire behavior is expected to hold, conformance tests required
frozen     -> compatible changes only
deprecated -> migration path exists, new use discouraged
removed    -> no longer accepted
```

## Freeze Criteria

Before a candidate freeze:

- `SPEC.md` and `WIRE_FORMAT.md` agree with implementation;
- `docs/STABLE_SCOPE_CANDIDATE.md` names the candidate scope and exclusions;
- spec/wire frame type alignment checker passes;
- local and H3 harnesses pass;
- conformance vectors exist for auth, replay, frames, DNS, TCP, and UDP;
- fallback behavior is documented and tested;
- all experimental features are clearly marked;
- security limitations are current.
- `conformance/freeze-readiness.json` has no partial or blocked candidate
  criteria.

Before a frozen release:

- at least two implementations or one implementation plus a parser/verifier;
- external security review plan in `docs/SECURITY_REVIEW_PLAN.md`;
- migration policy for previous draft behavior;
- governance process for compatible extensions.
- frozen conformance manifest snapshot recorded in
  `conformance/frozen-releases.json` and passing `scripts/conformance.sh`.
- implementation registry recorded in
  `conformance/implementation-registry.json` and passing
  `scripts/conformance.sh`.
- `conformance/freeze-readiness.json` has no partial or blocked frozen
  criteria.

## Change Control

Every wire-affecting change should include:

- spec diff;
- implementation diff;
- conformance vector update;
- compatibility note;
- downgrade or fallback risk note.

After a frozen release, existing frozen vector files must not be edited in
place. Additive changes should use new vector ids or a new release snapshot so
older implementers can continue testing against the frozen byte sequences.

## Non-Goals

- Freezing experimental crypto.
- Freezing TUN or GUI behavior as protocol behavior.
- Claiming standardization before multi-implementation feedback.
