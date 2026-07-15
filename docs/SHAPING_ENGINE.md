# Padding and Shaping Engine Design

Status: design complete for v3 planning. Config validation,
`BudgetedPaddingPolicy`, client-side outbound padding frames, bounded
client-side pacing delay, and runtime tunnel batching baselines are
implemented. Server-side outbound padding is implemented for authenticated
tunnel responses, and aggregate shaping padding metrics are implemented without
target labels. Cover-traffic budget planning, operator-decision, bounded
padding-frame emission, and minimal client/server runtime wiring are
implemented behind explicit config and operator-approval gates.

The v3 shaping engine should provide measurable engineering controls for frame
padding, batching, and pacing. It must not claim strong traffic-analysis
resistance without evidence from the v3.5 shape regression lab.

## Goals

- Keep all padding and delay budgets bounded.
- Preserve stable H2 behavior when shaping is disabled.
- Avoid user-facing transport complexity.
- Make `private` mode stricter without turning it into a magic anonymity claim.
- Provide metrics that explain overhead and latency introduced by shaping.

## Non-Goals

- Defending against global traffic correlation.
- Browser TLS fingerprint impersonation.
- Unlimited cover traffic.
- Any mode that silently buffers user traffic without bounded delay.

## Policy Model

The existing `mode` remains the user-facing policy selector:

```text
stable  -> no shaping except protocol-required padding
auto    -> low overhead padding and minimal batching
private -> stricter padding and pacing within explicit budgets
```

Advanced config should expose bounds, not a large menu of fingerprints:

```yaml
advanced:
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
```

`cover_traffic` is default-off and requires both `enabled: true` and
`cover_traffic_operator_approved: true`. The current runtime wiring is minimal:
it emits at most one bounded `Padding` frame for an eligible observed payload
event and does not generate idle background cover traffic.

The current operator-decision model is intentionally pre-runtime:

```text
ready only if:
  shaping.enabled == true
  cover_traffic == true
  mode != stable
  operator_approved == true
  window > 0
  observed_payload_bytes > 0
  budget planner returns a bounded plan
```

Config validation rejects cover traffic without shaping enablement, explicit
operator approval, and a bounded window.

## Frame-Level Padding

The current `PaddingPolicy` can evolve from a fixed placeholder into a budgeted
policy:

```text
padding_allowed = min(
  max_padding_bytes_per_frame,
  remaining_flow_padding_budget,
  overhead_budget_for_payload_size
)
```

Handshake frames should not receive random padding until the auth transcript and
wire compatibility story are explicitly versioned.

Implemented baseline:

- `advanced.shaping` config defaults to disabled.
- `cover_traffic: true` requires `advanced.shaping.enabled=true`,
  `cover_traffic_operator_approved=true`, and a bounded
  `cover_traffic_window_ms`.
- `BudgetedPaddingPolicy` caps padding by per-frame byte cap and overhead
  ratio.
- Handshake and error frames receive no optional budgeted padding.
- Client tunnel sends bounded `Padding` frames before eligible outbound frames
  when shaping is enabled.
- Server tunnel sends bounded `Padding` frames before eligible authenticated
  outbound response frames when shaping is enabled.
- Client tunnel applies bounded pacing delay before eligible post-auth outbound
  frames when shaping is enabled.
- Pacing delay skips handshake, FIN/reset/close, error, padding, and frames at
  or above `max_batch_bytes`.
- `RuntimeBatcher` queues only eligible data frames, flushes when
  `max_batch_bytes` is reached, flushes when the delay cap is reached, and
  releases queued data before FIN/reset/control frames.
- Client tunnel writes use `RuntimeBatcher` for eligible outbound frames before
  applying padding and transport writes.
- `stable` mode disables optional runtime padding, pacing, and batching even if
  `advanced.shaping.enabled=true`.
- Client and server config validation reject `log.redact: false`; the prototype
  does not support a non-redacted operational logging mode.
- Loopback metrics expose aggregate `shaping_padding_frames` and
  `shaping_padding_bytes` counters without per-target or per-user labels.
- Loopback metrics expose aggregate `cover_traffic_padding_frames` and
  `cover_traffic_padding_bytes` counters without per-target or per-user labels.
- `CoverTrafficPlan` models bounded cover traffic with no idle-flow emission,
  no stable-mode enablement, an observed-payload overhead budget, the existing
  batch cap, and deterministic per-window spacing.
- `CoverTrafficDecision` adds an explicit operator approval gate, nonzero
  window requirement, observed-payload requirement, and reason codes for local
  diagnostics.
- `CoverTrafficEmitter` turns an approved plan into bounded `Padding` frames
  for runtime integration. Client/server runtime paths emit at most one cover
  padding frame per eligible observed payload event.
- Client and server readers skip `Padding` frames before protocol dispatch.
- Unit tests cover cap, ratio, frame exclusions, mode ordering, runtime
  padding-frame construction, delay-budget enforcement, and bounded batcher
  decisions.
- Loopback TCP relay tests cover client-side runtime padding, server-side
  runtime padding, and runtime batching without touching system proxy, DNS,
  route, firewall, VPN, or other network-service settings.

## Batching and Pacing

Batching may coalesce small authenticated frames for up to `max_delay_ms`.
Runtime tunnel writes now pass eligible frames through `RuntimeBatcher` before
padding and transport writes. The current client tunnel writer is still a
single mutable async path, so this is a conservative bounded batching baseline
rather than a high-throughput multi-read coalescer. Current pacing and batching
remain deterministic and bounded; future jitter must remain within the same
cap.

Rules:

- Never delay pre-auth fallback decisions for shaping.
- Never hold a TCP FIN indefinitely.
- Flush immediately when a batch reaches `max_batch_bytes`.
- Disable shaping for flows that exceed memory or delay budgets.
- Report counters for bytes padded, frames padded, batches emitted, and delay
  budget exhausted.

## Failure Behavior

When shaping cannot run within budget, Maverick should continue without extra
shaping for that flow and increment a coarse metric. It should not close the
connection solely because a padding budget is exhausted.

## Private Mode Logging

When `mode = private`, implementation should prefer:

- redacted target hosts in ordinary logs;
- no payload sizes in info-level logs;
- coarse transport failure classes;
- no per-destination metrics labels;
- explicit debug opt-in for local diagnostics.

## Required Tests

- Padding never exceeds configured byte cap.
- Total overhead ratio remains under configured cap for a deterministic trace.
- Client-side padding frames are skipped by the server without changing relay
  semantics.
- Server-side padding frames are skipped by the client without changing relay
  semantics.
- Batching flushes on byte cap. Implemented in core batcher tests.
- Batching flushes on time cap. Implemented in core batcher tests and runtime
  loopback relay coverage.
- FIN and reset frames are not delayed past the cap. Implemented in core
  batcher tests.
- `stable` mode produces no optional shaping. Implemented for runtime padding,
  pacing, core batcher decisions, and runtime batching.
- Non-redacted operational logging is not a supported mode. Config validation
  rejects `log.redact: false`.
- Metrics expose aggregate shaping counters without target labels. Implemented
  for runtime server-side padding counters.
- Cover-traffic planning does not produce frames when disabled by default, in
  `stable` mode, without observed payload bytes, or beyond overhead/batch caps.
  Implemented in core unit tests.
- Cover-traffic operator decisions reject missing approval, invalid windows,
  missing observed payload budgets, and unavailable budgets. Implemented in
  core unit tests.
- Cover-traffic emitter tests prove emitted padding frames stay within
  per-window frame and byte caps. Runtime integration tests cover client relay
  semantics and server-side cover metrics.

## v3.5 Lab Handoff

The v3.5 shape lab should consume deterministic loopback traces from:

- direct TCP echo baseline;
- H2 without shaping;
- H2 with `auto` shaping;
- H2 with `private` shaping;
- H2 with `stable` mode and shaping flags enabled, proving policy gating keeps
  optional shaping off;
- H3 equivalents when the `h3` feature is enabled.

The loopback lab script now emits auto baseline plus stable/auto/private
runtime shaping scenario rows. The lab output is diagnostic only. It must not
be described as an anonymity proof.
