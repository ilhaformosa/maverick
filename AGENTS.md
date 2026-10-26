# Maverick Agent Guide

## Highest-priority rule

This rule takes precedence over all other guidance in this document.

> Before adding complexity for a speculative or vanishingly unlikely race or security edge case, explain the concrete failure mode, likelihood, and complexity cost to the user and get their buy-in. Do not silently expand scope for theoretical robustness.

## Project

Maverick is an experimental Rust privacy proxy. Product code and Rust
integration tests live under `crates/`.

- `STATUS.md`: current product state and authorization.
- `ROADMAP.md`: execution order.
- `docs/archive/` and `scripts/archive/`: historical reference, not active work.

## Working approach

- Solve the current problem with the smallest clear implementation.
- Reuse existing code and tools. Add abstractions, dependencies, retries,
  fallbacks, or extra validation only for a concrete requirement or observed
  problem.
- Keep changes focused on the requested outcome. Avoid unrelated refactors
  and new coordination frameworks.
- Make routine technical decisions within the user's existing authorization.
- Keep `scripts/user-smoke.sh` short and readable.
- Update `STATUS.md` when product state changes and `ROADMAP.md` when execution
  order changes. Do not routinely update archived documents.

## Verification

Test the behavior that changed.

- Use `./scripts/user-smoke.sh` for end-to-end product changes.
- Use `./scripts/local-harness.sh` for cross-component or security-sensitive
  changes.
- For documentation-only changes, review the diff; runtime tests are unnecessary.
- Do not repeat passing checks without relevant changes or failures.

## Practical boundaries

- Do not change this Mac's network settings. Local tests use `127.0.0.1`
  and OS-assigned ephemeral ports.
- Real-network trials require a named owner-controlled environment and
  explicit user authorization.
- Keep credentials and private infrastructure details out of git. Preserve
  authorized attribution.
- Preserve the Maverick name and accurate Beta/non-production claims.
