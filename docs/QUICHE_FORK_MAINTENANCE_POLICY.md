# quiche fork maintenance policy

Date: 2026-08-12

Task: B-002-S1; policy precision B-002-S3-2B/S3-2D (2026-08-13)

Status: **document-only policy/SLA evidence; B-002 remains RED**

## Purpose and claim boundary

This document freezes the minimum maintenance contract that must exist before
Maverick can either retain any private quiche patch or prove that an old patch
is no longer required. It is not a patch registry, an adoption decision, a
replay result, an upstream report, a security review, or permission to add
quiche, vendor source, product Cargo dependencies, H3 runtime, or H3 to Auto.
The test-tool dependency exception for the S2 synthetic verifier, the
candidate-test exception, and the later candidate-bound P3 logging-surface
exception are defined narrowly below. None is a product dependency or adoption
exception.

The owner has selected quiche as Maverick's only intended H3/UDP backend. That
direction does not make the preserved fork acceptable. Until every gate below
passes, B-002 is RED and product H3 stays disabled. Quinn is not a fallback.

This S1 slice defines policy and deadlines only. It does not contact
upstream, fetch source, apply a patch, run the future replay procedure, or
record an independent vendor-delta review.

## Frozen responsibility model

The following roles are explicit. A role assignment does not substitute for
evidence or let the same author approve their own work.

| Role | Frozen responsibility |
|---|---|
| Accountable principal — Maverick repository owner identified by the root `.github/CODEOWNERS` rule | Ultimately accountable for the repository and any accepted private-fork risk. `CODEOWNERS` provides review routing only; it does not supply or replace the independent review required below. The standing delegation means routine technical choices do not wait for another owner decision. |
| Delegated maintainer — Codex | Performs triage, proposes a `DROP` or `RETAIN` disposition, runs the bounded local workflow, records exact revisions and hashes, and disables or keeps H3 disabled when a gate or deadline fails. |
| `H3-PROTOCOL-SAFETY` | Operational owner for strict peer-push behavior and the inseparable adoption-hardening surface. |
| `H3-PRIVACY-LOGGING` | Operational owner for the H3 trace-privacy delta and its stated exclusions. |
| `DEPENDENCY-SECURITY` | Operational owner for official source and license verification, Boring closure, advisories, upgrade timing, dependency inventory, and target-aware SBOM evidence. |
| Independent replay and qualification maintainer | Executes the real historical reconstruction, selected-candidate replay, and candidate qualification. This maintainer must not have authored or modified an original patch; the S2 verifier, fixed constants, or self-tests; the S3 historical or selected-candidate real constants; the selected candidate; its Cargo/package or dependency/Boring solution; or the evidence being executed. They cannot review their own output and are not the final independent delta reviewer. No qualifying execution exists yet. |
| Independent delta reviewer | A reviewer who did not author, modify, own, or produce the selected candidate, patch, disposition, tests, replay verifier/constants/run/output, Cargo or package delta, dependency/Boring solution, upstream route or cannot-upstream exception, or any evidence under review. This role is separate from the independent replay maintainer. The final report uses only a public-safe reviewer identifier, binds to exact hashes, and states findings; it must not record an agent/session identifier or local path. No qualifying review exists yet. |

Patch ownership is therefore frozen as follows:

| Patch | Operational owner | Cross-cutting owner |
|---|---|---|
| P1 strict peer-push gate | `H3-PROTOCOL-SAFETY` | `DEPENDENCY-SECURITY` |
| P2 adoption-review hardening | `H3-PROTOCOL-SAFETY`; it has no independent product purpose and travels with P1 | `DEPENDENCY-SECURITY` |
| P3 H3 trace privacy | `H3-PRIVACY-LOGGING` | `DEPENDENCY-SECURITY` |

These assignments make responsibility explicit but only **PARTIAL**. They do
not decide whether a patch is needed, provide an upstream route, prove a clean
rebase, or supply the independent reviewer and result required for adoption.

## Official preimage and dependency boundary

During S1, a read-only check observed the official `quiche` 0.29.3 archive in
the local Cargo registry cache. The check recorded only public provenance
values:

| Object | Observed value |
|---|---|
| `.crate` SHA-256 | `61166d27591eb7cb1310eec2b8fc6ae0e0686e9e4ed742a3ffc6317171175e7d` |
| Locally cached crates.io index checksum | same SHA-256 |
| `.cargo_vcs_info.json` upstream commit | `09b125d4cfc16e78d73d8382c93926f3aba063d4` |
| `COPYING` SHA-256 | `2ef4b5abfce387a83933bda738e72467a79d15c1c17679143ec55011dae66b84` |

This closes only the former question of whether an exact official preimage is
locally available. The archive was not patched or compared byte-for-byte with
the preserved vendor result in S1. A cache entry is not a replay, an
independent source attestation, or permission to commit the archive.

The official 0.29.3 package manifest requires `boring` 4.x through
`boring = "4.3"` when its Boring feature is used. At the exact S1 implementation
base `be5f3ae532037468edbb1d619731a223284164c5`, Maverick uses `boring` 5.1.0,
`boring-sys` 5.1.0, and `tokio-boring` 5.0.0 for the existing browser-like H2
path. This is a point-in-time observation, not a permanent version requirement.
Quiche adoption is blocked until one reviewed solution preserves all of these
invariants:

- do not downgrade Maverick's current Boring 5.x path;
- do not link or ship simultaneous Boring 4.x and 5.x `boring-sys` closures;
- do not hide the conflict in a private Cargo patch, unpublished TLS fork, or
  second cryptographic closure;
- use the exact future shipping H3 product feature set, not the default H2-only
  feature set, to prove on both currently supported release targets,
  `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`, that the resolved
  dependency graph, Cargo `links` closure, target-aware SBOM, link output, and
  final exact-candidate artifact contain exactly one accepted Boring 5.x /
  `boring-sys` closure and no Boring 4.x or second cryptographic closure; and
- independently review the source, license, security, build, and rollback
  effect of the dependency solution.

No dependency solution was implemented or approved by S1. This is a hard RED
before any quiche foundation or runtime import.

## Patch-specific disposition gates

Every patch starts `UNRESOLVED`. Each must receive one explicit `DROP` or
`RETAIN` result bound to the exact selected upstream version, official archive
hash, design, retained-patch set and hashes, test revision, Cargo/package
delta, dependency graph, supported target set, qualification evidence, and
independent review. Any change to one of those bound objects invalidates the
disposition and returns that patch to `UNRESOLVED`. A general statement such as
“the feature is disabled” or “the old tests pass” is not a disposition.

### P1 — strict peer-push gate

Patch SHA-256:
`74e9078d2e6c244b4fba2dbad185a8eb1adba6762d32286540ed645122be04fa`.

`DROP` requires evidence that the selected pure-upstream quiche version already
provides equivalent fail-closed behavior, or that the final pre-auth H3 design
makes the private behavior unnecessary. The proof must cover `MAX_PUSH_ID`,
`PUSH_PROMISE`, `CANCEL_PUSH`, push-form `PRIORITY_UPDATE`, and push-stream
activity; fixed privacy-safe errors; fragmented input; preserved SETTINGS,
QPACK, request, GOAWAY, reserved-frame, and request-priority behavior; and both
client and server roles where applicable.

`RETAIN` requires a demonstrated security necessity that upstream does not
provide, an independently testable patch, a clean official-source replay, and
the upstream-route-or-exception gate below.

### P2 — adoption-review hardening

Patch SHA-256:
`873ba92b498ba260ae097c47474d51ee79d6f94ac87efa3ba53337ca57404512`.

P2 narrows the helper introduced by P1 and documents P1's exact boundary. It
cannot be retained by itself. If P1 is dropped, P2 is also dropped. If P1 is
retained, P2 must be reviewed as part of the same upstream issue or PR rather
than creating a duplicate route, or be covered by the same still-valid written
cannot-upstream exception.

`DROP` requires proof that the selected P1/upstream shape exposes no broader
helper and its public setter documentation states the exact covered and
excluded behavior. `RETAIN` requires a unique API-surface or compile-time
visibility check in addition to the common replay and review gates. A text-only
diff without that proof remains RED.

### P3 — H3 trace privacy

Patch SHA-256:
`923c9ce876e76c7758ecebe8d9126572a245ea98019b467b66d5acc228ad2ee0`.

`DROP` requires proof that the selected upstream/runtime configuration prevents
H3 frame, stream, and QPACK trace formatting of peer-controlled details for
both roles without a private patch. Merely leaving the trace subscriber off is
not enough if sensitive values are still formatted before filtering.

`RETAIN` requires a demonstrated privacy need, independent tests for both
roles, a complete logging-surface review, clean replay, and its own upstream
route or still-valid written cannot-upstream exception under the common gate
below. The review must keep QUIC transport logs and qlog explicitly outside
P3's claimed coverage and resolve them as separate gates before adoption.

### Upstream route or written exception

Every retained P1 or P3 patch requires either an upstream issue/PR opened
within seven calendar days of its `RETAIN` disposition or a still-valid written
cannot-upstream exception. P2 follows P1's route or exception. An exception is
allowed only after an actual upstream route is rejected or independently shown
to be structurally impossible. It must state the exact patch and candidate,
public-safe reason, approver, approval date, and hard expiry; it expires at the
next minor quiche release or after 90 calendar days, whichever comes first.
An edit cannot renew it. While valid, it satisfies only the seven-day route
gate; it does not waive replay, qualification, security, dependency, review, or
release deadlines. On expiry, absence of the required route is an immediate
gate failure: the patch returns to `DROP`-or-stop and H3 remains or becomes
disabled. The two-release/180-day resolution clock below applies only to an
opened upstream route.

## Common `DROP` and `RETAIN` gates

A `DROP` result passes only when all of the following are recorded:

1. the exact upstream source and dependency candidate;
2. a patch-specific reason the private delta is not required;
3. focused tests that fail if the claimed upstream or design property is
   absent;
4. security/privacy review of the behavior without the patch;
5. exact-candidate qualification, license, and the full real-H3 one-Boring-
   closure evidence defined above for both supported release targets; and
6. a selected-candidate byte-only complete-result replay for the complete
   disposition set that applies exactly the retained set and proves this
   dropped patch and its delta absent; the retained set is empty only when all
   three patches are `DROP`; and
7. independent exact-hash review with no unresolved Critical or High finding.

A `RETAIN` result passes only when all of the following are recorded:

1. patch-specific security or privacy necessity;
2. official source, license, patch, and result hashes;
3. exact, fuzz-free, offline selected-candidate replay from the official
   archive;
4. a unique deterministic test for that patch;
5. the required upstream route or still-valid written exception;
6. a full maintained-delta review, including curated Cargo/package changes;
7. the full real-H3 single-Boring-5.x dependency, `links`, SBOM, and final-
   artifact gates on both supported release targets;
8. the security-release and rebase SLA below; and
9. removal of the separate Quinn product path before retained-fork adoption;
10. a complete rebase/replay by a maintainer without the original patch
    author's help; and
11. an independent exact-hash vendor-delta review with no unresolved Critical
    or High finding.

Mixed results are allowed only when every patch independently passes its own
disposition. No patch may be retained by ancestry or implication.

## Frozen offline replay contract

The later mechanical verifier must be local-only, deterministic, and
fail-closed. It must not download, fetch, update an index, or substitute a
different source. The verifier itself and its synthetic self-tests are a
separate S2 implementation slice; the first real official-archive replay is a
separate S3 evidence run.

### S2 implementation and build boundary

A focused portability probe rejected the proposed Ruby/Fiddle implementation:
the Darwin system Ruby 2.6 interface cannot safely express the variadic
`open`/`openat` call used with `O_CREAT`, and the probe created a file with an
incorrect zero mode. That route remains RED. Python validation tooling remains
archived and must not be revived or hidden behind an extensionless entrypoint.

S2 therefore has one exact tooling-only exception. It may add one non-product
verifier binary under the unpublished `maverick-tests` package and exactly:

- add `rustix = { version = "=1.1.4", features = ["fs", "process"] }`, with
  its default features retained;
- add `flate2 = { version = "=1.1.9", default-features = false, features =
  ["rust_backend"] }`;
- add `signal-hook = { version = "=0.4.4", default-features = false }` and use
  only its safe high-level flag API; and
- update `Cargo.lock` only for that exact tool graph.

These dependencies must not enter a product crate, default product binary,
runtime, vendor tree, quiche graph, config, wire path, or release claim. Any
additional package, feature, target, or Cargo surface requires a new review and
keeps S2 RED. `signal-hook` is expected to be the only additional lockfile
package beyond the exact `rustix`/`flate2` tool graph named above; the S2
implementation must prove the complete exact locked graph before it may pass.
Direct use of `signal-hook-registry`, a direct signal-handler closure,
`sigaction`, or first-party `unsafe` is forbidden. The only permitted
unregistration path is `signal-hook`'s safe public unregistration by the
registration IDs returned by the flag API.

The prior Tokio-only receiver design remains RED. Delivery can set Tokio's
internal pending state before the runtime driver broadcasts readiness; a
worker can finish in that interval, so selecting the worker branch cannot prove
that a delivered signal lost the success race. S2 must instead register `INT`,
`TERM`, and `HUP` before work begins so the safe flag API stores into one
`AtomicUsize` with `SeqCst` ordering. Its storage has exactly three values:
`ACTIVE`, `SIGNALLED`, and `COMMITTED`. A signal stores `SIGNALLED`; the
verifier may attempt exactly one `ACTIVE`-to-`COMMITTED` compare-exchange only
after replay work, exact cleanup, and prior-umask restoration all succeed. A
signal store ordered before that compare-exchange makes it fail and the outcome
is RED. A successful compare-exchange is the irrevocable outcome linearization
point: a later signal may overwrite the storage with `SIGNALLED`, but the
verifier never reads it again and the already committed outcome is not revoked.
Do not use a timer, yield, sentinel signal, second atomic, receiver, or inferred
ordering as the success barrier.

Building and self-testing the verifier is a separate local build phase; it may
use Cargo only before mechanical replay begins. Mechanical replay runs the
already-built, exact reviewed binary and must never invoke Cargo, rustc, a
build script, tests, or input-derived code. The binary remains single-purpose:
its production entry accepts exactly one repository-external `.crate` path and
no mode, profile, registry, schema, or expected-value override. It sets umask
`077` before work begins, restores the prior umask only after all creation and
cleanup have finished on every controlled exit, and uses the same cleanup guard
for `INT`, `TERM`, and `HUP`. Synthetic self-tests must send each exact signal
at deterministic barriers before final manifest verification and after cleanup
but before the `ACTIVE`-to-`COMMITTED` compare-exchange. Each case must prove
RED, exact cleanup, and prior-umask restoration. Safe unregistration does not
restore the previous or default signal disposition. Every signal-bearing
self-test or controlled non-production invocation therefore runs in its own
disposable child process; after unregistering every returned registration ID,
that child exits immediately and no shared or long-lived process continues.
After the production compare-exchange records `COMMITTED`, the process exits
successfully immediately, with no fallible work, output, or unregistration.

### Fixed verifier constants and immutable inputs

There is one narrow B-002 verifier. Its expected values are fixed constants and
an ordinary checksum list in the exact reviewed code diff: archive and local-
index checksums; exact archive byte length and hard maximum; upstream commit;
license path and hash; exact patch Git commit/tree/blob object IDs and SHA-256
values; application order, working
directory, strip level, allowlisted paths, per-stage hashes, complete-result
hashes, and comparison scope. It creates no registry, evidence schema,
persistent record, general framework, or coordination layer. Replay
output can never rewrite the fixed values.

The caller supplies only an out-of-repository `.crate` path. A CLI argument,
environment variable, workspace file, archive field, mutable Git ref, or
worktree file can never override or establish an expected value. S2 contains
only a built-in synthetic test mode, fixed synthetic constants, and self-tests.
The S3 historical run requires a separate narrow reviewed code diff that fixes
the real historical constants. A later selected-candidate run requires another
narrow reviewed code diff that replaces and fixes the exact candidate
constants. The verifier accepts no arbitrary configuration, mode identifier, or
expected-value input.

The verifier opens the supplied archive exactly once without following a
symlink, requires a regular file, and uses `fstat` before copying to require the
fixed exact byte length and hard maximum. An oversize or wrong-size file is RED
without reading the full archive. It hashes and copies bytes from that same open
file descriptor into its private workspace, rehashes the private copy against
the fixed checksum, and uses only that copy thereafter; it never reopens the
caller path. A mismatch is RED.

When the verifier reads reference or patch bytes from Git, it must set
`GIT_NO_REPLACE_OBJECTS=1`, `GIT_NO_LAZY_FETCH=1`, and
`GIT_OPTIONAL_LOCKS=0`, or use the equivalent `git --no-replace-objects`
invocation. It reads only fixed exact commit, tree, and blob object IDs. It
must not resolve a mutable ref or worktree, invoke a filter or hook, perform
lazy fetching, or contact a network.

### Historical reconstruction and selected candidate

S3 first runs historical-reconstruction constants fixed to official quiche
0.29.3 and the original P1, P2, and P3 artifacts. It applies P1 and P2 from the
staging `vendor` directory with strip level 1 and then P3 from the staging root
with strip level 1. It compares every patch stage and its patched upstream
source tree to the fixed checksum list. Archived omissions, curated Cargo/package
changes, dependency changes, and test-support files receive separate exact-byte
inventory and accounting against fixed Git objects. Patch reconstruction cannot
impersonate their provenance, and byte inventory does not prove how those
curated changes were produced. PASS proves only that the patched upstream
source is reconstructable and that the other preserved vendor bytes are
exactly accounted for. It has no disposition and is not an adoption candidate.

After proposed `DROP`/`RETAIN` decisions exist, separately reviewed selected-
candidate constants start the verifier from the exact selected official
upstream archive. It applies only independently reviewed, hash-fixed rebased
patches proposed for retention, in a fixed order and context. P2 appears only
if P1 is retained. Every dropped patch must be absent from both the applied set
and full result tree. If all three are dropped, the result is a pure-upstream
tree. Even if the selected candidate is again 0.29.3, it requires its own
reviewed constants and cannot inherit the historical result or expected bytes.

Both runs reject offsets, fuzz, already-applied hunks, rejects, unexpected
paths, a changed working directory, or any complete-result checksum
mismatch. The verifier must not repair, redownload, retry with a different
strip level, relax a comparison, or convert a historical PASS into a candidate
disposition.

### Secure temporary workspace

Only after immutable-input hash preflight passes, the verifier must set
`umask 077`, acquire one lock in a fixed task-private, repository-external,
non-symlink parent owned by the running user with mode `0700`, and atomically
create a never-before-existing child through the verified parent directory file
descriptor. A nonempty parent at startup is RED and requires a maintainer's
private read-only residue check; the verifier neither reuses nor deletes an old
child. It must not accept a caller-supplied work directory.
Extraction accepts only regular files and directories and rejects absolute or
parent-traversal paths, symlinks, hardlinks, devices, FIFOs, sockets, duplicate
entries, and normalized-path collisions. Fixed constants bound entry count,
total expanded bytes, per-file bytes, and normalized path length; exceeding any
bound is RED before the offending content is materialized.

One cleanup guard covers every normal return, error, panic, and catchable
interrupt for the exact child created by the current process. Before deletion
it revalidates the locked parent and child through saved directory file
descriptors; it never deletes through an unresolved path, glob, symlink, caller
environment variable, or path created by an earlier run. Cleanup failure is
RED, and PASS is emitted only after cleanup
succeeds and the run verifies that it wrote nothing in the repository or
outside its exact temporary root. `SIGKILL`, power loss, or host failure cannot
produce PASS; residue is then inspected privately by a maintainer before
another run, and the verifier remains RED. A separate manual recovery step must
use no-follow operations to authenticate the fixed parent and single child,
their owner, mode, and expected content before deleting only that resolved exact
target. It does not scan or recursively clean a broader directory, and cleanup
is not evidence. If the exact child cannot be authenticated, do not delete it
and STOP. The verifier never automatically deletes a path it did not create in
its current process. No local path is printed.

### Byte-only replay and separate qualification

Mechanical replay may use only the reviewed verifier and fixed host primitives
to read, safely decompress, hash, copy, patch, compare, and produce the fixed
checksum results.
It must never execute content from the input archive, patch set, reconstructed
tree, or candidate. This prohibits Cargo, rustc, tests, Clippy, rustdoc,
`build.rs`, procedural macros, Make, shell scripts, Git hooks, dynamic
libraries, and generated binaries. Mechanical replay therefore cannot itself
claim build, test, dependency, security, SBOM, product, or release evidence.

Patch tests, dependency/security inventory, the real-H3 one-Boring closure,
target SBOMs, final-artifact inspection, and normal local gates remain required.
They run only in a later, separately reviewed qualification phase, after replay
cleanup and review, in a different controlled fresh workspace against the exact
selected candidate. The OS must deny every external or non-loopback network
operation. Repository local gates may use only `127.0.0.1` with OS-assigned
ephemeral ports; any other network attempt fails qualification. Expose no
credentials, Keychain, cloud metadata, user configuration, or inherited
sensitive environment; use a neutral task-local home/environment; mount or
expose the repository, archive, and replay input read-only; allow writes only
below one `0700` output root; and enforce fixed CPU, memory, disk, process, and
wall-time bounds. Raw logs remain private and are cleaned with the workspace.
Only one privacy-reviewed allowlisted summary of public hashes and gate results
may be recorded. Every result binds to the selected-candidate complete-result hash,
exact verifier revision and fixed checksum list, official archive hash,
reconstruction result hash, Cargo/package graph and target;
qualification cannot repair or override a replay RED.

The fixed summary for that run contains only public exact hashes and results,
never a source archive, patch body, raw log, local path, endpoint, credential,
account, reviewer-private identifier, or environment detail. It is not stored
in a new registry or evidence framework.

### S3 candidate-focused Cargo and test boundary

One separately reviewed implementation slice may evaluate the S3-2A proposal
through exactly one integration-test target in unpublished `maverick-tests`,
gated by one default-off feature named `quiche-candidate`. This is the only
candidate-test Cargo exception and is not a selected-candidate or adoption
decision.

- Pin `quiche = "=0.29.3"` with `default-features = false` and no quiche
  feature. Directly pin existing `boring = "=5.1.0"` and locked
  `log = "=0.4.33"` with default features disabled and `max_level_debug` as
  the only directly requested feature, reusing the exact `boring-sys` 5.1.0
  closure. Transitive activation of ordinary `default` and `std` is not a
  trace-widening feature. The exact lockfile closure may contain no unrelated
  upgrade, Boring 4.x, second
  `links = "boringssl"` package, Git dependency, quiche path override, vendor
  tree, `[patch]`, private Cargo/TLS patch, or mutable source.
- Normal preparation and focused build/test may obtain and build only those
  exact locked crates.io packages. Mechanical replay remains separate,
  byte-only, offline, Cargo-free, and may not fetch or execute build scripts.
  The inherited crates.io `boring-sys` 5.1.0 build may perform its packaged,
  network-free local `git init` and `git apply boring-pq.patch` only during
  candidate build/test. Its exact source, patch, build, and result require
  dependency-security review. The bundled source must already be present;
  any clone, fetch, submodule, or other Git-network branch is a STOP. Setting
  `BORING_BSSL_PATH`, `BORING_BSSL_SOURCE_PATH`,
  `BORING_BSSL_ASSUME_PATCHED`, or another Boring source/build/patch override
  is forbidden.
  If that literal packaged behavior is unacceptable, STOP rather than replace it.
- The later slice's maximum allowlist is `Cargo.lock`,
  `crates/maverick-tests/Cargo.toml`, one integration-test source,
  `.github/workflows/ci.yml`, and `STATUS.md`. The direct pins live in the test
  manifest, so root `Cargo.toml` is not required; stop for separate review if
  workspace structure genuinely forces it. Existing public-PR GNU/Linux and
  Apple jobs may add only the exact focused candidate step. It must not run
  through `local-harness`, a product build command, `pilot-release`, tag,
  publish, or artifact step, and candidate packages must remain absent from
  every product SBOM and artifact those jobs also check.

Exact-graph checks on both hosts must prove no quiche feature, one Boring 5.1.0
`links` closure, and no Boring 4.x. Default and no-default checks must prove
quiche absent from product/runtime crates, default workspace CLI, product
SBOMs, pilot/release builds, and artifacts; lockfile presence is no product-SBOM
exception. STOP on a disabled typed Boring bridge need, raw `SSL_CTX`/FFI,
first-party `unsafe`, qlog, any quiche feature, second cryptographic closure,
new patch, product leak, or replay fetch/build. PASS is focused evaluation
only: it resolves no P1/P2/P3 disposition and advances no replay,
qualification, adoption, runtime, H3, product, SBOM/artifact, or release gate.

### S3-2D candidate-bound P3 logging-surface exception

After the candidate-focused slice above is merged, exactly one later,
separately reviewed implementation slice may extend only that existing
`quiche-candidate` integration test and its existing GNU/Linux and Apple
public-PR candidate steps to evaluate the proposed P3 log-cap mechanism. Its
complete implementation allowlist is
`crates/maverick-tests/tests/quiche_candidate.rs`,
`.github/workflows/ci.yml`, and `STATUS.md`. It must reuse the same default-off
feature, integration-test target, exact dependencies, lockfile, and in-memory
QUIC pump. It may not edit a manifest or lockfile; add a target, dependency, or
feature; or change any quiche, qlog, Boring, product, default-workspace, SBOM,
pilot, release, or artifact graph.

The candidate test must assert that `log::STATIC_MAX_LEVEL` is `Debug` and use
a hostile global logger plus a formatting counter, with a Debug positive
control, to prove Trace arguments are removed before formatting. The bounded
H3 exercise must cover both endpoint roles; bidirectional HEADERS with
peer-controlled QPACK literal values and bidirectional DATA; SETTINGS and
control-stream processing; request `PRIORITY_UPDATE`; and GOAWAY, all through
the existing in-memory packet pump. Packet pumping, event draining, input and
output bytes, log records, formatting counts, and loop iterations must have
fixed reviewed bounds and fail closed on exhaustion. The implementation and
its independent review must bind the claim to the exact reviewed upstream H3
logging source surface and exact call-site count; this policy edit establishes
neither value, and mutable discovery or an empty match cannot pass.

Within each of the two existing candidate steps, the feature-graph check must
prove exactly one `log` 0.4.33 package; `max_level_debug` must be present, while
`max_level_trace`, `release_max_level_trace`, and every other trace-widening
feature must be absent. Ordinary `default` and `std` activation is not
forbidden. The existing no-quiche-feature, no-qlog, single-Boring 5.1.0 closure,
no-Boring-4.x, and product/default/SBOM/artifact isolation checks remain
unchanged. No other CI job or step may execute this exception.

PASS proves only this candidate-bound mechanism and evaluation surface. P3
remains `UNRESOLVED`; product and application logging, outer-QUIC logging,
qlog, real product H3, final artifacts, replay, and qualification remain
unproved. P2 cannot be proved before a separately authorized, independently
reviewed, hash-fixed rebased P1 candidate exists. An `E0603` compiler error or
proof that pure upstream exposes no wider helper is not the required unique P2
API/visibility and documentation proof. This exception authorizes no P1 rebase
or patch and no P2 implementation or proof.

STOP on any allowlist or graph drift, mutable or unbounded surface selection,
first-party `unsafe` or typed/raw Boring bridge, source or vendor change,
network or socket use, trace-widening feature, sensitive-value output, product
leak, P1/P2 implementation, or disposition/adoption claim. Do not create a
registry, receipt, schema, framework, or coordination layer. Regardless of a
focused PASS, P1/P2/P3 remain `UNRESOLVED`, B-002 remains **PARTIAL / RED**, and
no runtime, H3, product, release, artifact, or network gate advances.

## Security-release, rebase, and upstream SLA

Security-advisory T0 is the earliest provable publication by a trusted public
advisory source, including upstream, RustSec, or OSV; Maverick's receipt of a
pre-disclosure; or a credible internal discovery or receipt from review,
fuzzing, or testing, whichever occurs first. Impact and closure deadlines both run
from that same T0; discovery, classification or reclassification, patching, and
documentation do not reset either clock. Severity is the highest value across
every applicable trusted public source that reports severity and the
independently reviewed assessment. If no trusted source reports severity, the
independent assessment is missing or uncertain, any applicable report is
uncertain, or affectedness is unknown, treat the advisory as Critical and apply
the Critical fail-close. Hours are elapsed hours, calendar days are consecutive
24-hour periods, and business days are Monday through Friday in UTC with no
project-specific holiday exclusions.

Embargoed pre-disclosure content remains private until coordinated public
disclosure. It must not enter a public summary, PR, CI output, or repository
artifact; H3 remains disabled and closure remains open while the public-safe
record cannot yet be completed.

“Close” means an impact decision is recorded and, when affected, the upgrade,
selected-candidate replay, focused tests, real-H3 dependency/Boring/SBOM/final-
artifact gates, independent review, exact-head public CI, and merge are all
complete. A passing local run or an earlier PR's CI cannot substitute for that
exact updated head.

The advisory clock covers the complete transitive dependency and build closure
of any future H3 runtime, not merely the crates named in this document. The
ordinary-release clock is deliberately narrower as defined below. Every missed
assessment, closure, or applicable ordinary-release decision deadline is an H3
disable event under the shutdown contract below.

| Severity | Impact assessment | Closure deadline | Deadline result |
|---|---:|---:|---|
| Critical | 24 hours | 72 hours | At T0 or the first Critical classification, whichever comes first, keep or make product H3 disabled immediately; no affected H3 artifact or merge may proceed. |
| High | 48 hours | 7 calendar days | At the first independently accepted High classification, keep or make product H3 disabled immediately until a fully reviewed closure lands. |
| Medium | 5 business days | 30 calendar days | Record the open risk and keep affected H3 outside artifact, merge, and release until fully reviewed closure; no exception extends the deadline, and either overdue point disables H3. |
| Low | 5 business days | 90 calendar days | Record disposition by the deadline; either overdue point disables H3 and blocks the next H3 release. |

Ordinary non-security release T0 applies only to quiche, the selected TLS/Boring
integration upstream, and any upstream whose fork Maverick directly maintains;
it does not track every ordinary release of every transitive crate. T0 is the
upstream's official publication. Within 14 calendar days, record the exact
release, impact, and explicit upgrade/replay/adopt/defer decision. Missing that
decision disables H3. Any release with security content uses the earlier
advisory clock and cannot take the ordinary 14-day path. None of these clocks
is reset by a document edit.

While any private patch exists, a full official-source selected-candidate
replay and rebase drill is required for every adopted quiche release and at
least once every 90 days, whichever occurs first. Before the first retained-
fork adoption, the independent replay and qualification maintainer defined
above must complete the entire official-source rebase/replay, test,
dependency/SBOM, and exact-head CI procedure without help from the original
patch author or S2 authors. S3 must record that independent execution
separately from S2's tool authorship and self-tests, and the final delta
reviewer must separately review its exact output. P1 and P3 must satisfy the
common upstream-route-or-exception gate within seven days of a `RETAIN`
decision. P2 follows P1. If an opened retained route has no viable resolution
after two later quiche releases or 180 days, whichever occurs first, product
H3 is disabled and the patch returns to an explicit `DROP`-or-stop decision.
A documentation edit does not restart a clock.

## Fail-closed H3 behavior

Current main has no adopted quiche product runtime, so a missed gate presently
means no quiche code may enter a product slice. If H3 is later available, the
following behavior must already be implemented and tested before adoption:

- whenever any rule in this policy requires H3 to remain or become disabled,
  invoke this same shutdown contract immediately. Triggers include an
  unclassified advisory, a Critical or High classification, a missed ordinary-
  release decision, or any required gate miss, invalidation, or expiry. This
  includes checksum, design, dependency, disposition, reviewer or evidence
  drift; Medium/Low overdue points; an expired exception without a route; and
  aggregate fork-budget growth. Do not wait for a later assessment or closure
  deadline;
- while affectedness is unknown, treat every existing carrier using any part of
  the implicated future H3 transitive runtime/build closure as affected;
- a candidate- or generation-scoped failure affects every carrier using that
  candidate or generation. If that exact scope cannot be proven, treat every
  H3 carrier as affected;
- latch one terminal transition for every affected H3 association and carrier,
  stop new H3 admissions, and invalidate idle pools, resumable state, and
  session tickets;
- an explicit H3 request returns one fixed privacy-safe unavailable error
  before DNS, target work, socket creation, or peer-controlled logging;
- after the terminal latch, reject and discard all unsent application data; do
  not send or drain application data accepted before the latch. Allow only
  fixed-bounded close/control work, then close with one privacy-safe reason and
  release tasks, queues, and sockets;
- neither an explicit request nor Auto may retry, replay, migrate, or fall back
  any partial H3 application data to H2;
- existing H2 behavior and the v1.2 train are unchanged by this document-only
  slice, not exempt from shared dependency risk. Any quiche/Boring advisory or
  solution that may affect the shared H2 Boring closure opens a separate Train
  A exact-candidate security-impact gate. B-002 neither authorizes an H2 change
  nor inherits an earlier H2 review;
- re-enablement requires the same exact updated candidate to pass replay,
  security, dependency/SBOM, patch-disposition, and independent-review gates;
  and
- a deadline breach never revives Quinn or silently accepts a second backend.

## Privacy and stop lines

Do not commit the `.crate`, an extracted source tree, replay workspace, raw
patch output, raw H3/QUIC/qlog output, packet bytes, keys, header names or
values captured from a peer, endpoint or target details, credentials, local
paths, account data, or environment-specific logs. Public upstream material
must be minimal, synthetic, and independently privacy-reviewed before contact;
S1 makes no upstream contact.

Stop B-002 without adoption if a patch touches a cryptographic primitive,
requires a deep or growing TLS/QUIC fork, cannot replay without fuzz or network
access, lacks a unique test or the required upstream route/still-valid written
exception, requires a Boring downgrade or second `boring-sys` closure, exposes
private material, or cannot receive an independent exact-delta review.

The reviewed maintained-delta budget also fails closed if a fourth private
patch appears, a patch reaches a new runtime path, any patch touches TLS or
cryptographic surface, or the aggregate maintained delta grows relative to its
last independently reviewed baseline. Passing each patch separately cannot
hide aggregate growth. Any such change is RED and requires a new independent
whole-budget decision before B-002 may continue.

## B-002 completion rule and rollback

B-002 completion has three explicit layers:

1. **Common historical and disposition evidence.** The fixed-constant historical run
   passes only as patched-upstream source reconstruction plus exact-byte
   inventory/accounting of the separate curated vendor delta; it does not prove
   the curated delta's provenance. All three patches then receive passing
   explicit dispositions bound to one exact selected upstream/design,
   dependency and evidence set. Every disposition shape, including all-`DROP`,
   passes the selected-candidate byte-only complete-result replay. The selected
   candidate passes separate qualification, security SLA, exact-head public CI,
   the real-H3 one-Boring-
   5.x graph/links/SBOM/final-artifact gates on both supported targets, and an
   independent exact-hash review.
2. **All-`DROP` pure-upstream path.** The selected official upstream full tree
   passes the empty-retained-set selected-candidate byte-only replay, contains
   no private patch or private maintained delta, every patch has passing `DROP`
   evidence, and qualification and independent review pass.
   Retained-only route/exception, maintained-delta, retained-patch rebase, and
   no-original-author drill gates are explicitly recorded `N/A`; they are not
   silently treated as satisfied.
3. **Any-`RETAIN` path.** In addition to layer 1, the retained-only selected-
   candidate replay passes; every retained patch has its required upstream
   route or still-valid written exception; the independent replay and
   qualification maintainer defined above completes
   the full rebase/replay and qualification without the original patch author's
   help; the Quinn product path is removed in its separate reversible slice;
   and an independent reviewer approves the exact complete maintained delta.

Only the applicable path can make B-002 GREEN. These requirements do not make
B-001 or any later product/runtime gate pass.

Removing this S1 document rolls back only the policy contract. It cannot
restore a fork, change dependencies, enable H3, alter config or wire behavior,
or turn any RED evidence green.
