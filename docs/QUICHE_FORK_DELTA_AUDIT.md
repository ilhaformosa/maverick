# quiche fork delta audit

Date: 2026-08-12

Audit alignment note: 2026-08-13. `STATUS.md` remains the only current-truth
document.

Task: B-002

Result: **RED — the complete fork budget is not satisfied**

## What this document means

This is a one-time, read-only audit of the three patch artifacts preserved in
the experimental quiche tree. It is not a patch registry, maintenance receipt,
product result, or permission to vendor quiche into current `main`.

The child-friendly summary is: the three old parts can still be inspected, and
the revised verifier can rebuild their historical source bytes exactly. That
does not answer whether Maverick should keep those parts. No patch has a
passing `DROP` or `RETAIN` decision, no required upstream route or still-valid
written cannot-upstream exception is recorded, the shipping dependency and
security gates remain unresolved, and no independent candidate-delta review is
recorded. Therefore the quiche fork remains experimental.

## 2026-08-12 direction amendment

The owner subsequently fixed quiche as Maverick's sole intended H3/UDP product
backend and abandoned Quinn as a product direction. That governance choice
supersedes this audit's earlier prohibition on *selecting* a backend; it does
not alter any historical measurement, table cell, or RED result below.

Selection direction and adoption are different gates. Adoption remains
blocked. If any private patch is retained, every missing named owner, upstream
route or written exception, independent patch test, mechanical clean-source
rebase, security-release SLA, and independent vendor-delta review must be
supplied and pass. A pure-upstream quiche candidate may omit all three old
patches only after each receives an evidence-backed `DROP / not required`
disposition and the resolved dependency, security, and target-aware SBOM gates
pass. The separate B-001 qualification, privacy, fingerprint, resource, and
platform gates also remain open. If those gates do not pass, product H3 stays
disabled; Quinn is not restored as a fallback.

The frozen experimental tree's retained Quinn path keeps the historical
`No second Quinn product path` row RED. Quinn deletion belongs in a separate,
small, reversible code slice and cannot be mixed with this read-only audit or a
future quiche import. The preferred recovery oracle is
`archive/v1.3-direct-foundation-7f6158d`; archived dependency downgrades and the
private fork are evidence to audit, not code to copy automatically.

## 2026-08-13 evaluation candidate and non-effective proposal

The revised historical verifier has now passed once under the independent-run
contract recorded in `STATUS.md`. That PASS proves only historical source
reconstruction and curated-byte accounting. It does not select an adoption
candidate or resolve any patch.

The next tests need one fixed object, so this audit binds official `quiche`
0.29.3 as an **evaluation-only candidate** with upstream commit
`09b125d4cfc16e78d73d8382c93926f3aba063d4`, archive SHA-256
`61166d27591eb7cb1310eec2b8fc6ae0e0686e9e4ed742a3ffc6317171175e7d`,
and license SHA-256
`2ef4b5abfce387a83933bda738e72467a79d15c1c17679143ec55011dae66b84`.
This is the official 0.29.3 release fixed for this evaluation, but it is not a
selected-candidate, vendor, dependency, product, or release decision.

Its proposed shipping feature shape is `default-features = false` with no
quiche features enabled. In particular, `boringssl-boring-crate`, `qlog`,
`ffi`, `internal`, `custom-client-dcid`, `fuzzing`, `gcongestion`, and
`pkg-config-meta` are all disabled. The dependency hypothesis is to reuse the
existing single `boring`/`boring-sys` 5.1.0 closure rather than activate
quiche's optional `boring = "4.3"` edge. Disabling that edge also removes
quiche's typed `Config::with_boring_ssl_ctx_builder` and `SslRef` integration;
the probe proves only native-symbol coexistence and linking, not that a Boring
5 builder can be passed into quiche. A repository-external, offline
`aarch64-apple-darwin` probe observed that `quiche::Config::new()` and the
public Boring 5 builder can compile, link, and run through one
`boring-sys 5.1.0` native symbol closure. That probe did not exercise a QUIC or
H3 handshake, Linux, a shipping feature graph, an SBOM, or a final artifact.
It also observed the existing `boring-sys 5.1.0` build script's bundled,
network-free local `git init` and `git apply` of its packaged
`boring-pq.patch`; that build and patch surface remains subject to the exact
candidate security review and is not silently approved here.

The following are non-effective proposals only. Every row remains
`UNRESOLVED`, and no `RETAIN` clock or upstream-contact deadline starts:

| Patch | Proposal | Reason and required next proof |
|---|---|---|
| P1 strict peer-push gate | **PROPOSED RETAIN / UNRESOLVED** | Pristine 0.29.3 has no equivalent strict switch: it accepts or state-processes legal `MAX_PUSH_ID`, `PUSH_PROMISE`, `CANCEL_PUSH`, and push-form `PRIORITY_UPDATE`, while its push-stream rejection has a different error surface. This proposal applies only if the final pre-auth H3 design still gives those inputs to quiche and has no complete alternative gate; otherwise P1 returns to DROP evaluation. A rebased candidate must reject all five surfaces at the complete discriminator with one fixed empty `FrameUnexpected` close, cover both roles and every fragmentation boundary, and preserve SETTINGS, QPACK, request, GOAWAY, reserved-frame, and request-priority behavior. The proposed P1 starts with narrow helper visibility and the exact public documentation below; it does not recreate the historical wider helper. |
| P2 adoption hardening | **PROPOSED DROP / UNRESOLVED** | The historical helper lived in a private module, so an external compile-fail cannot uniquely distinguish its `pub` and `pub(super)` forms. The proposed rebased P1 never exposes the wider form and incorporates the exact covered/excluded setter documentation directly. Candidate-bound source and API checks must prove that final shape before P2 can be absent. |
| P3 H3 trace privacy | **PROPOSED DROP-FIRST / UNRESOLVED** | Upstream 0.29.3 still formats peer-controlled QPACK names and values at Trace. The first experiment will keep quiche `qlog` disabled and enable the shared `log` crate's all-profile `max_level_debug` cap so Trace is removed before formatting. Both H3 roles, send/receive/control paths, a hostile logger, formatting counters, the exact feature graph, outer QUIC logs, qlog absence, and Maverick application logging must all be checked. If any Trace value is formatted or product requirements need quiche Trace, this proposal fails and P3 returns to RETAIN-or-stop analysis. |

The exact proposed public setter contract for the candidate-bound P1 test is:

```text
Rejects peer MAX_PUSH_ID, PUSH_PROMISE, CANCEL_PUSH, push-form
PRIORITY_UPDATE, and push-stream activity.

This does not handle GOAWAY, request-form PRIORITY_UPDATE, QUIC Datagrams, or
any other pre-authentication HTTP/3 event or state. Those boundaries require
separate checks by the caller.
```

The next slice is candidate-bound focused evidence, not Cargo/vendor/product
adoption. Stop without changing product code if the exact release, archive,
features, Boring closure, or proposed set drifts; if a second cryptographic
closure or private Cargo/TLS patch is needed; if P1 or P3 lacks deterministic
two-role evidence; if qlog or sensitive application Debug logging is reachable;
if the required TLS/browser configuration needs quiche's disabled typed Boring
bridge before an official single-Boring-5 route is proved; if the final
pre-auth design removes P1's necessity; if P1 exposes the wider helper; if the
P2 source/rustdoc check is not unique or only proves the private module's E0603;
or if the selected-candidate replay, dependency/security review, supported-
target qualification, and independent review cannot all be kept separate.

## B-002-S1 maintenance contract

`docs/QUICHE_FORK_MAINTENANCE_POLICY.md` freezes a document-only contract
for accountable, delegated, patch-operational, dependency-security, and
independent-review roles; patch-specific `DROP`/`RETAIN` gates; an offline
replay contract; upstream and rebase rules; security-release deadlines; and
fail-closed H3 behavior. It assigns P1 and P2 to
`H3-PROTOCOL-SAFETY`, P3 to `H3-PRIVACY-LOGGING`, and source, dependency,
security-update, and SBOM responsibility to `DEPENDENCY-SECURITY` under the
repository owner's accountability and Codex's standing delegated execution.

The replay contract uses B-002-specific reviewed fixed constants, secure
repository-external cleanup, byte-only reconstruction, and separate historical
and selected-candidate runs; executable qualification is later and bound to the
exact candidate and replay hashes. The dependency gate requires the real H3
feature's graph, `links` closure, target SBOM, and final artifact on both
supported release targets. Unclassified advisories default to Critical,
ordinary releases have a 14-day decision deadline, and any rule that disables
H3 rejects new work, invalidates idle pools and resumption, and immediately
terminates affected existing carriers without sending or replaying application
data to H2.

That responsibility and SLA surface is **PARTIAL / RED** only. No role
assignment proves necessity, creates an upstream issue or PR, applies a patch,
resolves the dependency graph, demonstrates response to a real security
release, or supplies the required independent reviewer and result. The policy
does not authorize source, Cargo, vendor, runtime, capture, release, or network
changes.

## Fixed baselines

| Role | Exact object |
|---|---|
| Original read-only audit base | `origin/main` at `9820be7ea3d9e152054eb71e9f665062ab59ee98` |
| B-002-S1 implementation base | `main` at `be5f3ae532037468edbb1d619731a223284164c5` |
| Archived experimental source | `40b0aa7b630c0decc411c0983795828d15252bda` |
| Experimental source tree | `e57322e1467d84dbeb9c920269c64635b465efa9` |
| Archived vendor tree | `79e628882099575a6b9f9d10fa3a12571dff9677` (68 blobs; 2,455,232 bytes) |
| Claimed upstream crate | `quiche` 0.29.3 |
| Claimed upstream commit | `09b125d4cfc16e78d73d8382c93926f3aba063d4` |
| Claimed pristine `.crate` SHA-256 | `61166d27591eb7cb1310eec2b8fc6ae0e0686e9e4ed742a3ffc6317171175e7d` |

The original read-only audit copied the last three values from archived
`UPSTREAM.md`; the pristine `.crate` is not a Git object in this repository.
During B-002-S1, a read-only check found the exact official archive in the
local Cargo registry cache. Its recomputed SHA-256 matches both the table and
the locally cached crates.io index checksum; its `.cargo_vcs_info.json` names
the table's upstream commit, and its `COPYING` hash is
`2ef4b5abfce387a83933bda738e72467a79d15c1c17679143ec55011dae66b84`.
This proves local preimage availability only. S1 did not apply the patches,
compare a replay result, or independently review the full vendor delta.

The official 0.29.3 package manifest uses `boring = "4.3"` when its default
Boring feature is active, while the exact S1 implementation base locks
`boring`/`boring-sys` 5.1.0 and `tokio-boring` 5.0.0. The maintenance contract
therefore blocks both a Boring 5.x downgrade and simultaneous Boring 4.x/5.x
closures. The evaluation hypothesis above disables that optional quiche edge
and supplies the existing Boring 5 closure directly; its narrow Apple-arm64
probe is not the required shipping proof. A reviewed exact candidate using the
real H3 feature must still prove one Boring 5.x dependency and `links` closure,
target-aware SBOM, and final artifact on both supported release targets. That
evidence is still **MISSING / RED**.

## Fail-closed object checks

Run these checks from a checkout containing the archived objects. They disable
replacement objects, lazy fetching, and optional Git locks. If any object is
absent, stop; do not fetch, download, or substitute another source during this
audit.

```sh
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e 40b0aa7b630c0decc411c0983795828d15252bda^{commit}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e e57322e1467d84dbeb9c920269c64635b465efa9^{tree}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git rev-parse 40b0aa7b630c0decc411c0983795828d15252bda^{tree}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e 79e628882099575a6b9f9d10fa3a12571dff9677^{tree}
```

For every path below, first resolve its blob and then require that exact blob
to exist locally:

```sh
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/UPSTREAM.md
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/PATCHES/quiche-0.29.3-reject-peer-push-activity.patch
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/PATCHES/maverick-adoption-review-hardening.patch
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/PATCHES/maverick-h3-trace-privacy.patch
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e 789e8e0d4d607b6b589c4597331d338072e3354b^{blob}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e 387ff8d539e68d5bcdf21b1b8d4a3e1145b8952a^{blob}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e a2c982213c564e4556399c9aafa2b211fdfadcfc^{blob}
env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  git cat-file -e a7fa42323e27fd414f8664d6875f658183313cc5^{blob}
```

The final H3 source and focused-test blobs are independently bound to their
archived paths, rather than inferred from the patch objects:

```sh
test "$(env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/src/h3/mod.rs)" = \
  00ba6c88edcab281abec43047d9a36838bfe1145
test "$(env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/src/h3/stream.rs)" = \
  2cb31493501e5298ef9f1d6305043aaa27e16665
test "$(env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:vendor/quiche-0.29.3/src/h3/qpack/decoder.rs)" = \
  7bb0af4e6b56f8288fde1f06d6b8a2bec7d75000
test "$(env GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 git rev-parse \
  40b0aa7b630c0decc411c0983795828d15252bda:crates/maverick-client/tests/quiche_strict_push.rs)" = \
  b6f2312251ec6b6d18fa436bce45d45498e4f360
```

Observed local object-integrity result: **PASS**. The archived commit, tree,
`UPSTREAM.md`, all three patch blobs, all three patched H3 source blobs, and the
focused-test blob were present without a fetch. This only proves that the
preserved Git objects can be read; it does not satisfy B-002.

## Patch order and exact delta

The recorded application order is strict push, adoption hardening, then trace
privacy. The first two artifacts name paths below `quiche-0.29.3/`; the third
names paths below `vendor/quiche-0.29.3/`. A future rebase procedure must freeze
its working directory and strip level instead of guessing from those differing
prefixes.

| Order | Patch artifact | SHA-256 | Changed runtime paths | Recorded introduction |
|---|---|---|---|---|
| 1 | `vendor/quiche-0.29.3/PATCHES/quiche-0.29.3-reject-peer-push-activity.patch` | `74e9078d2e6c244b4fba2dbad185a8eb1adba6762d32286540ed645122be04fa` | `src/h3/mod.rs`; `src/h3/stream.rs` | `65157042427a8c803ded724e30bfd2c05a5647f9` |
| 2 | `vendor/quiche-0.29.3/PATCHES/maverick-adoption-review-hardening.patch` | `873ba92b498ba260ae097c47474d51ee79d6f94ac87efa3ba53337ca57404512` | `src/h3/mod.rs`; `src/h3/stream.rs` | same commit as order 1 |
| 3 | `vendor/quiche-0.29.3/PATCHES/maverick-h3-trace-privacy.patch` | `923c9ce876e76c7758ecebe8d9126572a245ea98019b467b66d5acc228ad2ee0` | `src/h3/mod.rs`; `src/h3/qpack/decoder.rs`; `src/h3/stream.rs` | `596da6ef9b33434b392d6440baf8d4313dd49751` |

Artifact statistics, not a smallness approval:

| Patch | Hunks | Insertions | Deletions |
|---|---:|---:|---:|
| strict push | 17 | 82 | 13 |
| adoption hardening | 2 | 9 | 2 |
| trace privacy | 38 | 153 | 88 |
| total | 57 | 244 | 103 |

The union touches three H3 runtime files and no cryptographic-primitive file.
That narrow path fact is **PASS** for this frozen artifact only. It does not
prove that the fork is small enough to maintain.

## Test mapping

The archived focused command was rerun against the exact experimental head:

```sh
env CARGO_NET_OFFLINE=true cargo test -p maverick-client \
  --features unstable-quiche-strict-push-test-support \
  --test quiche_strict_push
```

Observed result: **PASS, 15 passed, 0 failed**. The test uses synthetic local
inputs and temporary files. It is not a real-network, fingerprint, backend,
release, or product result.

| Patch | Focused evidence at the frozen head | Mapping result |
|---|---|---|
| strict push | default-off compatibility; fixed empty rejection for `MAX_PUSH_ID`, `CANCEL_PUSH`, `PUSH_PROMISE`, push-form `PRIORITY_UPDATE`, and push stream; fragmented pre-SETTINGS input; preserved reserved frame, request priority, GOAWAY, SETTINGS/QPACK/request paths; privacy-safe rejection surface | **PARTIAL** — historical reconstruction now passes, but no selected-candidate replay or independent candidate review exists |
| adoption hardening | the focused target compiles after helper visibility is narrowed; setter documentation is text-only | **RED** — no test uniquely demonstrates this patch and no mechanical rebase test exists |
| trace privacy | `connection_local_trace_gate_is_default_false_and_suppresses_both_roles`; `strict_rejection_surfaces_do_not_expose_peer_input` | **PARTIAL** — synthetic H3/QPACK trace coverage passes, but no independent delta or full logging-surface review exists |

## Complete fork-budget audit, patch by patch

`MISSING` means no qualifying evidence was found in the frozen objects. It is
not permission for this document to invent the missing answer.

| Budget item | Strict push | Adoption hardening | Trace privacy |
|---|---|---|---|
| Explicit security/privacy necessity | **PARTIAL**: internal pre-auth push rationale exists; qualification necessity is unproven | **PARTIAL**: visibility and documentation tightening exists; fork necessity is unproven | **PARTIAL**: synthetic peer-controlled trace exposure is tested; fork necessity over an upstream solution is unproven |
| Named patch owner | **PARTIAL / RED**: `H3-PROTOCOL-SAFETY` responsibility is frozen; no passing disposition or adoption owner result exists | **PARTIAL / RED**: folded into P1 under `H3-PROTOCOL-SAFETY`; it cannot be retained alone | **PARTIAL / RED**: `H3-PRIVACY-LOGGING` responsibility is frozen; no passing disposition or adoption owner result exists |
| Required upstream route or still-valid written cannot-upstream exception | **MISSING / RED** | **MISSING / RED** | **MISSING / RED** |
| Patch independently testable | **PARTIAL / RED**: focused behavior tests pass; no independent run is recorded | **MISSING / RED**: no unique behavior test | **PARTIAL / RED**: focused trace test passes; no independent run is recorded |
| Historical reconstruction and selected-candidate replay | **PARTIAL / RED**: historical reconstruction passes; selected-candidate replay is missing | **PARTIAL / RED**: historical reconstruction passes; selected-candidate replay is missing | **PARTIAL / RED**: historical reconstruction passes; selected-candidate replay is missing |
| Frozen security-release evaluation/upgrade/replay/CI SLA | **PARTIAL / RED**: deadlines and exact-head CI requirement are frozen; no real release response is demonstrated | **PARTIAL / RED**: follows P1; no real response is demonstrated | **PARTIAL / RED**: deadlines and exact-head CI requirement are frozen; no real release response is demonstrated |
| Independent vendor-delta reviewer and result | **MISSING / RED** | **MISSING / RED** | **MISSING / RED** |
| Cryptographic primitive modified by this artifact | **NO / PASS** | **NO / PASS** | **NO / PASS** |
| No second Quinn product path | **RED**: the frozen experimental tree also retains Quinn | **RED**: same tree-wide condition | **RED**: same tree-wide condition |
| Overall patch budget | **RED** | **RED** | **RED** |

The archived sentence “Maverick maintainers own review, rebasing, and security
maintenance” is a general responsibility claim. S1 now adds explicit
operational roles and deadlines, but neither statement provides a passing
patch disposition, required upstream route or still-valid written exception,
selected-candidate replay, demonstrated release
response, or independent reviewer and result. The remaining red cells cannot
be filled by implication.

## Preimage availability and replay boundary

The first patch records abbreviated preimage/result blob pairs
`b6c2552..32ed044` and `97e018b..3c846f7`; none of those four exact Git blobs
is retained in this repository. The adoption patch has no index-object line,
and its changes were committed together with the strict-push adoption. The
official `.crate` was observed locally outside Git during S1, and its public
source, commit, and license hashes matched as described above. A later revised,
independently executed verifier applied the fixed historical chain:

```text
pristine crates.io archive
  -> strict-push patch
  -> adoption-hardening patch
  -> trace-privacy patch
  -> patched upstream source matching its fixed historical checksums
```

That run passed its fixed source-stage and curated-byte comparisons. It proves
reconstruction of the old patched upstream source and exact accounting of the
separate curated bytes, not their provenance or justification. The three
patches still cannot decide whether any patch belongs in a selected candidate.
After
proposed dispositions, a second B-002-specific fixed-constant replay must start from
the exact selected official upstream, apply only retained patches (P2 only if
P1 is retained), prove dropped patches absent and the complete result tree
exact, and produce pure upstream when all patches are dropped. Mechanical
replay executes no Cargo, `build.rs`, tests, or source. Tests, dependency and
security inventory, target SBOMs, final artifacts, and normal gates run later
in a separate controlled qualification bound to the exact candidate and replay
hashes.

The next selected-candidate mechanical verifier must use the explicit,
offline, fuzz-free working directories and strip levels frozen in the
maintenance policy. Historical reconstruction is now PASS at its narrow
boundary; every selected-candidate, disposition, dependency, qualification,
and adoption result remains **UNKNOWN / RED**.

## Decision and stop line

B-002 is **RED**. Object-integrity PASS, local official-preimage availability,
the historical reconstruction PASS, the archived 15-test focused PASS, the
evaluation-only proposal, and the S1 policy/SLA contract do not upgrade it.
Under OD-05, the selected quiche direction cannot restore this private fork
while the complete fork budget remains red. The proposed P1-retained shape
still requires candidate-bound tests, replay, upstream routing, dependency,
security, supported-target qualification, SBOM/final-artifact, and independent
review gates. No proposed row above is an effective disposition.

Do not expand vendor code, edit Cargo files, add CI, assign an owner by
implication, contact upstream, or download a replacement source as a follow-up
hidden inside this audit. B-003 now records the fixed direction only. It does
not convert B-001 observations, the fork budget, product adoption, security,
fingerprint, native Datagram, release, or real-network evidence to green.
