# Maverick v1.3 One-Time Merge Manifest

Date: 2026-08-12
Status: **Provisional G-002 recovery inventory; not an integration approval**

## Purpose and lifetime

This manifest gives every commit in the cumulative experimental chain exactly
one preliminary recovery destination. It is a one-time selection tool, not a
new registry, completion ledger, or source of current product truth. Remove or
archive it after the rebuilt integration sequence no longer needs it.

`KEEP` means preserve the narrow semantic asset, not cherry-pick the original
commit. Every one of the 77 commits changes the old `ROADMAP.md`, and 17 change
`STATUS.md`; no commit may be copied with those historical control-state edits.

## Exact range

- Base: `da69e15a6b9a6a70b55ab7697465c4d113edbc57`
- Head: `40b0aa7b630c0decc411c0983795828d15252bda`
- Topology: 77 commits ahead, 0 behind, 0 merge commits, one linear chain
- Remote preservation: five immutable `archive/v1.3-*` branches
- Remote quality baseline: historical Draft PR
  [#29](https://github.com/ilhaformosa/maverick/pull/29), closed without rerun or
  merge; five checks passed and the focused CycloneDX count assertion failed

## Codes

- Areas: `CFG`, `AUTH`, `H2`, `H3-BE`, `H3-RT`, `TARGET`, `UDP`, `DGRAM`,
  `TUN`, `SOCKS`, `VENDOR`, `SEC`, `QA`, `DOC`.
- Test: `N` production/spec asset, `M` mixed, `Y` test-only.
- Disposition: `KEEP`, `REWRITE`, `DROP`.
- Surface: `A` public Rust API, `C` config/schema, `W` auth/frame wire, `D`
  normative docs, `B` build/vendor, `E` CLI/runtime entry, `T` test-support,
  `-` none.
- Rollback: `O` omit, `R` revert rebuilt slice, `F` feature-off and revert,
  `V` remove vendor/dependency, `A` SemVer-aware public API rollback, `C`
  schema migration rollback, `W` versioned wire rollback.

`S-*` means an independent mainline candidate that must be reproduced and
authorized separately. `PR4-V` exists only if B-003 selects quiche and the fork
budget passes.

## Summary

| Preliminary disposition | Count |
|---|---:|
| KEEP | 18 |
| REWRITE | 57 |
| DROP | 2 |
| Total | 77 |

| Recovery source bucket | Count | Boundary |
|---|---:|---|
| PR-1 auth core/spec | 6 | split spec/vectors from core if review size requires |
| PR-2 config convergence | 3 | all must be rewritten after OD-06 and config compatibility decisions |
| PR-3 direct H2 proof | 3 | better-proven Beta carrier reference; no H3/vendor |
| PR-4 H3 runtime/reference | 41 | source inventory only; never one giant PR |
| PR4-V conditional vendor | 2 | drop unless quiche wins and B-002 passes |
| PR-5 Datagram/legacy adapter | 11 | split semantic contract/actor from legacy adapter |
| PR-6 TUN/SOCKS consumers | 6 | split TUN and SOCKS |
| Independent candidates | 3 | reproduce and queue separately on current main |
| DROP | 2 | archive provenance only |
| PR-7 native CONNECT-UDP/QUIC Datagram | 0 | no existing commit implements the standard path |

## Preliminary rebuilt dependency graph

The table's `Semantic dependency` column records historical source provenance
inside the linear cumulative branch. It is not permission to import the old
cross-bucket coupling into a rebuilt PR. In particular, later config invariants
from rows 18 and 32 must be extracted and rewritten into `PR-2-core` before any
consumer, while `PR-4` must be split into foundation and runtime stages around
the conditional vendor delta. If an invariant cannot be decoupled this way, it
must be reclassified rather than creating a target-PR cycle.

```text
G-004 -> PR-1 -> PR-2-core -> PR-3

B-003 + PR-2-core -> PR-4-foundation
PR-4-foundation -> PR-4-runtime (non-quiche path)
PR-4-foundation -> PR4-V (quiche only, after B-002) -> PR-4-runtime
PR-4-runtime -> B-004 -> A-002

D-001 -> D-003-RED -> D-002-private-prototype -> D-003-GREEN
D-003-GREEN -> PR-5-adapters -> PR-6-TUN / PR-6-SOCKS

PR-3 + A-002 + PR-5-adapters + PR-6-TUN + PR-6-SOCKS -> PR-7
```

## Commit inventory

| # | Commit and original title | Area | Semantic dependency | Value | Test | Disposition | Target | Surface | Rollback |
|---:|---|---|---|---|:---:|---|---|---|:---:|
| 1 | `c732dada3af080e952b6d5b8df80267dff504472` fix(config): reject private mode with experimental h3 | CFG | base | fail-closed config guard | N | KEEP | S-CFG | C | C |
| 2 | `b0c7161cd7bbbfb30bbeba27e10ae336781215d8` feat(h3): add gated quiche foundation | H3-BE | base | backend spike input | M | REWRITE | PR-4 | A,B | F |
| 3 | `2d49c744357028fc8f7c8ab8625a7343fbf240fb` feat(h3): add private single-identity QUIC manager | H3-BE | #2 | manager prototype | M | REWRITE | PR-4 | A,B,E | F |
| 4 | `dfdebe647d610e98e044e8a6cdb0d55871299c2c` docs(auth): freeze direct auth v3 vectors | AUTH | base | canonical spec and vectors | N | KEEP | PR-1 | D,W | W |
| 5 | `d7087c04250a7d487a50040f60f18053eecab76f` feat(core): add direct auth v3 primitive | AUTH | #4 | codec and verifier | N | KEEP | PR-1 | A,W | W |
| 6 | `fd4e317d148f58c0aca8a8ab791b15eab3780e3f` core: add singleton auth-v3 provisioning binding | AUTH | #5 | provisioning validation | N | KEEP | PR-1 | A | A |
| 7 | `1f5afde89e503919b8052bb8448a1832f786701a` feat(core): add strict direct-v3 role config projection | CFG | #6 | role validation source | N | REWRITE | PR-2 | A,C,D | C |
| 8 | `3aca640076fadded45b8e81677a068ad18753d4e` docs: freeze direct H2 auth v3 control mapping | AUTH | #4 | H2 normative mapping | N | KEEP | PR-1 | D,W | W |
| 9 | `14b61d744a6640426da77b06e76f2cc9359a5c46` Add dormant server direct-H2 auth-v3 gate | H2 | #5-#8 | server reference | M | REWRITE | PR-3 | T,B | F |
| 10 | `c547d663973a88011a4e34b54796a3c8a06eab14` Add dormant client auth-v3 H2 reference gate | H2 | #5-#8 | client reference | M | REWRITE | PR-3 | T,B | F |
| 11 | `c03b31723c7bc557b290f611a3fccae8fec68341` Test paired direct-v3 H2 reference gates | H2 | #9,#10 | paired proof | Y | REWRITE | PR-3 | T,B | F |
| 12 | `af85ac594638aa4595fd5961ebeff56ab9a4e58c` Bind auth-v3 exporter to QUIC generation | H3-RT | #2,#3,#5 | exporter invariant | M | REWRITE | PR-4 | T | F |
| 13 | `6d8b79c85641b22e372c8bc72221ce92e6ac6706` Reject post-observation pre-auth H3 activity | H3-RT | #12 | pre-auth gate | M | REWRITE | PR-4 | T | F |
| 14 | `d8c97b094e9975d85a58887dbe66ab3cf4a9ddd9` docs: freeze direct H3 auth v3 mapping | AUTH | #4 | H3 normative mapping | N | KEEP | PR-1 | D,W | W |
| 15 | `65157042427a8c803ded724e30bfd2c05a5647f9` T026b-1: adopt vendored quiche strict push gate | VENDOR | #2 | conditional fork import | M | REWRITE | PR4-V | B | V |
| 16 | `596da6ef9b33434b392d6440baf8d4313dd49751` T026b-2: suppress vendored quiche H3 traces | VENDOR | #15 | trace privacy delta | M | REWRITE | PR4-V | B | V |
| 17 | `5373972f3af34c937760350f5ab7d7f7ad6d8ec0` T026c: add test-private H3 auth-v3 runtime reference | H3-RT | #12-#16 | runtime oracle | Y | REWRITE | PR-4 | T | F |
| 18 | `12ec55c08d3e5dbbccb9b96d56105ae4c2986153` core: require trusted direct-v3 authority | CFG | #7,#9,#10,#17 | authority invariant | M | REWRITE | PR-2 | A,C,D | C |
| 19 | `3c8693668043bef3203c2510f41310e1881a825a` T026d-1: retain authenticated H3 generation capability | H3-RT | #17,#18 | generation state | M | REWRITE | PR-4 | T | F |
| 20 | `fe2a089d0a9835014b9f5cfe3ec42c62c75d9b6f` T027a-1: add authenticated classic CONNECT reference | H3-RT | #19 | CONNECT client oracle | M | REWRITE | PR-4 | T | F |
| 21 | `0c2adb64180b27da590ace081907b5f1693e35d7` T027b-1: decouple structured target opening | TARGET | base | shared opener boundary | N | KEEP | PR-4 | - | R |
| 22 | `eea2adf57d1ea75648890f2ff971326a2516c232` T023b-1: enforce authenticated generation policy | H3-RT | #19 | expiry and admission | M | REWRITE | PR-4 | T | F |
| 23 | `e5ca092313811a3ca243892816dc37da36eb71aa` T027b-2a: add strict Classic CONNECT parser | H3-RT | base | privacy-safe parser | N | KEEP | PR-4 | - | R |
| 24 | `7e7273c6cf13cc86ec12ed938ccb03dc47f929f4` T027b-2b0: add server-owned quiche connection state | H3-RT | #15,#23 | connection state | M | REWRITE | PR-4 | B | F |
| 25 | `b2b8fb9a2870d90b8a8013c77434ff0eb9195e2c` T027b-2b1a: add bounded server CID registry | H3-RT | #24 | resource-bound idea | M | REWRITE | PR-4 | T | F |
| 26 | `7a5b61a0ff6adbbb2beebed08d3b4a9e1343ff09` T027b-2b1b: add bounded UDP connection actors | H3-RT | #25 | actor ownership idea | M | REWRITE | PR-4 | T | F |
| 27 | `2f0cfbf04fab7a8e8dac011d1fa33fef44db0099` T027b-2b1c: preserve QUIC termination draining | H3-RT | #26 | drain semantics | M | REWRITE | PR-4 | T | F |
| 28 | `f0e8aba99dc2e3f5c9525b4069dcd702fb62d977` core: expose verified auth-v3 credential expiry | AUTH | #6 | verified expiry | N | KEEP | PR-1 | A | A |
| 29 | `b39b2d03f223cb4efa3cc115e891a3fbda336c7d` T027b-2b2-1: freeze server H3 foundation role | H3-RT | #24-#28 | server role input | M | REWRITE | PR-4 | T | F |
| 30 | `8d6dab53f8d75846e2cd412bbf2605d21ab09173` Implement private direct-H3 server auth runtime | H3-RT | #17,#29 | server auth runtime | M | REWRITE | PR-4 | T | F |
| 31 | `d1d8ac4d47ed2877b6512b48b737196c302dc851` server: gate authenticated H3 CONNECT metadata | H3-RT | #23,#30 | auth-before-target | M | REWRITE | PR-4 | T | F |
| 32 | `a78fc8b8bda12dab7d1d90a222860a845bdff1ad` config: freeze direct-v3 target-open policy | CFG | #7,#31 | target policy source | M | REWRITE | PR-2 | A,C,D | C |
| 33 | `5deb254d571d00dc1eb004693f856540814d8f1e` T027b-2c1 bound target dispatch lifecycle | H3-RT | #30-#32 | bounded dispatch | M | REWRITE | PR-4 | T | F |
| 34 | `578efe5c705365cd04054bd059d39277d44e78b0` server: add direct-v3 whole-attempt opener contract | TARGET | #21 | opener seam | N | REWRITE | PR-4 | - | R |
| 35 | `6762597ebbc2bffd9a09ad5b01005a87ad40bb01` T027b-2c3 hand off metrics owner to quiche actors | H3-RT | #33 | metrics ownership | M | REWRITE | PR-4 | T | F |
| 36 | `c7e4c602cb0198a9363b393d9583b54f5f200506` feat(server): retain target streams in fixed slots | H3-RT | #33 | bounded slot idea | M | REWRITE | PR-4 | T | F |
| 37 | `8a7cb904b499cd5f37341139a2be97a1cffcab5a` T027b-2c5 wire whole-attempt target opener | H3-RT | #34-#36 | target connection | M | REWRITE | PR-4 | T | F |
| 38 | `52d33f6805019b14a58ba0f12b0acb93f7baa914` T027b-2d0 queue Classic CONNECT success response | H3-RT | #37 | response ordering | M | REWRITE | PR-4 | T | F |
| 39 | `2fb6746454d149930c7d20c68d57558530688965` T027b-2d1 bound target-to-client response data | H3-RT | #38 | downlink bounds | M | REWRITE | PR-4 | T | F |
| 40 | `61eebf966de9a611920b84b2017ed495894d35c3` feat(server): bound H3 upload data to target slots | H3-RT | #39 | upload bounds | M | REWRITE | PR-4 | T | F |
| 41 | `a405979edf4675dbecdebfce5f5e59c3b1a6f52a` feat(server): forward H3 request FIN to target | H3-RT | #40 | half-close semantics | M | REWRITE | PR-4 | T | F |
| 42 | `57b7fd6ece9838f660a98244bce47068536b9dc3` feat(server): bind private H3 terminal lifecycle | H3-RT | #41 | terminal state | M | REWRITE | PR-4 | T | F |
| 43 | `f4095cfd3e6627c0f63426a37d122bc21598971f` feat(server): safely reclaim collected H3 slots | H3-RT | #42 | resource release | M | REWRITE | PR-4 | T | F |
| 44 | `b679728226bdd40f18c14ed79f5f03751e1fe486` fix(core): preserve Noise key zeroization under all features | SEC | base | key cleanup | N | KEEP | S-NOISE | - | R |
| 45 | `9840c63f0bdf66fb891d3603b070db49924d118f` fix(client): keep all-feature test targets lint-clean | QA | base | historical lint cleanup | Y | DROP | DROP | - | O |
| 46 | `5ca82357d7b962123d7536c9547b5c264db6d374` fix(tooling): make dependency inventory fail closed | QA | #15,#24 | supply-chain gate | M | REWRITE | S-INVENTORY | B | R |
| 47 | `06df7ad809b54aacf0c2ac313b34a5b2ee4a04fd` chore: close H3 foundation integration | DOC | #46 | historical control text | N | DROP | DROP | D | O |
| 48 | `c6ad2d7cc4b543fe33e4140a5dccf99ff5675f40` feat(server): add version-first role runtime entry | H3-RT | #29,#43 | server entry | M | REWRITE | PR-4 | A,C | F |
| 49 | `d078daaa6188b93d1423bfc64e47fcb7d520ac93` fix(client): make H3 readiness independently cancellable | H3-RT | #19 | cancellation idea | M | REWRITE | PR-4 | T | F |
| 50 | `1a91068a0a7fc44e98afd7b2c4416c43ebd3a6ce` feat(client): add private H3 role trust adapter | H3-RT | #7,#49 | trust mapping | M | REWRITE | PR-4 | T,C | F |
| 51 | `32462972fa449c161b1e08153502b9a0591b03fd` feat(client): own private H3 runtime policy | H3-RT | #50 | policy ownership | M | REWRITE | PR-4 | T | F |
| 52 | `e44dd5adf2cb4dfa1d9005759907cfdeb752be80` feat(client): add private H3 CONNECT flow | H3-RT | #20,#51 | client flow | M | REWRITE | PR-4 | T | F |
| 53 | `a48f69bf24feec836a160867a73457ab47d6130c` fix(h3): verify cross-crate loopback relay | QA | #43,#52 | loopback oracle | Y | REWRITE | PR-4 | T | F |
| 54 | `f5972e76e1f7e42fc0c7d73f0c2a030c10e48f9e` feat(client): verify one-shot SOCKS over direct H3 | H3-RT | #53 | SOCKS oracle | M | REWRITE | PR-4 | T | F |
| 55 | `2d630100bad3ebed25308e7920d5f7d26b8f05bd` feat(client): reuse collected private H3 flow | H3-RT | #54 | flow reuse idea | M | REWRITE | PR-4 | T | F |
| 56 | `f26f4d26fde05b3d69af266daa6c0e60bf0831f1` test(h3): prove sequential SOCKS composition | QA | #55 | regression idea | Y | REWRITE | PR-4 | T | F |
| 57 | `a662c4ee8d1d588c0597ade6a470ea7a2a43a65b` test(h3): prove first-peer failure isolation | QA | #55 | isolation oracle | Y | REWRITE | PR-4 | T | F |
| 58 | `eb49c21321d77dc9a61efd4669d394023468e515` test(h3): prove active-flow controller shutdown | QA | #55 | shutdown oracle | Y | REWRITE | PR-4 | T | F |
| 59 | `f64abc72d4091d15977ae253366f95bf7a3cbc68` feat(h3): add one-shot client role entry | H3-RT | #58 | client entry | M | REWRITE | PR-4 | A,C | F |
| 60 | `7f6158d23bf72b54073977e296a66c9ef2318818` fix(h3): stop reset peer before target open | H3-RT | #59 | pre-target gate | M | REWRITE | PR-4 | T | F |
| 61 | `b39bbff53f646472fb022fa2b7b2387dc706d0a3` feat(udp): add connected target owner | UDP | base | stable source and socket | M | KEEP | PR-5 | - | R |
| 62 | `1a7ca24fb3ef8e28f9ecc5115acfb1d2fda32405` feat(udp): retain target owner per flow | UDP | #61 | flow ownership | M | KEEP | PR-5 | - | R |
| 63 | `71f6fd8b6fcc2533297131ed4dc00c77bb81ee41` fix(udp): reject mismatched flow ids | UDP | #62 | flow isolation | M | KEEP | PR-5 | - | R |
| 64 | `7163139d014b1952f4eca0cc742870a0b7c175d8` fix(h3): bound application frame completion | UDP | #63 | deadline | M | KEEP | PR-5 | - | R |
| 65 | `1c7ad25ac4ac3133d610dff80e97105a1104f129` fix(udp): fail closed after interrupted relay | UDP | #64 | cancellation safety | M | KEEP | PR-5 | - | R |
| 66 | `6eb2e50f701488fe526ffded4967639d7db2720b` feat(udp): add OpenUdp mode negotiation gate | UDP | #65 | negotiation asset | M | KEEP | PR-5 | A,W | W |
| 67 | `b415c507f3d741508a87492d03aee09d0292e003` feat(udp): add negotiated H3 server push | UDP | #66 | unsolicited push asset | M | KEEP | PR-5 | W | W |
| 68 | `1424f39c83fd4abe4718b45d2f0a543f921b58a4` feat(udp): add public legacy-H3 duplex client | UDP | #67 | borrowed API oracle | M | REWRITE | PR-5 | A,W | W |
| 69 | `4e567ff1dffbf681d5e8bba853f26f436f0674e6` feat(udp): enable selected H3 SOCKS duplex | SOCKS | #68 | consumer oracle | M | REWRITE | PR-6 | - | R |
| 70 | `c8b54b8ce2cd5419ba36603e2eb2e40452f5bcdd` fix(udp): bound legacy H3 SOCKS setup | SOCKS | #69 | setup deadline | M | REWRITE | PR-6 | - | R |
| 71 | `26f78c28a5a6a399dab4ba8b4d86b2197192ca24` feat(socks): hand off legacy H3 UDP targets | SOCKS | #70 | target ownership oracle | M | REWRITE | PR-6 | - | R |
| 72 | `0553f2509719de07a62d0a072b00492801982f80` fix(socks): match UDP relay address family | SOCKS | #71 | IPv6 local relay fix | M | KEEP | PR-6 | - | R |
| 73 | `f28dd39fd5d7b6d016b234946bac6ce4a23787e2` feat(tun): add independent UDP receive contract | DGRAM | base | receive semantics | M | REWRITE | PR-5 | A | A |
| 74 | `49157d74c96561190c9ece65488c7c870ab8f794` feat(tun): consume negotiated H3 UDP push | TUN | #68,#73 | inbound consumer oracle | M | REWRITE | PR-6 | - | R |
| 75 | `c4f0421549d2ed11921dda8ada38a3d9687fcfa5` feat(tun): support response-optional UDP submission | DGRAM | #73 | send-ahead semantics | M | REWRITE | PR-5 | A | A |
| 76 | `d0f76b07457d8df3c59a105f0396a9907bac76d3` feat(tun): submit H3 datagrams without reply gating | TUN | #74,#75 | consumer oracle | M | REWRITE | PR-6 | - | R |
| 77 | `40b0aa7b630c0decc411c0983795828d15252bda` Complete T025f H3 ready-target scheduling | UDP | #67 | finite-burst regression only | M | REWRITE | PR-5 | - | R |

## Recovery rules and stop conditions

1. No row authorizes a cherry-pick, merge, public API, schema, wire, backend,
   release, or field action.
2. PR-4 is a source bucket, not a 41-commit PR. B-001/B-002/B-003 decide what,
   if anything, is rebuilt.
3. Vendor code remains isolated and conditional. If quiche does not win or the
   fork budget fails, PR4-V is dropped.
4. Config rows are rewritten only after OD-06 plus schema-3 compatibility and
   first-runtime support decisions.
5. Public/test-support seams preserve assertions only; they do not become
   product API merely because old cross-crate tests used them.
6. The borrowed API shape and the T025f one-probe scheduler are not retained as
   the new architecture.
7. PR-7 contains no recovered implementation. Standard CONNECT-UDP and QUIC
   DATAGRAM begin only after their named prerequisites pass.
8. The three `S-*` candidates require a newly reproduced failure or safety need,
   a separate current-main task card, and their own tests.
9. If a rebuilt slice cannot compile, test, and roll back independently without
   old hidden local state, stop and reclassify it.
10. PR #29's sole remote red was a stale exact component-count assertion after
    the gated quiche/Boring dependency change: generated Linux/macOS counts were
    185/184 while the old test expected 177/176. The preceding dependency,
    deny, and unsafe inventory gate passed. This is not a vulnerability finding
    and must not be hidden by patching the frozen branch. Every rebuilt
    dependency slice must update and review its target-aware SBOM inventory in
    the same slice.
