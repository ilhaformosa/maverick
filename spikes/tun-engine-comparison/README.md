# TUN Engine Comparison Spike

This directory is an isolated, unprivileged Phase 0 comparison. It is not a
workspace member and does not create a TUN interface, open a listener, change a
route or resolver, invoke a platform helper, or contact a remote host.

The comparison set is capped at three families:

1. released `ipstack` plus the released `tun2proxy` bridge;
2. released `smoltcp` with only the in-memory IP/TCP/UDP feature set;
3. pinned gVisor netstack as a foreign sidecar boundary.

`candidates.json` binds versions, source revisions, registry archives, licenses,
and the selection decision. `results/` contains redacted aggregate records. The
only executable candidate harness is the selected native-Rust primitive spike;
the other two families failed a mandatory preflight gate before a product
adapter was justified.

Run the comparison checks with:

```sh
cargo test --locked \
  --manifest-path spikes/tun-engine-comparison/smoltcp-harness/Cargo.toml
python3 scripts/check-tun-engine-comparison.py
python3 scripts/test-tun-engine-comparison.py
```

The committed harness uses documentation-only address ranges and in-memory
queues. Its queue depth, MTU, TCP buffers, UDP buffers, UDP message count, and
flow count are fixed in source. Candidate setup, TUN, raw-socket, and hosted PHY
features are not enabled.

The result selects `smoltcp` only for the unprivileged Phase 1 adapter. It does
not claim product TUN readiness. Real device, route, resolver, leak, coexistence,
crash recovery, and residue evidence remain behind the separate Phase 2
approval gate.
