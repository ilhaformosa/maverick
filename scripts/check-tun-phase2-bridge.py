#!/usr/bin/env python3
"""Validate the approved-host-only Phase 2 Linux TUN bridge boundary."""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path


FORBIDDEN_SOURCE = {
    "std::process::Command",
    "tokio::process::Command",
    "/etc/resolv.conf",
    "iptables",
    "nft ",
    "ip route",
    "ip link",
    "sudo",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    args = parser.parse_args()
    result = check_repository(args.repo_root.resolve())
    print(
        "TUN Phase 2 bridge OK: "
        f"adapter={result['adapter']}, snapshots={result['snapshot_fields']} fields"
    )


def check_repository(repo_root: Path) -> dict[str, int | str]:
    workspace = load_toml(repo_root / "Cargo.toml")
    dependency = workspace["workspace"]["dependencies"].get("libc")
    require(dependency == "=0.2.186", "libc version must stay exact")

    manifest = load_toml(repo_root / "crates/maverick-tests/Cargo.toml")
    phase2_feature = set(manifest.get("features", {}).get("tun-phase2", []))
    require(
        phase2_feature == {"tun-runtime", "dep:clap", "dep:libc"},
        "tun-phase2 feature boundary drifted",
    )
    binaries = manifest.get("bin", [])
    runner = next(
        (item for item in binaries if item.get("name") == "maverick-tun-phase2"),
        None,
    )
    require(isinstance(runner, dict), "Phase 2 runner binary is missing")
    require(
        runner.get("required-features") == ["tun-phase2"],
        "Phase 2 runner must stay feature-gated",
    )

    lock = load_toml(repo_root / "Cargo.lock")
    locked = [item for item in lock["package"] if item.get("name") == "libc"]
    require(len(locked) == 1, "Cargo.lock must contain exactly one libc")
    require(locked[0].get("version") == "0.2.186", "locked libc version drifted")

    source = (repo_root / "crates/maverick-tests" / runner["path"]).read_text(
        encoding="utf-8"
    )
    for token in FORBIDDEN_SOURCE:
        require(token not in source, f"forbidden bridge source token: {token!r}")
    required = {
        "TunEndpoint::open_existing(&args.device)",
        "PacketIo::new(",
        "advanced.experimental_tun",
        "configured_buffer_capacity_bytes",
        "peak_buffered_bytes",
        "peak_ingress_queue_depth",
        "peak_egress_queue_depth",
        "runner_started",
        "runner_stopped",
        "timestamp_unix_ms",
    }
    for token in required:
        require(token in source, f"missing bridge boundary token: {token!r}")
    require(source.count("Arc<TunEndpoint>") == 2, "runner must expose one shared TUN endpoint")
    linux_source = (
        repo_root
        / "crates/maverick-tests/src/bin/maverick-tun-phase2/linux_tun.rs"
    ).read_text(encoding="utf-8")
    require(linux_source.count("unsafe {") == 1, "Linux bridge must contain one unsafe block")
    require("unsafe fn" not in linux_source, "Linux bridge must not expose an unsafe function")
    require("// SAFETY:" in linux_source, "Linux bridge unsafe contract is undocumented")
    for token in ("libc::TUNSETIFF", "libc::IFF_TUN", "libc::IFF_NO_PI", "AsyncFd::new"):
        require(token in linux_source, f"missing Linux TUN token: {token!r}")
    snapshot_fields = source.count('snapshot.')
    require(snapshot_fields >= 30, "runner snapshot evidence surface is incomplete")
    return {"adapter": "linux-ioctl-single-unsafe", "snapshot_fields": snapshot_fields}


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    main()
