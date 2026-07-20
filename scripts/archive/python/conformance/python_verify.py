#!/usr/bin/env python3
"""No-network verifier for Maverick conformance JSON."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


FRAME_TYPES = {
    "client_hello": 0x01,
    "server_hello": 0x02,
    "open_tcp": 0x03,
    "tcp_data": 0x04,
    "tcp_fin": 0x05,
    "tcp_reset": 0x06,
    "open_udp": 0x07,
    "udp_packet": 0x08,
    "close_flow": 0x09,
    "ping": 0x0A,
    "pong": 0x0B,
    "window_update": 0x0C,
    "error": 0x0D,
    "dns_query": 0x0E,
    "dns_response": 0x0F,
    "padding": 0x10,
}

ERROR_CODES = {
    "target_connect_failed": 0x0001,
    "flow_not_found": 0x0002,
    "flow_limit_exceeded": 0x0003,
    "protocol_error": 0x0004,
    "internal_error": 0x0005,
}

MODES = {
    "auto": 0,
    "stable": 1,
    "private": 2,
}

CLIENT_HELLO_AUTH_LABEL = b"Maverick v1 client hello"
SERVER_HELLO_AUTH_LABEL = b"Maverick v1 server hello"
CLIENT_HELLO_V2_AUTH_LABEL = b"Maverick v2 client hello"
SERVER_HELLO_V2_AUTH_LABEL = b"Maverick v2 server hello"
AUTH_V2_EPOCH_SALT_LABEL = b"Maverick auth v2 epoch"
AUTH_V2_CLIENT_INFO = b"Maverick auth v2 client mac"
AUTH_V2_SERVER_INFO = b"Maverick auth v2 server mac"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector_dir", type=Path)
    args = parser.parse_args()

    paths = sorted(args.vector_dir.glob("*.json"))
    if not paths:
        raise SystemExit(f"no vectors found in {args.vector_dir}")

    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            vector = json.load(handle)
        verify_vector(path.name, vector)

    print(f"python conformance OK: {len(paths)} vectors")


def verify_vector(file_name: str, vector: dict[str, Any]) -> None:
    kind = vector["kind"]
    if kind == "frame":
        verify_frame(file_name, vector)
    elif kind == "open_udp":
        expect_equal(file_name, be_u64(vector["idle_timeout_ms"]), hx(vector["encoded_hex"]))
    elif kind == "open_tcp":
        verify_open_tcp(file_name, vector)
    elif kind == "udp_packet":
        verify_udp_packet(file_name, vector)
    elif kind == "error_code":
        expect_equal(file_name, be_u16(ERROR_CODES[vector["code"]]), hx(vector["encoded_hex"]))
    elif kind == "client_hello_v1":
        verify_client_hello_v1(file_name, vector)
    elif kind == "server_hello_v1":
        verify_server_hello_v1(file_name, vector)
    elif kind == "client_hello_v2":
        verify_client_hello_v2(file_name, vector)
    elif kind == "server_hello_v2":
        verify_server_hello_v2(file_name, vector)
    elif kind == "replay_sequence":
        verify_replay_sequence(file_name, vector)
    else:
        raise AssertionError(f"{file_name}: unsupported vector kind {kind}")


def verify_frame(file_name: str, vector: dict[str, Any]) -> None:
    frame = vector["frame"]
    payload = hx(frame["payload_hex"])
    expected = bytes(
        [
            FRAME_TYPES[frame["type"]],
            frame["flags"],
        ]
    )
    expected += int(frame["flow_id"]).to_bytes(8, "big")
    expected += len(payload).to_bytes(4, "big")
    expected += payload
    if len(payload) > int(vector["max_frame_size"]):
        raise AssertionError(f"{file_name}: payload exceeds max_frame_size")
    expect_equal(file_name, expected, hx(vector["encoded_hex"]))


def verify_open_tcp(file_name: str, vector: dict[str, Any]) -> None:
    expected = encode_target(vector["target"])
    expected += be_u16(vector["port"])
    initial_data = hx(vector["initial_data_hex"])
    expected += len(initial_data).to_bytes(4, "big")
    expected += initial_data
    expect_equal(file_name, expected, hx(vector["encoded_hex"]))


def verify_udp_packet(file_name: str, vector: dict[str, Any]) -> None:
    target = {"kind": "ipv4", "addr": vector["target"]}
    expected = encode_target(target)
    expected += be_u16(vector["port"])
    data = hx(vector["data_hex"])
    expected += len(data).to_bytes(4, "big")
    expected += data
    expect_equal(file_name, expected, hx(vector["encoded_hex"]))


def verify_client_hello_v1(file_name: str, vector: dict[str, Any]) -> None:
    credential_id = vector["credential_id"].encode()
    tunnel_path = vector["tunnel_path"].encode()
    client_nonce = hx(vector["client_nonce_hex"])
    auth_tag = client_hello_v1_tag(vector, client_nonce, credential_id, tunnel_path)
    expect_equal(file_name, auth_tag, hx(vector["auth_tag_hex"]))

    encoded = be_u16(vector["protocol_version"])
    encoded += client_nonce
    encoded += int(vector["timestamp_unix"]).to_bytes(8, "big", signed=True)
    encoded += be_u16(len(credential_id)) + credential_id
    encoded += bytes([MODES[vector["mode"]]])
    encoded += int(vector["feature_flags"]).to_bytes(8, "big")
    encoded += auth_tag
    expect_equal(file_name, encoded, hx(vector["encoded_hex"]))


def verify_server_hello_v1(file_name: str, vector: dict[str, Any]) -> None:
    client_nonce = hx(vector["client_nonce_hex"])
    server_nonce = hx(vector["server_nonce_hex"])
    session_id = hx(vector["session_id_hex"])
    auth_tag = server_hello_v1_tag(vector, client_nonce, server_nonce, session_id)
    expect_equal(file_name, auth_tag, hx(vector["server_auth_tag_hex"]))

    encoded = be_u16(vector["protocol_version_selected"])
    encoded += server_nonce
    encoded += bytes([len(session_id)])
    encoded += session_id
    encoded += int(vector["max_frame_size"]).to_bytes(4, "big")
    encoded += int(vector["max_concurrent_flows"]).to_bytes(4, "big")
    encoded += int(vector["feature_flags_selected"]).to_bytes(8, "big")
    encoded += auth_tag
    expect_equal(file_name, encoded, hx(vector["encoded_hex"]))


def verify_client_hello_v2(file_name: str, vector: dict[str, Any]) -> None:
    credential_hint = hx(vector["credential_hint_hex"])
    tunnel_path = vector["tunnel_path"].encode()
    client_nonce = hx(vector["client_nonce_hex"])
    auth_tag = client_hello_v2_tag(vector, client_nonce, credential_hint, tunnel_path)
    expect_equal(file_name, auth_tag, hx(vector["auth_tag_hex"]))

    encoded = be_u16(vector["protocol_version"])
    encoded += int(vector["auth_epoch"]).to_bytes(8, "big")
    encoded += client_nonce
    encoded += int(vector["timestamp_unix"]).to_bytes(8, "big", signed=True)
    encoded += be_u16(len(credential_hint)) + credential_hint
    encoded += bytes([MODES[vector["mode"]]])
    encoded += int(vector["feature_flags"]).to_bytes(8, "big")
    encoded += int(vector["rotation_flags"]).to_bytes(4, "big")
    encoded += auth_tag
    expect_equal(file_name, encoded, hx(vector["encoded_hex"]))


def verify_server_hello_v2(file_name: str, vector: dict[str, Any]) -> None:
    client_nonce = hx(vector["client_nonce_hex"])
    server_nonce = hx(vector["server_nonce_hex"])
    session_id = hx(vector["session_id_hex"])
    auth_tag = server_hello_v2_tag(vector, client_nonce, server_nonce, session_id)
    expect_equal(file_name, auth_tag, hx(vector["server_auth_tag_hex"]))

    encoded = be_u16(vector["protocol_version_selected"])
    encoded += int(vector["selected_epoch"]).to_bytes(8, "big")
    encoded += server_nonce
    encoded += bytes([len(session_id)])
    encoded += session_id
    encoded += int(vector["max_frame_size"]).to_bytes(4, "big")
    encoded += int(vector["max_concurrent_flows"]).to_bytes(4, "big")
    encoded += int(vector["feature_flags_selected"]).to_bytes(8, "big")
    encoded += int(vector["rotation_window_secs"]).to_bytes(4, "big")
    encoded += auth_tag
    expect_equal(file_name, encoded, hx(vector["encoded_hex"]))


def verify_replay_sequence(file_name: str, vector: dict[str, Any]) -> None:
    cache = ReplayCache(
        window_secs=int(vector["window_secs"]),
        max_entries=int(vector["max_entries"]),
    )
    for idx, step in enumerate(vector["steps"]):
        operation = step["operation"]
        if operation == "cleanup":
            cache.cleanup(int(step["now_unix"]))
            expect_len(file_name, idx, cache, int(step["len_after"]))
            continue
        if operation != "check_insert":
            raise AssertionError(f"{file_name}: unsupported replay operation {operation}")
        result = cache.check_and_insert(
            credential_id=step["credential_id"],
            nonce=hx(step["nonce_hex"]),
            timestamp_unix=int(step["timestamp_unix"]),
            now_unix=int(step["now_unix"]),
        )
        expect_replay_result(file_name, idx, step["expect"], result)
        expect_len(file_name, idx, cache, int(step["len_after"]))


class ReplayCache:
    def __init__(self, window_secs: int, max_entries: int) -> None:
        self.window_secs = window_secs
        self.max_entries = max_entries
        self.keys: set[tuple[str, bytes]] = set()
        self.entries: list[tuple[tuple[str, bytes], int]] = []

    def check_and_insert(
        self, credential_id: str, nonce: bytes, timestamp_unix: int, now_unix: int
    ) -> str:
        if len(nonce) != 32:
            raise AssertionError("replay nonce must be 32 bytes")
        if timestamp_unix < now_unix - self.window_secs:
            return "rejected_timestamp_too_old"
        if timestamp_unix > now_unix + self.window_secs:
            return "rejected_timestamp_too_new"
        self.cleanup(now_unix)
        key = (credential_id, nonce)
        if key in self.keys:
            return "rejected_duplicate_nonce"
        if len(self.entries) >= self.max_entries:
            return "rejected_cache_full"
        self.keys.add(key)
        self.entries.append((key, timestamp_unix))
        return "accepted"

    def cleanup(self, now_unix: int) -> None:
        while self.entries and self.entries[0][1] < now_unix - self.window_secs:
            old_key, _ = self.entries.pop(0)
            self.keys.remove(old_key)

    def __len__(self) -> int:
        return len(self.entries)


def expect_replay_result(file_name: str, idx: int, expected: str, actual: str) -> None:
    if actual != expected:
        raise AssertionError(
            f"{file_name}: replay step {idx} expected={expected} actual={actual}"
        )


def expect_len(file_name: str, idx: int, cache: ReplayCache, expected: int) -> None:
    actual = len(cache)
    if actual != expected:
        raise AssertionError(
            f"{file_name}: replay step {idx} len expected={expected} actual={actual}"
        )


def client_hello_v1_tag(
    vector: dict[str, Any], client_nonce: bytes, credential_id: bytes, tunnel_path: bytes
) -> bytes:
    mac = hmac.new(
        vector["secret_test_only"].encode(),
        digestmod=hashlib.sha256,
    )
    mac.update(CLIENT_HELLO_AUTH_LABEL)
    mac.update(be_u16(vector["protocol_version"]))
    mac.update(client_nonce)
    mac.update(int(vector["timestamp_unix"]).to_bytes(8, "big", signed=True))
    mac.update(be_u16(len(credential_id)))
    mac.update(credential_id)
    mac.update(be_u16(len(tunnel_path)))
    mac.update(tunnel_path)
    mac.update(bytes([MODES[vector["mode"]]]))
    mac.update(int(vector["feature_flags"]).to_bytes(8, "big"))
    return mac.digest()


def server_hello_v1_tag(
    vector: dict[str, Any], client_nonce: bytes, server_nonce: bytes, session_id: bytes
) -> bytes:
    mac = hmac.new(
        vector["secret_test_only"].encode(),
        digestmod=hashlib.sha256,
    )
    mac.update(SERVER_HELLO_AUTH_LABEL)
    mac.update(client_nonce)
    mac.update(server_nonce)
    mac.update(bytes([len(session_id)]))
    mac.update(session_id)
    mac.update(be_u16(vector["protocol_version_selected"]))
    mac.update(int(vector["max_frame_size"]).to_bytes(4, "big"))
    mac.update(int(vector["max_concurrent_flows"]).to_bytes(4, "big"))
    mac.update(int(vector["feature_flags_selected"]).to_bytes(8, "big"))
    return mac.digest()


def client_hello_v2_tag(
    vector: dict[str, Any], client_nonce: bytes, credential_hint: bytes, tunnel_path: bytes
) -> bytes:
    key = auth_v2_epoch_key(
        vector["secret_test_only"].encode(),
        int(vector["auth_epoch"]),
        AUTH_V2_CLIENT_INFO,
    )
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(CLIENT_HELLO_V2_AUTH_LABEL)
    mac.update(be_u16(vector["protocol_version"]))
    mac.update(int(vector["auth_epoch"]).to_bytes(8, "big"))
    mac.update(client_nonce)
    mac.update(int(vector["timestamp_unix"]).to_bytes(8, "big", signed=True))
    mac.update(be_u16(len(credential_hint)))
    mac.update(credential_hint)
    mac.update(be_u16(len(tunnel_path)))
    mac.update(tunnel_path)
    mac.update(bytes([MODES[vector["mode"]]]))
    mac.update(int(vector["feature_flags"]).to_bytes(8, "big"))
    mac.update(int(vector["rotation_flags"]).to_bytes(4, "big"))
    return mac.digest()


def server_hello_v2_tag(
    vector: dict[str, Any], client_nonce: bytes, server_nonce: bytes, session_id: bytes
) -> bytes:
    key = auth_v2_epoch_key(
        vector["secret_test_only"].encode(),
        int(vector["selected_epoch"]),
        AUTH_V2_SERVER_INFO,
    )
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(SERVER_HELLO_V2_AUTH_LABEL)
    mac.update(client_nonce)
    mac.update(server_nonce)
    mac.update(bytes([len(session_id)]))
    mac.update(session_id)
    mac.update(be_u16(vector["protocol_version_selected"]))
    mac.update(int(vector["selected_epoch"]).to_bytes(8, "big"))
    mac.update(int(vector["max_frame_size"]).to_bytes(4, "big"))
    mac.update(int(vector["max_concurrent_flows"]).to_bytes(4, "big"))
    mac.update(int(vector["feature_flags_selected"]).to_bytes(8, "big"))
    mac.update(int(vector["rotation_window_secs"]).to_bytes(4, "big"))
    return mac.digest()


def auth_v2_epoch_key(secret: bytes, auth_epoch: int, info: bytes) -> bytes:
    salt = AUTH_V2_EPOCH_SALT_LABEL + int(auth_epoch).to_bytes(8, "big")
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def encode_target(target: dict[str, Any]) -> bytes:
    kind = target["kind"]
    if kind == "domain":
        host = target["host"].encode()
        return b"\x03" + be_u16(len(host)) + host
    if kind == "ipv4":
        return b"\x01" + bytes(int(part) for part in target["addr"].split("."))
    if kind == "ipv6":
        parts = target["addr"].split(":")
        if len(parts) != 8:
            raise AssertionError("ipv6 vectors must use expanded form")
        return b"\x04" + b"".join(int(part, 16).to_bytes(2, "big") for part in parts)
    raise AssertionError(f"unsupported target kind {kind}")


def hx(value: str) -> bytes:
    return bytes.fromhex(value)


def be_u16(value: int) -> bytes:
    return int(value).to_bytes(2, "big")


def be_u64(value: int) -> bytes:
    return int(value).to_bytes(8, "big")


def expect_equal(file_name: str, actual: bytes, expected: bytes) -> None:
    if actual != expected:
        raise AssertionError(
            f"{file_name}: byte mismatch\nactual={actual.hex()}\nexpected={expected.hex()}"
        )


if __name__ == "__main__":
    main()
