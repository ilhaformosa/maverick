#!/usr/bin/env python3
"""Import small official crypto vector subsets for disabled experiments."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any


HPKE_URL = "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json"
ML_KEM_KEY_PROMPT_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json"
ML_KEM_KEY_EXPECTED_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json"
ML_KEM_ENCAP_PROMPT_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json"
ML_KEM_ENCAP_EXPECTED_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json"
EXPECTED_SHA256 = {
    HPKE_URL: "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6",
    ML_KEM_KEY_PROMPT_URL: "3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523",
    ML_KEM_KEY_EXPECTED_URL: "a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4",
    ML_KEM_ENCAP_PROMPT_URL: "91d405f78eb450d42e59e40948148212566e7b31b3ff953366c01c084152a0e3",
    ML_KEM_ENCAP_EXPECTED_URL: "5f1544d9604ca27c0388d114344fa14ee4d8f8e902a1c13832aa8ff5db3c535d",
}


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = repo_root / "test-vectors"
    out_dir.mkdir(exist_ok=True)

    write_json(out_dir / "hpke-config-v1.json", build_hpke_subset())
    write_json(out_dir / "ml-kem-768-hybrid-v1.json", build_ml_kem_subset())
    # Noise vectors are implementation-backed by the Rust/Snow harness. Do not
    # overwrite them with metadata-only placeholders from this importer.
    print("imported HPKE and ML-KEM crypto vector subsets")


def build_hpke_subset() -> dict[str, Any]:
    raw, vectors = fetch_json(HPKE_URL)
    vector = vectors[0]
    encryption = vector["encryptions"][0]
    export = vector["exports"][0]
    return {
        "suite": "hpke_config_v1",
        "status": "imported_official_subset_no_runtime",
        "source": {
            "name": "CFRG HPKE test-vectors.json",
            "url": HPKE_URL,
            "sha256": sha256(raw),
        },
        "cases": [
            {
                "id": "rfc9180_base_x25519_hkdf_sha256_aes128gcm_case0",
                "mode": vector["mode"],
                "kem_id": vector["kem_id"],
                "kdf_id": vector["kdf_id"],
                "aead_id": vector["aead_id"],
                "info": vector["info"],
                "enc": vector["enc"],
                "shared_secret": vector["shared_secret"],
                "key": vector["key"],
                "base_nonce": vector["base_nonce"],
                "exporter_secret": vector["exporter_secret"],
                "encryption": {
                    "aad": encryption["aad"],
                    "pt": encryption["pt"],
                    "nonce": encryption["nonce"],
                    "ct": encryption["ct"],
                },
                "export": {
                    "exporter_context": export["exporter_context"],
                    "length": export["L"],
                    "exported_value": export["exported_value"],
                },
            }
        ],
    }


def build_ml_kem_subset() -> dict[str, Any]:
    key_prompt_raw, key_prompt = fetch_json(ML_KEM_KEY_PROMPT_URL)
    key_expected_raw, key_expected = fetch_json(ML_KEM_KEY_EXPECTED_URL)
    encap_prompt_raw, encap_prompt = fetch_json(ML_KEM_ENCAP_PROMPT_URL)
    encap_expected_raw, encap_expected = fetch_json(ML_KEM_ENCAP_EXPECTED_URL)

    key_prompt_group, key_prompt_case = first_case(key_prompt, "ML-KEM-768")
    key_expected_group = group_by_id(key_expected, key_prompt_group["tgId"])
    key_expected_case = case_by_id(key_expected_group, key_prompt_case["tcId"])

    encap_prompt_group, encap_prompt_case = first_case(
        encap_prompt, "ML-KEM-768", function="encapsulation"
    )
    encap_expected_group = group_by_id(encap_expected, encap_prompt_group["tgId"])
    encap_expected_case = case_by_id(encap_expected_group, encap_prompt_case["tcId"])

    return {
        "suite": "ml_kem_768_hybrid_v1",
        "status": "imported_official_subset_no_runtime",
        "sources": [
            source("NIST ACVP ML-KEM keyGen prompt", ML_KEM_KEY_PROMPT_URL, key_prompt_raw),
            source(
                "NIST ACVP ML-KEM keyGen expectedResults",
                ML_KEM_KEY_EXPECTED_URL,
                key_expected_raw,
            ),
            source(
                "NIST ACVP ML-KEM encapDecap prompt",
                ML_KEM_ENCAP_PROMPT_URL,
                encap_prompt_raw,
            ),
            source(
                "NIST ACVP ML-KEM encapDecap expectedResults",
                ML_KEM_ENCAP_EXPECTED_URL,
                encap_expected_raw,
            ),
        ],
        "cases": [
            {
                "id": "nist_acvp_ml_kem_768_keygen_tg{}_tc{}".format(
                    key_prompt_group["tgId"], key_prompt_case["tcId"]
                ),
                "kind": "key_gen",
                "parameter_set": "ML-KEM-768",
                "z": key_prompt_case["z"],
                "d": key_prompt_case["d"],
                "ek": key_expected_case["ek"],
                "dk": key_expected_case["dk"],
            },
            {
                "id": "nist_acvp_ml_kem_768_encapsulation_tg{}_tc{}".format(
                    encap_prompt_group["tgId"], encap_prompt_case["tcId"]
                ),
                "kind": "encapsulation",
                "parameter_set": "ML-KEM-768",
                "ek": encap_prompt_case["ek"],
                "c": encap_expected_case["c"],
                "k": encap_expected_case["k"],
            },
        ],
    }


def first_case(
    document: dict[str, Any], parameter_set: str, function: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    for group in document["testGroups"]:
        if group.get("parameterSet") != parameter_set:
            continue
        if function is not None and group.get("function") != function:
            continue
        return group, group["tests"][0]
    raise AssertionError(f"missing {parameter_set} {function or ''} test group")


def group_by_id(document: dict[str, Any], group_id: int) -> dict[str, Any]:
    for group in document["testGroups"]:
        if group["tgId"] == group_id:
            return group
    raise AssertionError(f"missing test group {group_id}")


def case_by_id(group: dict[str, Any], case_id: int) -> dict[str, Any]:
    for case in group["tests"]:
        if case["tcId"] == case_id:
            return case
    raise AssertionError(f"missing test case {case_id}")


def source(name: str, url: str, raw: bytes) -> dict[str, str]:
    return {"name": name, "url": url, "sha256": sha256(raw)}


def fetch_json(url: str) -> tuple[bytes, Any]:
    with urllib.request.urlopen(url) as response:
        raw = response.read()
    expected = EXPECTED_SHA256.get(url)
    if expected is None:
        raise AssertionError(f"no pinned digest for crypto vector source: {url}")
    actual = sha256(raw)
    if actual != expected:
        raise AssertionError(
            f"crypto vector source digest mismatch for {url}: expected {expected}, got {actual}"
        )
    return raw, json.loads(raw)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
