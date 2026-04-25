"""
Seed deterministic users, keys, secrets, and genesis blocks.

Run once before starting the system. Idempotent: re-running rewrites all
keys/secrets/users and clears the on-disk chains.
"""

import json
import os
import secrets
from pathlib import Path

from medcrypto.canonical import canonical_json
from medcrypto.hashes import hmac_sha256_hex, sha256_hex
from medcrypto.passwords import hash_password
from medcrypto.signatures import generate_keypair

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
KEYS = ROOT / "keys"
CONFIG = ROOT / "config.json"

NODES = ["companyA", "companyB", "companyC"]

PATIENTS = [f"patient_{i:02d}" for i in range(1, 11)]
DOCTORS = [f"doctor_{i:02d}" for i in range(1, 4)]
AUDITS = ["audit_company_A", "audit_company_B", "audit_company_C"]
ADMINS = ["admin"]

GENESIS_INDEX = 0
GENESIS_PREV_HASH = "0" * 64
GENESIS_TIMESTAMP = "2026-01-01T00:00:00Z"
GENESIS_EVENT_ID = "00000000-0000-0000-0000-000000000000"


def build_users() -> dict:
    users = {}
    for u in PATIENTS:
        users[u] = {"role": "patient", "password": hash_password(f"pw_{u}")}
    for u in DOCTORS:
        users[u] = {"role": "doctor", "password": hash_password(f"pw_{u}")}
    for u in AUDITS:
        users[u] = {"role": "audit", "password": hash_password(f"pw_{u}")}
    for u in ADMINS:
        users[u] = {"role": "admin", "password": hash_password(f"pw_{u}")}
    return users


def build_node_keys() -> dict:
    KEYS.mkdir(exist_ok=True)
    out = {}
    for node_id in NODES:
        sk_pem, pk_pem = generate_keypair()
        sk_path = KEYS / f"{node_id}_ed25519.pem"
        pk_path = KEYS / f"{node_id}_ed25519.pub"
        sk_path.write_bytes(sk_pem)
        pk_path.write_bytes(pk_pem)
        os.chmod(sk_path, 0o600)
        out[node_id] = {
            "private_key_path": str(sk_path.relative_to(ROOT)),
            "public_key_path": str(pk_path.relative_to(ROOT)),
            "public_key_pem": pk_pem.decode("ascii"),
        }
    return out


def build_genesis(node_id: str, index_secret_hex: str) -> dict:
    patient_id_hash = hmac_sha256_hex(bytes.fromhex(index_secret_hex), b"__genesis__")
    payload = {
        "index": GENESIS_INDEX,
        "event_id": GENESIS_EVENT_ID,
        "commit_timestamp": GENESIS_TIMESTAMP,
        "prev_hash": GENESIS_PREV_HASH,
        "patient_id_hash": patient_id_hash,
        "ciphertext": "",
        "nonce": "",
        "aad": "",
    }
    block_hash = sha256_hex(canonical_json(payload))
    block = dict(payload)
    block["hash"] = block_hash
    block["node_id"] = node_id
    block["signature"] = ""  # genesis is unsigned; signature checks skip index 0
    return block


def reset_chains(index_secret_hex: str) -> None:
    for node_id in NODES:
        node_dir = DATA / node_id
        node_dir.mkdir(parents=True, exist_ok=True)
        chain_path = node_dir / "chain.jsonl"
        with chain_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(build_genesis(node_id, index_secret_hex)) + "\n")


def main() -> None:
    DATA.mkdir(exist_ok=True)
    users = build_users()
    node_keys = build_node_keys()

    config = {
        "users": users,
        "nodes": {
            node_id: {
                "url": f"http://127.0.0.1:{8001 + i}",
                "shared_secret_hex": secrets.token_hex(32),
                "private_key_path": node_keys[node_id]["private_key_path"],
                "public_key_path": node_keys[node_id]["public_key_path"],
                "public_key_pem": node_keys[node_id]["public_key_pem"],
                "data_path": str((DATA / node_id / "chain.jsonl").relative_to(ROOT)),
            }
            for i, node_id in enumerate(NODES)
        },
        "secrets": {
            "master_secret_hex": secrets.token_hex(32),
            "index_secret_hex": secrets.token_hex(32),
            "token_secret_hex": secrets.token_hex(32),
        },
        "replication": {
            "mode": "strict",  # 'strict' = 3-of-3, 'quorum' = 2-of-3
        },
        "gateway": {
            "host": "127.0.0.1",
            "port": 9000,
        },
    }
    CONFIG.write_text(json.dumps(config, indent=2))
    os.chmod(CONFIG, 0o600)

    reset_chains(config["secrets"]["index_secret_hex"])

    print(f"Wrote {CONFIG.relative_to(ROOT)}")
    print(f"Seeded {len(users)} users")
    print(f"Generated Ed25519 keypairs for {', '.join(NODES)}")
    print(f"Wrote genesis block to {len(NODES)} chains")


if __name__ == "__main__":
    main()
