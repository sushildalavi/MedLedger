"""
Gateway replication coordinator.

Encrypts an audit record once, builds a canonical block payload, and
broadcasts the identical payload to every audit node. Each node verifies
the payload, signs the block_hash with its own Ed25519 key, and persists.

In `strict` mode, the write commits only when 3-of-3 nodes ack.
In `quorum` mode, 2-of-3 acks are sufficient.
"""

import base64
import json
import uuid
from datetime import datetime, timezone

import requests

from medcrypto.aesgcm import encrypt as aes_encrypt
from medcrypto.block import compute_block_hash
from medcrypto.canonical import canonical_json
from medcrypto.hashes import hmac_sha256, hmac_sha256_hex
from medcrypto.kdf import derive_patient_key

VALID_ACTIONS = {"create", "delete", "change", "query", "print", "copy"}


class ReplicationError(Exception):
    pass


class Replicator:
    def __init__(self, nodes_cfg: dict, master_secret: bytes, index_secret: bytes, mode: str = "strict"):
        self.nodes_cfg = nodes_cfg
        self.master_secret = master_secret
        self.index_secret = index_secret
        self.mode = mode

    def _required_acks(self) -> int:
        return 3 if self.mode == "strict" else 2

    def _gateway_auth_header(self, node_id: str, body: bytes) -> dict:
        secret = bytes.fromhex(self.nodes_cfg[node_id]["shared_secret_hex"])
        return {"X-Gateway-Auth": hmac_sha256(secret, body).hex()}

    def fetch_chain(self, node_id: str, patient_id_hash: str | None = None) -> list[dict]:
        url = f"{self.nodes_cfg[node_id]['url']}/node/chain"
        headers = self._gateway_auth_header(node_id, b"")
        params = {"patient_id_hash": patient_id_hash} if patient_id_hash else None
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()["blocks"]

    def fetch_local_verify(self, node_id: str) -> dict:
        url = f"{self.nodes_cfg[node_id]['url']}/node/verify"
        headers = self._gateway_auth_header(node_id, b"")
        resp = requests.get(url, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()

    def commit(self, record: dict) -> dict:
        if record.get("action") not in VALID_ACTIONS:
            raise ReplicationError(f"invalid action: {record.get('action')}")

        for field in ("timestamp", "patient_id", "user_id", "action"):
            if field not in record:
                raise ReplicationError(f"missing field: {field}")

        # Determine next index from any node's view of the chain. They must
        # agree in strict mode; we trust companyA as the read source.
        chain_a = self.fetch_chain("companyA")
        next_index = chain_a[-1]["index"] + 1
        prev_hash = chain_a[-1]["hash"]

        patient_id = record["patient_id"]
        patient_id_hash = hmac_sha256_hex(self.index_secret, patient_id.encode("utf-8"))
        event_id = str(uuid.uuid4())
        commit_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        plaintext = canonical_json(record)
        aad = canonical_json({
            "index": next_index,
            "event_id": event_id,
            "patient_id_hash": patient_id_hash,
        })
        key = derive_patient_key(self.master_secret, patient_id)
        ciphertext, nonce = aes_encrypt(key, plaintext, aad)

        payload = {
            "index": next_index,
            "event_id": event_id,
            "commit_timestamp": commit_timestamp,
            "prev_hash": prev_hash,
            "patient_id_hash": patient_id_hash,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "aad": base64.b64encode(aad).decode("ascii"),
        }
        block = dict(payload)
        block["hash"] = compute_block_hash(block)

        body = json.dumps(block).encode("utf-8")
        acks: list[dict] = []
        errors: list[dict] = []
        for node_id in self.nodes_cfg.keys():
            url = f"{self.nodes_cfg[node_id]['url']}/node/append"
            try:
                resp = requests.post(
                    url,
                    data=body,
                    headers={
                        **self._gateway_auth_header(node_id, body),
                        "Content-Type": "application/json",
                    },
                    timeout=5,
                )
                if resp.status_code == 200:
                    acks.append({"node_id": node_id, "response": resp.json()})
                else:
                    errors.append({"node_id": node_id, "status": resp.status_code, "body": resp.text})
            except requests.RequestException as e:
                errors.append({"node_id": node_id, "error": str(e)})

        required = self._required_acks()
        committed = len(acks) >= required

        return {
            "status": "committed" if committed else "rejected",
            "acks": len(acks),
            "required_acks": required,
            "mode": self.mode,
            "event_id": event_id,
            "index": next_index,
            "errors": errors,
        }
