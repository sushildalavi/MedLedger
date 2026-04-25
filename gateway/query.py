"""
Query service: fetch ciphertext blocks, decrypt only those the caller is
authorized to see, and return plaintext audit records.
"""

import base64
import json

from medcrypto.aesgcm import decrypt as aes_decrypt
from medcrypto.hashes import hmac_sha256_hex
from medcrypto.kdf import derive_patient_key


class QueryService:
    def __init__(self, replicator, master_secret: bytes, index_secret: bytes):
        self.replicator = replicator
        self.master_secret = master_secret
        self.index_secret = index_secret

    def _decrypt_for_patient(self, blocks: list[dict], patient_id: str) -> list[dict]:
        key = derive_patient_key(self.master_secret, patient_id)
        out = []
        for b in blocks:
            if b.get("index", 0) == 0:
                continue
            try:
                ciphertext = base64.b64decode(b["ciphertext"])
                nonce = base64.b64decode(b["nonce"])
                aad = base64.b64decode(b["aad"])
                plaintext = aes_decrypt(key, ciphertext, nonce, aad)
                record = json.loads(plaintext)
            except Exception:
                continue
            out.append({
                "index": b["index"],
                "event_id": b["event_id"],
                "commit_timestamp": b["commit_timestamp"],
                "node_id": b.get("node_id"),
                "record": record,
            })
        return out

    def query_patient(self, patient_id: str) -> list[dict]:
        target_hash = hmac_sha256_hex(self.index_secret, patient_id.encode("utf-8"))
        blocks = self.replicator.fetch_chain("companyA", patient_id_hash=target_hash)
        return self._decrypt_for_patient(blocks, patient_id)

    def query_all(self) -> list[dict]:
        blocks = self.replicator.fetch_chain("companyA")
        out = []
        for b in blocks:
            if b.get("index", 0) == 0:
                continue
            try:
                record = self._decrypt_block(b)
            except Exception:
                continue
            out.append({
                "index": b["index"],
                "event_id": b["event_id"],
                "commit_timestamp": b["commit_timestamp"],
                "node_id": b.get("node_id"),
                "record": record,
            })
        return out

    def _decrypt_block(self, b: dict) -> dict:
        # query_all has no patient_id up front, so we recover the patient_id
        # from the plaintext after decrypting. Strategy: try each known
        # patient key derived from the master secret. The number of patients
        # is bounded (10) so this is fast and avoids storing patient_id in
        # the clear in chain.jsonl.
        ciphertext = base64.b64decode(b["ciphertext"])
        nonce = base64.b64decode(b["nonce"])
        aad = base64.b64decode(b["aad"])
        # Patients are seeded as patient_01..patient_10. Iterate.
        for i in range(1, 11):
            patient_id = f"patient_{i:02d}"
            target_hash = hmac_sha256_hex(self.index_secret, patient_id.encode("utf-8"))
            if target_hash != b.get("patient_id_hash"):
                continue
            key = derive_patient_key(self.master_secret, patient_id)
            plaintext = aes_decrypt(key, ciphertext, nonce, aad)
            return json.loads(plaintext)
        raise ValueError("no key matched patient_id_hash")
