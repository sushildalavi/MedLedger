"""
Block payload schema and hash computation, shared by gateway and nodes.

The block payload (the dict whose canonical JSON is the input to block_hash)
is identical across all honest nodes. Only `node_id` and `signature` are
node-specific and are NOT part of the hash input.
"""

from .canonical import canonical_json
from .hashes import sha256_hex

PAYLOAD_FIELDS = (
    "index",
    "event_id",
    "commit_timestamp",
    "prev_hash",
    "patient_id_hash",
    "ciphertext",
    "nonce",
    "aad",
)


def block_payload(block: dict) -> dict:
    return {k: block[k] for k in PAYLOAD_FIELDS}


def compute_block_hash(block: dict) -> str:
    return sha256_hex(canonical_json(block_payload(block)))
