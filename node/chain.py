"""
Local chain verification for a single node.

Replays the chain from genesis: every block_hash must recompute, every
prev_hash must match the previous block's hash, and every Ed25519
signature must verify against the node's public key. Genesis (index 0)
is unsigned by convention.
"""

import base64

from medcrypto.block import compute_block_hash
from medcrypto.signatures import load_public, verify as ed_verify


def verify_chain(blocks: list[dict], public_key_pem: bytes) -> dict:
    if not blocks:
        return {"valid": False, "block_index": None, "reason": "empty chain"}
    pk = load_public(public_key_pem)

    prev_hash = "0" * 64
    seen_event_ids: set[str] = set()
    for i, block in enumerate(blocks):
        if block.get("index") != i:
            return {"valid": False, "block_index": i, "reason": f"index mismatch (got {block.get('index')})"}
        if block.get("prev_hash") != prev_hash:
            return {"valid": False, "block_index": i, "reason": "prev_hash linkage broken"}
        recomputed = compute_block_hash(block)
        if block.get("hash") != recomputed:
            return {"valid": False, "block_index": i, "reason": "stored hash does not match recomputed hash"}
        event_id = block.get("event_id", "")
        if i > 0:
            if event_id in seen_event_ids:
                return {"valid": False, "block_index": i, "reason": f"duplicate event_id {event_id}"}
            seen_event_ids.add(event_id)

            sig_b64 = block.get("signature", "")
            if not sig_b64:
                return {"valid": False, "block_index": i, "reason": "missing signature"}
            try:
                sig = base64.b64decode(sig_b64)
            except (ValueError, base64.binascii.Error):
                return {"valid": False, "block_index": i, "reason": "malformed signature encoding"}
            if not ed_verify(pk, recomputed.encode("ascii"), sig):
                return {"valid": False, "block_index": i, "reason": "ed25519 signature verification failed"}
        prev_hash = recomputed
    return {"valid": True}
