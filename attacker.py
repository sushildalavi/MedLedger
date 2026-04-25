"""
Internal-attacker simulation tool.

Modifies a node's chain.jsonl directly to mimic an attacker who has
filesystem access to one audit-company repository. Use the verify CLI
command afterward to confirm tamper detection.

Modes:
    modify-ciphertext   flip bytes in the ciphertext of a chosen block
    delete-block        remove a chosen block from the chain
    modify-prev-hash    rewrite the prev_hash of a chosen block
"""

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def _chain_path(node_id: str) -> Path:
    return DATA / node_id / "chain.jsonl"


def _read_chain(node_id: str) -> list[dict]:
    path = _chain_path(node_id)
    if not path.exists():
        raise SystemExit(f"chain not found: {path}")
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _write_chain(node_id: str, blocks: list[dict]) -> None:
    path = _chain_path(node_id)
    with path.open("w", encoding="utf-8") as f:
        for block in blocks:
            f.write(json.dumps(block) + "\n")


def modify_ciphertext(node_id: str, index: int) -> None:
    blocks = _read_chain(node_id)
    if index >= len(blocks):
        raise SystemExit(f"block {index} not found on {node_id}")
    block = blocks[index]
    raw = bytearray(base64.b64decode(block["ciphertext"]))
    if not raw:
        raise SystemExit(f"block {index} on {node_id} has empty ciphertext")
    raw[0] ^= 0x01
    block["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    _write_chain(node_id, blocks)
    print(f"flipped 1 byte of ciphertext at block {index} on {node_id}")


def delete_block(node_id: str, index: int) -> None:
    blocks = _read_chain(node_id)
    if index >= len(blocks):
        raise SystemExit(f"block {index} not found on {node_id}")
    del blocks[index]
    _write_chain(node_id, blocks)
    print(f"deleted block {index} on {node_id}")


def modify_prev_hash(node_id: str, index: int) -> None:
    blocks = _read_chain(node_id)
    if index >= len(blocks):
        raise SystemExit(f"block {index} not found on {node_id}")
    block = blocks[index]
    block["prev_hash"] = "0" * 64
    _write_chain(node_id, blocks)
    print(f"overwrote prev_hash at block {index} on {node_id}")


def main() -> int:
    p = argparse.ArgumentParser(prog="attacker")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("tamper")
    t.add_argument("--node", required=True, choices=["companyA", "companyB", "companyC"])
    t.add_argument("--block", type=int, required=True)
    t.add_argument("--mode", required=True, choices=["modify-ciphertext", "delete-block", "modify-prev-hash"])

    args = p.parse_args()
    if args.mode == "modify-ciphertext":
        modify_ciphertext(args.node, args.block)
    elif args.mode == "delete-block":
        delete_block(args.node, args.block)
    elif args.mode == "modify-prev-hash":
        modify_prev_hash(args.node, args.block)
    else:
        print(f"unknown mode: {args.mode}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
