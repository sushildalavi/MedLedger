"""
Audit-company node service.

Each instance is owned by one audit company (companyA/B/C). The gateway
authenticates using a per-node shared secret in `X-Gateway-Auth` (HMAC
of the request body). Every append is validated locally before the node
signs and persists the block.

Run:
    python -m node.server --node-id companyA
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from flask import Flask, jsonify, request

from medcrypto.block import compute_block_hash
from medcrypto.hashes import hmac_sha256, hmac_compare
from medcrypto.signatures import load_private, sign as ed_sign

from .chain import verify_chain
from .storage import ChainStorage

ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    return json.loads((ROOT / "config.json").read_text())


def build_app(node_id: str) -> Flask:
    config = load_config()
    if node_id not in config["nodes"]:
        raise SystemExit(f"unknown node id: {node_id}")
    node_cfg = config["nodes"][node_id]

    storage = ChainStorage(ROOT / node_cfg["data_path"])
    private_key = load_private((ROOT / node_cfg["private_key_path"]).read_bytes())
    public_key_pem = node_cfg["public_key_pem"].encode("ascii")
    shared_secret = bytes.fromhex(node_cfg["shared_secret_hex"])

    app = Flask(node_id)
    app.config["NODE_ID"] = node_id

    def _check_gateway_auth(raw_body: bytes) -> bool:
        provided = request.headers.get("X-Gateway-Auth", "")
        if not provided:
            return False
        try:
            provided_bytes = bytes.fromhex(provided)
        except ValueError:
            return False
        expected = hmac_sha256(shared_secret, raw_body)
        return hmac_compare(provided_bytes, expected)

    @app.get("/node/health")
    def health():
        tip = storage.tip()
        return jsonify({
            "node_id": node_id,
            "status": "ok",
            "tip_index": tip["index"] if tip else None,
        })

    @app.get("/node/chain")
    def chain():
        if not _check_gateway_auth(request.get_data()):
            return jsonify({"error": "unauthorized"}), 401
        patient_id_hash = request.args.get("patient_id_hash")
        blocks = storage.read_all()
        if patient_id_hash:
            blocks = [b for b in blocks if b.get("patient_id_hash") == patient_id_hash and b.get("index", 0) > 0]
        return jsonify({"node_id": node_id, "blocks": blocks})

    @app.get("/node/verify")
    def verify():
        if not _check_gateway_auth(request.get_data()):
            return jsonify({"error": "unauthorized"}), 401
        blocks = storage.read_all()
        result = verify_chain(blocks, public_key_pem)
        result["node_id"] = node_id
        return jsonify(result)

    @app.post("/node/append")
    def append():
        raw = request.get_data()
        if not _check_gateway_auth(raw):
            return jsonify({"error": "unauthorized"}), 401
        try:
            block = json.loads(raw)
        except json.JSONDecodeError:
            return jsonify({"error": "invalid json"}), 400

        required = {"index", "event_id", "commit_timestamp", "prev_hash",
                    "patient_id_hash", "ciphertext", "nonce", "aad", "hash"}
        if not required.issubset(block.keys()):
            return jsonify({"error": "missing fields"}), 400

        chain = storage.read_all()
        if not chain:
            return jsonify({"error": "node not seeded"}), 500
        tip = chain[-1]

        if block["index"] != tip["index"] + 1:
            return jsonify({"error": "index mismatch", "expected": tip["index"] + 1}), 409
        if block["prev_hash"] != tip["hash"]:
            return jsonify({"error": "prev_hash mismatch"}), 409
        if any(b.get("event_id") == block["event_id"] for b in chain):
            return jsonify({"error": "duplicate event_id"}), 409
        if compute_block_hash(block) != block["hash"]:
            return jsonify({"error": "hash does not match payload"}), 400

        signature = ed_sign(private_key, block["hash"].encode("ascii"))
        finalized = dict(block)
        finalized["node_id"] = node_id
        finalized["signature"] = base64.b64encode(signature).decode("ascii")
        storage.append(finalized)

        return jsonify({
            "status": "appended",
            "node_id": node_id,
            "index": finalized["index"],
            "signature": finalized["signature"],
        })

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", required=True)
    parser.add_argument(
        "--host",
        help="Bind interface (defaults to nodes[<id>].bind_host from config). Use 0.0.0.0 to expose on the LAN.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Bind port (defaults to the port in nodes[<id>].url from config).",
    )
    args = parser.parse_args()

    config = load_config()
    if args.node_id not in config["nodes"]:
        print(f"unknown node id: {args.node_id}", file=sys.stderr)
        sys.exit(1)

    node_cfg = config["nodes"][args.node_id]
    host = args.host or node_cfg.get("bind_host", "127.0.0.1")
    port = args.port or int(node_cfg["url"].rsplit(":", 1)[-1])

    cert_path = node_cfg.get("tls_cert_path")
    key_path = node_cfg.get("tls_key_path")
    if not cert_path or not key_path:
        print(f"node {args.node_id} missing TLS material in config; re-run seed.py", file=sys.stderr)
        sys.exit(1)
    ssl_context = (str(ROOT / cert_path), str(ROOT / key_path))

    app = build_app(args.node_id)
    app.run(host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
