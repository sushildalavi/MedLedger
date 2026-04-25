"""
Gateway service: authentication, RBAC, EHR access write path, query, verify.

Run:
    python -m gateway.server
"""

import json
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory

from .auth import AuthService, require_roles
from .query import QueryService
from .replication import Replicator, ReplicationError, VALID_ACTIONS
from .verify import VerificationService

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"


def load_config() -> dict:
    return json.loads((ROOT / "config.json").read_text())


def build_app() -> Flask:
    config = load_config()

    node_bundle_rel = config.get("tls", {}).get("node_bundle_path")
    node_ca_bundle = str(ROOT / node_bundle_rel) if node_bundle_rel else None

    auth = AuthService(
        users=config["users"],
        token_secret=bytes.fromhex(config["secrets"]["token_secret_hex"]),
    )
    replicator = Replicator(
        nodes_cfg=config["nodes"],
        master_secret=bytes.fromhex(config["secrets"]["master_secret_hex"]),
        index_secret=bytes.fromhex(config["secrets"]["index_secret_hex"]),
        mode=config["replication"]["mode"],
        node_ca_bundle=node_ca_bundle,
    )
    queries = QueryService(
        replicator=replicator,
        master_secret=bytes.fromhex(config["secrets"]["master_secret_hex"]),
        index_secret=bytes.fromhex(config["secrets"]["index_secret_hex"]),
    )
    verifier = VerificationService(replicator=replicator)

    app = Flask("medledger-gateway")

    @app.post("/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("user")
        password = data.get("password")
        if not username or not password:
            return jsonify({"error": "user and password required"}), 400
        token = auth.login(username, password)
        if not token:
            return jsonify({"error": "invalid credentials"}), 401
        role = config["users"][username]["role"]
        return jsonify({"token": token, "user": username, "role": role})

    @app.post("/ehr/access")
    @require_roles(auth, "doctor", "admin")
    def ehr_access():
        data = request.get_json(silent=True) or {}
        record = {
            "timestamp": data.get("timestamp") or _utc_now(),
            "patient_id": data.get("patient_id"),
            "user_id": g.user["user"],
            "action": data.get("action"),
        }
        if record["action"] not in VALID_ACTIONS:
            return jsonify({
                "error": "invalid action",
                "allowed": sorted(VALID_ACTIONS),
            }), 400
        if not record["patient_id"]:
            return jsonify({"error": "patient_id required"}), 400
        try:
            result = replicator.commit(record)
        except ReplicationError as e:
            return jsonify({"error": str(e)}), 400
        status_code = 200 if result["status"] == "committed" else 502
        return jsonify(result), status_code

    @app.get("/audit/patient/<patient_id>")
    @require_roles(auth, "patient", "audit", "admin")
    def audit_patient(patient_id: str):
        if g.user["role"] == "patient" and g.user["user"] != patient_id:
            return jsonify({"error": "forbidden: patients may only query their own audit log"}), 403
        records = queries.query_patient(patient_id)
        return jsonify({"patient_id": patient_id, "records": records})

    @app.get("/audit/all")
    @require_roles(auth, "audit", "admin")
    def audit_all():
        records = queries.query_all()
        return jsonify({"records": records})

    @app.get("/verify")
    @require_roles(auth)
    def verify_system():
        return jsonify(verifier.verify_system())

    @app.get("/nodes")
    @require_roles(auth, "admin")
    def nodes():
        out = {}
        for node_id, cfg in config["nodes"].items():
            out[node_id] = {"url": cfg["url"]}
        return jsonify(out)

    @app.get("/admin/storage/<node_id>")
    @require_roles(auth, "admin")
    def admin_storage(node_id: str):
        if node_id not in config["nodes"]:
            return jsonify({"error": "unknown node"}), 404
        try:
            blocks = replicator.fetch_chain(node_id)
        except Exception as e:
            return jsonify({"error": f"chain fetch failed: {e}"}), 502
        # Return blocks as-is so the UI can show that ciphertext is opaque.
        return jsonify({"node_id": node_id, "blocks": blocks})

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/")
    def web_root():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/web/<path:filename>")
    def web_static(filename: str):
        return send_from_directory(WEB_DIR, filename)

    return app


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    config = load_config()
    app = build_app()
    cert = config["gateway"].get("tls_cert_path")
    key = config["gateway"].get("tls_key_path")
    if not cert or not key:
        raise SystemExit("gateway missing TLS material in config; re-run seed.py")
    ssl_context = (str(ROOT / cert), str(ROOT / key))
    app.run(
        host=config["gateway"]["host"],
        port=config["gateway"]["port"],
        debug=False,
        use_reloader=False,
        ssl_context=ssl_context,
    )


if __name__ == "__main__":
    main()
