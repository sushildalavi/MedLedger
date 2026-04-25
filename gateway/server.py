"""
Gateway service: authentication, RBAC, EHR access write path, query, verify.

Run:
    python -m gateway.server
"""

import json
from pathlib import Path

from flask import Flask, g, jsonify, request

from .auth import AuthService, require_roles
from .query import QueryService
from .replication import Replicator, ReplicationError, VALID_ACTIONS
from .verify import VerificationService

ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    return json.loads((ROOT / "config.json").read_text())


def build_app() -> Flask:
    config = load_config()

    auth = AuthService(
        users=config["users"],
        token_secret=bytes.fromhex(config["secrets"]["token_secret_hex"]),
    )
    replicator = Replicator(
        nodes_cfg=config["nodes"],
        master_secret=bytes.fromhex(config["secrets"]["master_secret_hex"]),
        index_secret=bytes.fromhex(config["secrets"]["index_secret_hex"]),
        mode=config["replication"]["mode"],
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

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    config = load_config()
    app = build_app()
    app.run(
        host=config["gateway"]["host"],
        port=config["gateway"]["port"],
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
