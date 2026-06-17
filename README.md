# MedLedger

## What this is

A prototype audit-logging system for electronic health records that satisfies five goals: privacy, identification & authorization, queries, immutability, decentralization. Audit records are encrypted, hash-chained across three independent audit-company nodes, and signed per node. A single tampered node is detected by cross-node majority comparison.

All inter-service traffic is HTTPS with self-signed certs. The gateway pins each node's cert via a CA bundle (no `verify=False` anywhere). The CLI pins the gateway's cert. A vanilla-JS web UI is served by the gateway.

## Layout

```
gateway/      Flask service: auth, RBAC, replication, queries, verify, web UI hosting
node/         Flask service: per-company audit node (3 instances)
medcrypto/    AES-GCM, HKDF, HMAC, PBKDF2, Ed25519, tokens, canonical JSON, TLS cert gen
web/          single-page web UI (vanilla HTML/CSS/JS)
cli.py        client: login, access, query, query-all, verify
attacker.py   internal-attacker simulation: 3 tamper modes
seed.py       deterministic setup of users, keys, secrets, TLS certs, genesis blocks
scripts/      run_local.sh, demo.sh, reset.sh, tamper_demo.sh
data/         per-node chain.jsonl files (gitignored)
keys/         per-node Ed25519 keypairs (gitignored)
certs/        TLS cert/key per service + node_bundle.pem (gitignored)
report/       written report + screenshots
```

## Setup (single machine)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py            # generates users, keys, TLS certs, genesis blocks
./scripts/run_local.sh    # starts gateway :9000 + nodes :8001/2/3 over TLS
```

Open the web UI: `https://127.0.0.1:9000` — accept the self-signed cert warning. Sign in as e.g. `doctor_01` with password `pw_doctor_01`.

## End-to-end demo

```bash
./scripts/demo.sh         # login, generate all 6 actions, query, verify
./scripts/tamper_demo.sh  # baseline -> 3 tamper modes -> detection
```

## Multi-machine deployment

The gateway and each audit node read URLs from `config.json`. To run a node on a different machine:

1. Run `python seed.py` once on the gateway machine. This generates all keys, certs, secrets, and the per-node configuration.
2. Copy these files to the remote node machine:
   - `config.json`
   - `keys/<node>_ed25519.pem` and `keys/<node>_ed25519.pub`
   - `certs/<node>.crt` and `certs/<node>.key`
   - `data/<node>/chain.jsonl`
   - the source tree (or `pip install` the same deps)
3. On the remote machine, edit `config.json` so `nodes.<node>.bind_host` is `0.0.0.0` (bind all interfaces) or its specific LAN IP, then start it:

   ```bash
   python -m node.server --node-id companyB --host 0.0.0.0
   ```

4. On the gateway machine, edit `config.json` so `nodes.<node>.url` is `https://<remote-ip-or-hostname>:8002`, then start the gateway normally.

The gateway verifies each node's TLS cert against the pinned `certs/node_bundle.pem`, so cert verification keeps working across machines (the CA bundle was built on the gateway machine and is the source of truth).

## Cryptographic stack

| Concern | Mechanism |
|---|---|
| At-rest record encryption | AES-256-GCM, AAD = `index ‖ event_id ‖ patient_id_hash` |
| Per-patient key derivation | HKDF-SHA256 from a master secret held only by the gateway |
| Patient-ID indexing | HMAC-SHA256 (no plaintext patient_id in storage) |
| Block linkage | SHA-256 hash chain |
| Per-node block attestation | Ed25519 signature on `block_hash` |
| Gateway → node auth | per-node shared secret in `X-Gateway-Auth` (HMAC of body) |
| Service transport | TLS 1.2+ (self-signed certs, pinned via CA bundle) |
| Tokens | HMAC-SHA256-signed JSON |
| Passwords | PBKDF2-HMAC-SHA256, 200,000 iterations, per-user salt |

## External packages (disclosed)

| Package | Used for |
|---|---|
| Flask | gateway and audit node HTTP servers, static file serving |
| cryptography | AES-256-GCM, Ed25519, HKDF, RSA + X.509 cert generation |
| requests | gateway → node HTTP calls (cert verification via pinned bundle) |

Everything else uses the Python standard library (`hmac`, `hashlib`, `secrets`, `json`, `base64`, `time`, `argparse`, `os`, `pathlib`, `threading`, `uuid`, `dataclasses`, `ssl`, `ipaddress`, `datetime`).

## Roles

| Role | Permissions |
|---|---|
| patient | Query only their own audit logs |
| doctor | Generate EHR access events |
| audit | Query all audit logs |
| admin | Generate events, query all, run system verify, view raw encrypted storage |

## Seeded users

`patient_01` … `patient_10`, `doctor_01`–`doctor_03`, `audit_company_A`/`B`/`C`, `admin`. Default password for every seeded user: `pw_<username>` (see `seed.py`).

## What's prototype-grade vs production

This is a prototype. The following are explicitly listed as limitations in the report rather than fixed in code:

- **Self-signed certs.** Production would use CA-signed certs or a private PKI. The pinning model (CA bundle) is the right shape but the certs themselves are throwaway.
- **Local key storage.** All long-term secrets (Ed25519 private keys, master/index/token secrets, gateway↔node shared secrets, TLS keys) live on disk. Production would use a KMS/HSM with policy-controlled key release.
- **Werkzeug dev server.** Flask's built-in server is fine for the demo. Production would put the apps behind a hardened WSGI server (gunicorn/uWSGI) and a reverse proxy.
- **No catch-up protocol.** Strict 3-of-3 mode demands all nodes be online. Quorum 2-of-3 mode is implemented but a node that misses a write during downtime stays behind permanently — there is no reconciliation.
- **No real EHR.** The audit system trusts that authenticated doctors honestly report access events. The assignment explicitly does not require a real EHR access-control component.
- **`patient_id_hash` allows frequency analysis.** An observer of `chain.jsonl` can count events per hashed patient (without knowing the patient identity). Acceptable for prototype scope.
- **Bounded threat model.** A filesystem-level attacker on one node can rewrite that node's chain; we detect this via local replay + cross-node comparison. Collusion of all three audit companies is out of scope.
