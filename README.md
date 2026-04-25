# MedLedger

Secure decentralized audit logging for EHR access. Coursework for CSCI-531 Spring 2026. Not licensed for redistribution.

Option 2 — Extended Prototype. Working alone.

## What this is

A prototype audit-logging system for electronic health records that satisfies five goals: privacy, identification & authorization, queries, immutability, decentralization. Audit records are encrypted, hash-chained across three independent audit-company nodes, and signed per node. A single tampered node is detected by cross-node majority comparison.

## Layout

```
gateway/      Flask service: auth, RBAC, replication, queries, verify
node/         Flask service: per-company audit node (3 instances)
medcrypto/    AES-GCM, HKDF, HMAC, PBKDF2, Ed25519, tokens, canonical JSON
cli.py        client: login, access, query, query-all, verify
attacker.py   internal-attacker simulation: 3 tamper modes
seed.py       deterministic setup of users, keys, secrets, genesis blocks
scripts/      run_local.sh, demo.sh, reset.sh, tamper_demo.sh
data/         per-node chain.jsonl files (gitignored)
keys/         per-node Ed25519 keypairs (gitignored)
report/       written report + screenshots
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py
```

## Run locally

```bash
./scripts/run_local.sh
```

This starts gateway on :9000 and three audit nodes on :8001, :8002, :8003.

## End-to-end demo

```bash
./scripts/demo.sh
```

## Tamper detection demo

```bash
./scripts/tamper_demo.sh
```

## External packages

| Package | Used for |
|---|---|
| Flask | gateway and audit node HTTP servers |
| cryptography | AES-256-GCM, Ed25519, HKDF |
| requests | gateway → node HTTP calls |

Everything else uses the Python standard library (`hmac`, `hashlib`, `secrets`, `json`, `base64`, `time`, `argparse`, `os`, `pathlib`, `threading`, `uuid`, `dataclasses`, `ssl`).

## Roles

| Role | Permissions |
|---|---|
| patient | Query only their own audit logs |
| doctor | Generate EHR access events |
| audit | Query all audit logs |
| admin | Generate events, query all, run system verify |

## Seeded users

`patient_01` … `patient_10`, `doctor_01`–`doctor_03`, `audit_company_A`/`B`/`C`, `admin`. Default password for every seeded user: `pw_<username>` (see `seed.py`).
