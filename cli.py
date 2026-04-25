"""
MedLedger CLI client.

Subcommands:
    login        get a bearer token for a user
    access       generate an EHR access audit event (doctor/admin only)
    query        retrieve audit records for a single patient
    query-all    retrieve audit records for all patients (audit/admin)
    verify       run cross-node verification

Tokens are persisted per user in `.medledger_token.json` so subsequent
commands don't need to re-login. If a stored token is missing or expired
and `--password` is provided, the CLI re-logs in transparently.
"""

import argparse
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
TOKEN_STORE = ROOT / ".medledger_token.json"
DEFAULT_GATEWAY = "https://127.0.0.1:9000"
DEFAULT_GATEWAY_CERT = ROOT / "certs" / "gateway.crt"


def _gateway_verify(cert_path: str | None) -> str | bool:
    if cert_path:
        return cert_path
    if DEFAULT_GATEWAY_CERT.exists():
        return str(DEFAULT_GATEWAY_CERT)
    return True  # fall through to system trust store; do NOT silently disable


def _load_tokens() -> dict:
    if not TOKEN_STORE.exists():
        return {}
    try:
        return json.loads(TOKEN_STORE.read_text())
    except json.JSONDecodeError:
        return {}


def _save_tokens(store: dict) -> None:
    TOKEN_STORE.write_text(json.dumps(store, indent=2))


def _default_password(user: str) -> str:
    return f"pw_{user}"


def login_cmd(args, gateway: str) -> int:
    password = args.password or _default_password(args.user)
    resp = requests.post(
        f"{gateway}/auth/login",
        json={"user": args.user, "password": password},
        verify=_gateway_verify(args.cert),
    )
    if resp.status_code != 200:
        print(f"login failed: {resp.status_code} {resp.text}", file=sys.stderr)
        return 1
    data = resp.json()
    store = _load_tokens()
    store[args.user] = data["token"]
    _save_tokens(store)
    print(f"logged in as {args.user} ({data['role']})")
    return 0


def _ensure_token(user: str, gateway: str, password: str | None, cert: str | None) -> str:
    store = _load_tokens()
    if user in store:
        return store[user]
    pw = password or _default_password(user)
    resp = requests.post(
        f"{gateway}/auth/login",
        json={"user": user, "password": pw},
        verify=_gateway_verify(cert),
    )
    if resp.status_code != 200:
        raise SystemExit(f"login failed for {user}: {resp.status_code} {resp.text}")
    token = resp.json()["token"]
    store[user] = token
    _save_tokens(store)
    return token


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _retrying_request(method: str, url: str, *, user: str, gateway: str, password: str | None, cert: str | None, **kwargs):
    token = _ensure_token(user, gateway, password, cert)
    headers = kwargs.pop("headers", {})
    headers.update(_auth_headers(token))
    kwargs["verify"] = _gateway_verify(cert)
    resp = requests.request(method, url, headers=headers, **kwargs)
    if resp.status_code == 401:
        store = _load_tokens()
        store.pop(user, None)
        _save_tokens(store)
        token = _ensure_token(user, gateway, password, cert)
        headers["Authorization"] = f"Bearer {token}"
        resp = requests.request(method, url, headers=headers, **kwargs)
    return resp


def access_cmd(args, gateway: str) -> int:
    body = {"patient_id": args.patient, "action": args.action}
    resp = _retrying_request(
        "POST", f"{gateway}/ehr/access",
        user=args.user, gateway=gateway, password=args.password, cert=args.cert,
        json=body,
    )
    print(f"[{resp.status_code}] {json.dumps(resp.json(), indent=2)}")
    return 0 if resp.status_code == 200 else 1


def query_cmd(args, gateway: str) -> int:
    resp = _retrying_request(
        "GET", f"{gateway}/audit/patient/{args.patient}",
        user=args.user, gateway=gateway, password=args.password, cert=args.cert,
    )
    print(f"[{resp.status_code}] {json.dumps(resp.json(), indent=2)}")
    return 0 if resp.status_code == 200 else 1


def query_all_cmd(args, gateway: str) -> int:
    resp = _retrying_request(
        "GET", f"{gateway}/audit/all",
        user=args.user, gateway=gateway, password=args.password, cert=args.cert,
    )
    print(f"[{resp.status_code}] {json.dumps(resp.json(), indent=2)}")
    return 0 if resp.status_code == 200 else 1


def verify_cmd(args, gateway: str) -> int:
    user = args.user or "admin"
    resp = _retrying_request(
        "GET", f"{gateway}/verify",
        user=user, gateway=gateway, password=args.password, cert=args.cert,
    )
    print(f"[{resp.status_code}] {json.dumps(resp.json(), indent=2)}")
    return 0 if resp.status_code == 200 else 1


def main() -> int:
    p = argparse.ArgumentParser(prog="cli")
    p.add_argument("--gateway", default=DEFAULT_GATEWAY)
    p.add_argument(
        "--cert",
        default=None,
        help="Gateway TLS cert (PEM) to verify against. Defaults to certs/gateway.crt.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("login")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password")
    sp.set_defaults(func=login_cmd)

    sp = sub.add_parser("access")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password")
    sp.add_argument("--patient", required=True)
    sp.add_argument("--action", required=True)
    sp.set_defaults(func=access_cmd)

    sp = sub.add_parser("query")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password")
    sp.add_argument("--patient", required=True)
    sp.set_defaults(func=query_cmd)

    sp = sub.add_parser("query-all")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password")
    sp.set_defaults(func=query_all_cmd)

    sp = sub.add_parser("verify")
    sp.add_argument("--user")
    sp.add_argument("--password")
    sp.set_defaults(func=verify_cmd)

    args = p.parse_args()
    return args.func(args, args.gateway)


if __name__ == "__main__":
    raise SystemExit(main())
