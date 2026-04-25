import base64
import hmac as _hmac
import secrets
import time

from .canonical import canonical_json
from .hashes import hmac_sha256, hmac_compare

DEFAULT_TTL_SECONDS = 3600


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(secret: bytes, user: str, role: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    payload = {
        "user": user,
        "role": role,
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    body = canonical_json(payload)
    sig = hmac_sha256(secret, body)
    return f"{_b64u(body)}.{_b64u(sig)}"


def verify_token(secret: bytes, token: str) -> dict | None:
    try:
        body_b64, sig_b64 = token.split(".")
        body = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
    except (ValueError, base64.binascii.Error):
        return None
    expected = hmac_sha256(secret, body)
    if not hmac_compare(sig, expected):
        return None
    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
