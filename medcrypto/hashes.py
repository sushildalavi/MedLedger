import hashlib
import hmac as _hmac


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return _hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_compare(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)
