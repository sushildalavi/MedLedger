from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk_pem, pk_pem


def load_private(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_public(pem: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)


def sign(sk: Ed25519PrivateKey, message: bytes) -> bytes:
    return sk.sign(message)


def verify(pk: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
