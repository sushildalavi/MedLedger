from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_patient_key(master_secret: bytes, patient_id: str) -> bytes:
    info = b"medledger:patient:" + patient_id.encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(master_secret)
