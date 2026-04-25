"""
Self-signed certificate generation for the prototype.

Each service (gateway and each audit node) gets its own RSA-2048 keypair
and a self-signed cert valid for one year. The gateway pins each node's
cert by loading them as a CA bundle for `requests.verify=`. The CLI
pins the gateway cert the same way. There is no `verify=False` anywhere.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _san_for(host: str) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = []
    try:
        ip = ipaddress.ip_address(host)
        names.append(x509.IPAddress(ip))
    except ValueError:
        names.append(x509.DNSName(host))
    if host != "localhost":
        names.append(x509.DNSName("localhost"))
    try:
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    except ValueError:
        pass
    return x509.SubjectAlternativeName(names)


def generate_self_signed(common_name: str, host: str, out_cert: Path, out_key: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    out_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MedLedger Prototype"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(_san_for(host), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    out_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
