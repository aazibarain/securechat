"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
#raise NotImplementedError("students: implement CA generation")

#!/usr/bin/env python3
"""
Generate a self-signed Root CA (RSA 3072) and write PEM files:
  certs/ca.key (PEM, private)
  certs/ca.pem (PEM, certificate)
Usage:
  python scripts/gen_ca.py --cn "My SecureChat Root CA" --days 3650
"""
import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = Path("certs")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_ca(common_name: str, days_valid: int = 3650, key_size: int = 3072):
    # generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        ]
    )

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        # CA: true
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    key_path = OUT_DIR / "ca.key"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    key_path.chmod(0o600)

    # Write certificate
    cert_path = OUT_DIR / "ca.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated CA key: {key_path}")
    print(f"Generated CA cert: {cert_path}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cn", required=False, default="SecureChat Root CA", help="CA Common Name")
    p.add_argument("--days", type=int, default=3650, help="Validity in days")
    p.add_argument("--key-size", type=int, default=3072, help="RSA key size")
    args = p.parse_args()
    generate_ca(args.cn, args.days, args.key_size)


if __name__ == "__main__":
    main()
