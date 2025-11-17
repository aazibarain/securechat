"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
#raise NotImplementedError("students: implement cert issuance")

#!/usr/bin/env python3
"""
Generate key + CSR for an entity and sign with the CA.
Usage:
  python scripts/gen_cert.py --name server --cn "server.local" --san "DNS:server.local,IP:127.0.0.1" --days 825
Outputs:
  certs/server.key
  certs/server.pem
"""
import argparse
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS = Path("certs")
CERTS.mkdir(parents=True, exist_ok=True)


def parse_san(san_str):
    # Example san_str: "DNS:server.local,IP:127.0.0.1"
    parts = [p.strip() for p in san_str.split(",")] if san_str else []
    sans = []
    for p in parts:
        if p.upper().startswith("DNS:"):
            sans.append(x509.DNSName(p[4:]))
        elif p.upper().startswith("IP:"):
            sans.append(x509.IPAddress(ip_address(p[3:])))
        else:
            raise ValueError("SAN entries must start with DNS: or IP:")
    return sans


def generate_cert(name: str, cn: str, san: str, days: int, key_size: int = 3072):
    # Load CA key and cert
    ca_key_path = CERTS / "ca.key"
    ca_cert_path = CERTS / "ca.pem"
    if not ca_key_path.exists() or not ca_cert_path.exists():
        print("CA files not found. Run scripts/gen_ca.py first.", file=sys.stderr)
        sys.exit(1)

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # generate private key for entity
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # Subject
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.utcnow()
    # build CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    sans = parse_san(san) if san else []
    if sans:
        csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    csr = csr_builder.sign(key, hashes.SHA256())

    # Certificate builder
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    )

    if sans:
        cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Write key and cert
    key_path = CERTS / f"{name}.key"
    cert_path = CERTS / f"{name}.pem"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    key_path.chmod(0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Wrote key: {key_path}")
    print(f"Wrote cert: {cert_path}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True, help="short name for files (server, client)")
    p.add_argument("--cn", required=True, help="Common Name for subject")
    p.add_argument("--san", required=False, help='Comma separated SANs e.g. "DNS:server.local,IP:127.0.0.1"')
    p.add_argument("--days", type=int, default=825, help="validity in days")
    p.add_argument("--key-size", type=int, default=3072, help="RSA key size")
    args = p.parse_args()
    generate_cert(args.name, args.cn, args.san, args.days, args.key_size)


if __name__ == "__main__":
    main()
