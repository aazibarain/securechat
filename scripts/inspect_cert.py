#!/usr/bin/env python3
"""
Print readable info about a cert file.
Usage: python scripts/inspect_cert.py certs/server.pem
"""
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def inspect(path):
    data = Path(path).read_bytes()
    cert = x509.load_pem_x509_certificate(data)
    print("Subject:", cert.subject.rfc4514_string())
    print("Issuer:", cert.issuer.rfc4514_string())
    print("Serial:", cert.serial_number)
    print("Not before:", cert.not_valid_before)
    print("Not after :", cert.not_valid_after)
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        print("SubjectKeyIdentifier:", ski.value.digest.hex())
    except Exception:
        pass
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        print("AuthorityKeyIdentifier:", aki.value.key_identifier.hex() if aki.value.key_identifier else None)
    except Exception:
        pass
    print("Extensions:")
    for ext in cert.extensions:
        print(" -", ext.oid._name)
    print()
    # print PEM
    print(cert.public_bytes(serialization.Encoding.PEM).decode())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: inspect_cert.py path/to/cert.pem")
        sys.exit(1)
    inspect(sys.argv[1])
