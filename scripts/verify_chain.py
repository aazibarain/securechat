#!/usr/bin/env python3
"""
Verify that certs/<name>.pem is signed by certs/ca.pem
Usage:
  python scripts/verify_chain.py certs/server.pem certs/ca.pem
Exits 0 if OK, non-zero if verification fails.
"""
import sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def verify(cert_path, ca_path):
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    ca = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
    pub = ca.public_key()
    try:
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("Verification OK: certificate is signed by the CA.")
        return 0
    except Exception as e:
        print("Verification failed:", e)
        return 2

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: verify_chain.py cert.pem ca.pem")
        sys.exit(1)
    sys.exit(verify(sys.argv[1], sys.argv[2]))
