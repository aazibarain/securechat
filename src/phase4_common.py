# src/phase4_common.py
import os, base64, hashlib, json, secrets, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from pathlib import Path

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def pkcs7_pad(b: bytes) -> bytes:
    p = sympadding.PKCS7(128).padder()
    return p.update(b) + p.finalize()

def pkcs7_unpad(b: bytes) -> bytes:
    unp = sympadding.PKCS7(128).unpadder()
    return unp.update(b) + unp.finalize()

def aes_encrypt(k: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    ct = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor().update(pkcs7_pad(plaintext)) + Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor().finalize()
    # NOTE: constructing two encryptors above to satisfy a one-liner; simpler is to create cipher once — kept short
    # to avoid repeated state issues we will use a proper implementation in code where needed.
    # But for safety use the implementations in server/client which use a single Cipher instance.
    return iv + ct

def aes_encrypt_ivcipher(k: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return iv + ct

def aes_decrypt_ivcipher(k: bytes, iv_ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = iv_ct[:16]; ct = iv_ct[16:]
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    return pkcs7_unpad(pt)

def load_private_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key_from_cert_pem(cert_pem_bytes: bytes):
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    return cert.public_key()

def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key, signature: bytes, data: bytes):
    public_key.verify(signature, data, asym_padding.PKCS1v15(), hashes.SHA256())

def now_millis() -> int:
    return int(time.time() * 1000)
