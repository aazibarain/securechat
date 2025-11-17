# src/common_crypto.py
import os
import hashlib
import base64
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def derive_aes128_from_shared_int(shared_int: int) -> bytes:
    """Derive AES-128 key (16 bytes) from shared integer (DH) using SHA256 and truncation."""
    kb = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    return sha256(kb)[:16]

def pkcs7_pad(data: bytes) -> bytes:
    padder = sympadding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt(k: bytes, plaintext: bytes) -> bytes:
    """Return iv + ciphertext"""
    iv = os.urandom(16)
    pt = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(pt) + cipher.encryptor().finalize()
    return iv + ct

def aes_decrypt(k: bytes, iv_ct: bytes) -> bytes:
    iv = iv_ct[:16]
    ct = iv_ct[16:]
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend())
    pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    return pkcs7_unpad(pt)

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))
