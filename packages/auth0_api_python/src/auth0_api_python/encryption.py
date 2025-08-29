from __future__ import annotations

import base64
import json
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DIGEST = hashes.SHA256()
BYTE_LENGTH = 32
ENCRYPTION_INFO = b'Auth0 Generated Encryption'


def derive_encryption_key(secret: bytes, salt: bytes) -> bytes:
    """
    Derives a key using HKDF with SHA-256.
    """
    hkdf = HKDF(
        algorithm=DIGEST,
        length=BYTE_LENGTH,
        salt=salt,
        info=ENCRYPTION_INFO,
    )
    return base64.urlsafe_b64encode(hkdf.derive(secret))

def encrypt(payload: dict, secret: str) -> str:
    """
    Encrypts a dict.
    """
    payload_str = json.dumps(payload)
    salt = os.urandom(16)
    key = derive_encryption_key(secret.encode(), salt)
    f = Fernet(key)
    encrypted = f.encrypt(payload_str.encode())
    return base64.urlsafe_b64encode(salt + encrypted).decode()

def decrypt(cipher_text: str, secret: str) -> dict:
    """
    Decrypts a string and returns a dict.
    """
    data = base64.urlsafe_b64decode(cipher_text.encode())
    salt, encrypted = data[:16], data[16:]
    key = derive_encryption_key(secret.encode(), salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return json.loads(decrypted.decode())
