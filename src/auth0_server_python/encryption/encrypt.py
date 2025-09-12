from __future__ import annotations

import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jwcrypto import jwe, jwk
from jwcrypto.common import base64url_encode

# Constants equivalent to the TypeScript version
ENC = 'A256CBC-HS512'
ALG = 'dir'
DIGEST = hashes.SHA256()
BYTE_LENGTH = 64
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
    return hkdf.derive(secret)

def encrypt(payload: dict, secret: str, salt: str) -> str:
    """
    Encrypts the given payload into a JWE using the direct algorithm and A256CBC-HS512 encryption.
    """
    # Convert secret and salt to bytes
    secret_bytes = secret.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Derive the encryption key
    encryption_secret = derive_encryption_key(secret_bytes, salt_bytes)

    # Create a symmetric key for JWE. jwcrypto expects the key as a base64url-encoded string.
    key = jwk.JWK(k=base64url_encode(encryption_secret), kty="oct")

    payload_json = json.dumps(payload)

    # Create a JWE object with the specified header
    jwetoken = jwe.JWE(
        payload_json,
        protected={'alg': ALG, 'enc': ENC}
    )

    jwetoken.add_recipient(key)

    # Return the compact serialization of the token
    return jwetoken.serialize(compact=True)

def decrypt(token: str, secret: str, salt: str) -> dict:
    """
    Decrypts the JWE token back to the original payload.
    """
    secret_bytes = secret.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    encryption_secret = derive_encryption_key(secret_bytes, salt_bytes)
    key = jwk.JWK(k=base64url_encode(encryption_secret), kty="oct")

    jwetoken = jwe.JWE()
    jwetoken.deserialize(token)
    jwetoken.decrypt(key)
    payload_json = jwetoken.payload.decode('utf-8')
    return json.loads(payload_json)
