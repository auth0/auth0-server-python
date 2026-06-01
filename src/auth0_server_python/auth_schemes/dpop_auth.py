import base64
import hashlib
import time
import uuid

import httpx
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class DPoPAuth(httpx.Auth):
    def __init__(self, token: str, key: "jwk.JWK") -> None:
        public_jwk = key.export_public(as_dict=True)
        if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
            raise ValueError("DPoP key must be an EC P-256 key")
        self._token = token
        self._key = key
        self._public_jwk = public_jwk

    def __repr__(self) -> str:
        return "DPoPAuth(token=[REDACTED], key=[REDACTED])"

    def __str__(self) -> str:
        return "DPoPAuth(token=[REDACTED], key=[REDACTED])"

    def auth_flow(self, request: httpx.Request):
        proof = self._make_proof(request.method, str(request.url))
        request.headers["Authorization"] = f"DPoP {self._token}"
        request.headers["DPoP"] = proof
        yield request

    def _make_proof(self, method: str, url: str) -> str:
        htu = url.split("?")[0].split("#")[0]
        ath = _base64url(hashlib.sha256(self._token.encode("ascii")).digest())

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._public_jwk}
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": htu,
            "iat": int(time.time()),
            "ath": ath,
        }

        token = jwcrypto_jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)
        return token.serialize()
