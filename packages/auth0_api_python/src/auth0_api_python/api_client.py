import time
import hashlib
from typing import Optional, List, Dict, Any, Tuple

from authlib.jose import JsonWebToken, JsonWebKey

from .config import ApiClientOptions
from .errors import MissingRequiredArgumentError, VerifyAccessTokenError, InvalidAuthSchemeError, InvalidDpopProofError
from .utils import fetch_oidc_metadata, fetch_jwks, get_unverified_header, normalize_url_for_htu, sha256_base64url

class ApiClient:
    """
    The main class for discovering OIDC metadata (issuer, jwks_uri) and verifying
    Auth0-issued JWT access tokens in an async environment.
    """

    def __init__(self, options: ApiClientOptions):

        if not options.domain:
            raise MissingRequiredArgumentError("domain")
        if not options.audience:
            raise MissingRequiredArgumentError("audience")

        self.options = options
        self._metadata: Optional[Dict[str, Any]] = None
        self._jwks_data: Optional[Dict[str, Any]] = None

        self._jwt = JsonWebToken(["RS256"])

        self._dpop_algorithms = ["ES256"]
        self._dpop_jwt = JsonWebToken(self._dpop_algorithms)

    
    def _build_www_authenticate(self) -> List[Tuple[str,str]]:
        """
        Build one or two WWW-Authenticate headers:
        - Required mode: single DPoP challenge
        - Allowed mode: Bearer + DPoP challenges
        """
        realm = self.options.realm \
              or f'https://{self.options.domain}'
        algs = " ".join(self._dpop_algorithms)

        # 1) If DPoP *required*, only send a DPoP header
        if self.options.dpop_required:
            return [
                ("WWW-Authenticate", f'DPoP algs="{algs}"')
            ]

        # 2) Otherwise, send Bearer then DPoP
        bearer = f'Bearer realm="{realm}"'
        dpop   = f'DPoP algs="{algs}"'
        return [
            ("WWW-Authenticate", bearer),
            ("WWW-Authenticate", dpop)
        ]

    async def _discover(self) -> Dict[str, Any]:
        """Lazy-load OIDC discovery metadata."""
        if self._metadata is None:
            self._metadata = await fetch_oidc_metadata(
                domain=self.options.domain,
                custom_fetch=self.options.custom_fetch
            )
        return self._metadata

    async def _load_jwks(self) -> Dict[str, Any]:
        """Fetches and caches JWKS data from the OIDC metadata."""
        if self._jwks_data is None:
            metadata = await self._discover()
            jwks_uri = metadata["jwks_uri"]
            self._jwks_data = await fetch_jwks(
                jwks_uri=jwks_uri, 
                custom_fetch=self.options.custom_fetch
            )
        return self._jwks_data

    async def verify_access_token(
        self,
        access_token: str,
        required_claims: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Asynchronously verifies the provided JWT access token.
        
        - Fetches OIDC metadata and JWKS if not already cached.
        - Decodes and validates signature (RS256) with the correct key.
        - Checks standard claims: 'iss', 'aud', 'exp', 'iat'
        - Checks extra required claims if 'required_claims' is provided.

        Returns:
            The decoded token claims if valid.

        Raises:
            MissingRequiredArgumentError: If no token is provided.
            VerifyAccessTokenError: If verification fails (signature, claims mismatch, etc.).
        """
        if not access_token:
            raise MissingRequiredArgumentError("access_token")

        required_claims = required_claims or []

    
        try:
            header = await get_unverified_header(access_token)
            kid = header["kid"]
        except Exception as e:
            raise VerifyAccessTokenError(f"Failed to parse token header: {str(e)}") from e

        jwks_data = await self._load_jwks()
        matching_key_dict = None
        for key_dict in jwks_data["keys"]:
            if key_dict.get("kid") == kid:
                matching_key_dict = key_dict
                break

        if not matching_key_dict:
            raise VerifyAccessTokenError(f"No matching key found for kid: {kid}")

        public_key = JsonWebKey.import_key(matching_key_dict)

        if isinstance(access_token, str) and access_token.startswith("b'"):
            access_token = access_token[2:-1]
        try:
            claims = self._jwt.decode(access_token, public_key)
        except Exception as e:
            raise VerifyAccessTokenError(f"Signature verification failed: {str(e)}") from e

        metadata = await self._discover()
        issuer = metadata["issuer"]


        if claims.get("iss") != issuer:
            raise VerifyAccessTokenError("Issuer mismatch")
        
        expected_aud = self.options.audience
        actual_aud = claims.get("aud")

        if isinstance(actual_aud, list):
            if expected_aud not in actual_aud:
                raise VerifyAccessTokenError("Audience mismatch (not in token's aud array)")
        else:
            if actual_aud != expected_aud:
                raise VerifyAccessTokenError("Audience mismatch (single aud)")

        now = int(time.time())
        if "exp" not in claims or now >= claims["exp"]:
            raise VerifyAccessTokenError("Token is expired")
        if "iat" not in claims:
            raise VerifyAccessTokenError("Missing 'iat' claim in token")

        #Additional required_claims
        for rc in required_claims:
            if rc not in claims:
                raise VerifyAccessTokenError(f"Missing required claim: {rc}")

        return claims
    
    async def verify_dpop_proof(
        self,
        access_token: str,
        proof: str,
        http_method: str,
        http_url: str
    ) -> Dict[str, Any]:
        """
        1. Single well-formed compact JWS
        2. typ="dpop+jwt", alg∈allowed, alg≠none
        3. jwk header present & public only
        4. Signature verifies with jwk
        5. iat within leeway
        6. htm == http_method
        7. htu == http_url (normalized)
        8. ath == SHA256(access_token)
        Raises InvalidDpopProofError on any failure.
        """
        if not proof:
            raise MissingRequiredArgumentError("dpop_proof")
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if not http_method or not http_url:
            raise MissingRequiredArgumentError("http_method/http_url")

        header = await get_unverified_header(proof)
      
        if header.get("typ") != "dpop+jwt":
            raise InvalidDpopProofError("Invalid typ header")
       
        alg = header.get("alg")
        if alg not in self._dpop_algorithms:
            raise InvalidDpopProofError(f"Unsupported alg: {alg}")

    
        jwk_dict = header.get("jwk")
        if not jwk_dict or "d" in jwk_dict:
            raise InvalidDpopProofError("Missing or private jwk in header")

   
        public_key = JsonWebKey.import_key(jwk_dict)
        try:
            claims = self._dpop_jwt.decode(proof, public_key)
        except Exception as e:
            raise InvalidDpopProofError(f"Signature verification failed: {e}")

        now = int(time.time())
        iat = claims.get("iat")

        if not isinstance(iat, int):
            raise InvalidDpopProofError("Missing or invalid iat claim")
        leeway = getattr(self.options, "dpop_iat_leeway", 30)
        if abs(now - iat) > leeway:
            raise InvalidDpopProofError("iat timestamp check failed")

        if claims.get("htm") != http_method:
            raise InvalidDpopProofError("htm claim mismatch")
    
        if normalize_url_for_htu(claims.get("htu","")) != normalize_url_for_htu(http_url):
            raise InvalidDpopProofError("htu claim mismatch")

        if claims.get("ath") != sha256_base64url(access_token):
            raise InvalidDpopProofError("ath claim mismatch")

        return claims
    
    async def verify_request(
        self,
        authorization_header: str,
        dpop_proof: Optional[str],
        http_method: Optional[str],
        http_url: Optional[str]
    ) -> Dict[str, Any]:
        """
        Dispatch based on Authorization scheme:
          • If scheme is 'DPoP', calls verify_dpop_request()
          • Else treats as Bearer and calls verify_access_token()

        Raises:
          MissingRequiredArgumentError if required args are missing
          InvalidDpopSchemeError   if an unsupported scheme is provided
        """

        if not authorization_header:
            raise MissingRequiredArgumentError("authorization_header")
        try:
            scheme, token = authorization_header.split(" ", 1)
        except ValueError:
            raise InvalidAuthSchemeError("Malformed Authorization header (expected '<scheme> <token>')")

        scheme = scheme.strip().lower()

        if scheme == "dpop":
            if not self.options.dpop_enabled:
                raise InvalidAuthSchemeError("DPoP is disabled")
            if not dpop_proof:
                raise MissingRequiredArgumentError("dpop_proof")
            if not http_method or not http_url:
                raise MissingRequiredArgumentError(
                    "http_method and http_url are required for DPoP"
                )
            return await self.verify_dpop_proof(
                access_token=token,
                dpop_proof=dpop_proof,
                http_method=http_method,
                http_url=http_url
            )

        if scheme == "bearer":
            return await self.verify_access_token(token)

        raise InvalidAuthSchemeError(f"Unsupported auth scheme: {scheme}")