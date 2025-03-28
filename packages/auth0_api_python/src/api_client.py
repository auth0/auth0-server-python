import time
from typing import Optional, List, Dict, Any

from authlib.jose import JsonWebToken, JsonWebKey

from .config import ApiClientOptions
from .errors import MissingRequiredArgumentError, VerifyAccessTokenError
from .utils import fetch_oidc_metadata, fetch_jwks, get_unverified_header

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