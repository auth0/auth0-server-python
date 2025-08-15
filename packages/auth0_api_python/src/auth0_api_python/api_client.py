import time
import httpx
from typing import Optional, List, Dict, Any

from authlib.jose import JsonWebToken, JsonWebKey

from .config import ApiClientOptions
from .errors import MissingRequiredArgumentError, VerifyAccessTokenError, GetTokenForConnectionError, ApiError
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


    async def get_token_for_connection(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieves a token for a connection.

        Args:
            options: Options for retrieving an access token for a connection.
                Must include 'connection' and 'access_token' keys.
                May optionally include 'login_hint'.

        Raises:
            GetTokenForConnectionError: If there was an issue requesting the access token.
            ApiError: If the token exchange endpoint returns an error.

        Returns:
            Dictionary containing the token response with accessToken, expiresAt, and scope.
        """
        # Constants
        SUBJECT_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
        REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "http://auth0.com/oauth/token-type/federated-connection-access-token"
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"

        connection = options.get("connection")
        access_token = options.get("access_token")

        if not connection:
            raise MissingRequiredArgumentError("connection")

        if not access_token:
            raise MissingRequiredArgumentError("access_token")

        associated_client = self.options.associated_client
        if not associated_client:
            raise GetTokenForConnectionError("You must configure the SDK with an associated_client to use get_token_for_connection.")

        metadata = await self._discover()

        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise GetTokenForConnectionError("Token endpoint missing in OIDC metadata")

        # Prepare parameters
        params = {
            "connection": connection,
            "requested_token_type": REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
            "grant_type": GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
            "client_id": associated_client["client_id"],
            "subject_token": access_token,
            "subject_token_type": SUBJECT_TYPE_ACCESS_TOKEN,
        }

        # Add login_hint if provided
        if "login_hint" in associated_client and associated_client["login_hint"]:
            params["login_hint"] = options["login_hint"]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=params,
                auth=(associated_client["client_id"], associated_client["client_secret"])
            )

            if response.status_code != 200:
                error_data = response.json() if response.headers.get(
                    "content-type") == "application/json" else {}
                raise ApiError(
                    error_data.get("error", "connection_token_error"),
                    error_data.get(
                        "error_description", f"Failed to get token for connection: {response.status_code}")
                )

            token_endpoint_response = response.json()

            return {
                "access_token": token_endpoint_response.get("access_token"),
                "expires_at": int(time.time()) + int(token_endpoint_response.get("expires_in", 3600)),
                "scope": token_endpoint_response.get("scope", "")
            }
