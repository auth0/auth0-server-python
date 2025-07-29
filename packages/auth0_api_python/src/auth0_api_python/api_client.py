import time
from typing import Any, Optional

from authlib.jose import JsonWebKey, JsonWebToken

from .config import ApiClientOptions
from .errors import (
    BaseAuthError,
    InvalidAuthSchemeError,
    InvalidDpopProofError,
    MissingAuthorizationError,
    MissingRequiredArgumentError,
    VerifyAccessTokenError,
)
from .utils import (
    calculate_jwk_thumbprint,
    fetch_jwks,
    fetch_oidc_metadata,
    get_unverified_header,
    normalize_url_for_htu,
    sha256_base64url,
)


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
        self._metadata: Optional[dict[str, Any]] = None
        self._jwks_data: Optional[dict[str, Any]] = None

        self._jwt = JsonWebToken(["RS256"])

        self._dpop_algorithms = ["ES256"]
        self._dpop_jwt = JsonWebToken(self._dpop_algorithms)


    async def verify_request(
        self,
        headers: dict[str, str],
        http_method: Optional[str] = None,
        http_url: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Dispatch based on Authorization scheme:
          • If scheme is 'DPoP', verifies both access token and DPoP proof
          • If scheme is 'Bearer', verifies only the access token

        Args:
            headers: HTTP headers dict containing:
                - "authorization": The Authorization header value (required)
                - "dpop": The DPoP proof header value (required for DPoP)
            http_method: The HTTP method (required for DPoP)
            http_url: The HTTP URL (required for DPoP)

        Returns:
            The decoded access token claims

        Raises:
            MissingRequiredArgumentError: If required args are missing
            InvalidAuthSchemeError: If an unsupported scheme is provided
            InvalidDpopProofError: If DPoP verification fails
            VerifyAccessTokenError: If access token verification fails
        """
        authorization_header = headers.get("authorization", "")
        dpop_proof = headers.get("dpop")

        if not authorization_header:
            if getattr(self.options, "dpop_required", False):
                raise self._prepare_error(
                        InvalidAuthSchemeError("Expecting Authorization header with DPoP scheme.")
                    )
            else :
                raise self._prepare_error(MissingAuthorizationError())


        parts = authorization_header.split(" ", 1)
        if len(parts) < 2:
            raise self._prepare_error(MissingAuthorizationError())


        try:
            scheme, token = authorization_header.split(" ", 1)
        except ValueError:
            raise self._prepare_error(
                MissingAuthorizationError()
            )


        scheme = scheme.strip().lower()

        if getattr(self.options, "dpop_required", False) and scheme != "dpop":
                if scheme == "bearer":
                    raise self._prepare_error(
                        InvalidAuthSchemeError("Invalid scheme. Expected 'DPoP', but got 'bearer'."),
                        auth_scheme=scheme
                    )
                else:
                    raise self._prepare_error(
                        InvalidAuthSchemeError("Invalid scheme. Expected 'DPoP' scheme."),
                        auth_scheme=scheme
                    )
        if not token.strip():
            raise self._prepare_error(MissingAuthorizationError())


        if scheme == "dpop":
            if not self.options.dpop_enabled:
                raise self._prepare_error(MissingAuthorizationError())

            if not dpop_proof:
                if getattr(self.options, "dpop_required", False):
                    raise self._prepare_error(
                        InvalidAuthSchemeError("Expecting Authorization header with DPoP scheme."),
                        auth_scheme=scheme
                    )
                else:
                    raise self._prepare_error(
                        InvalidDpopProofError("Operation indicated DPoP use but the request has no DPoP HTTP Header"),
                        auth_scheme=scheme
                    )

            if "," in dpop_proof:
                raise self._prepare_error(
                    InvalidDpopProofError("Multiple DPoP proofs are not allowed"),
                    auth_scheme=scheme
                )

            try:
                await get_unverified_header(dpop_proof)
            except Exception:
                raise self._prepare_error(InvalidDpopProofError("Failed to verify DPoP proof"), auth_scheme=scheme)

            if not http_method or not http_url:
                raise self._prepare_error(
                    InvalidDpopProofError("Operation indicated DPoP use but the request has no http_method or http_url"), auth_scheme=scheme
                )

            try:
                access_token_claims = await self.verify_access_token(token)
            except VerifyAccessTokenError as e:
                raise self._prepare_error(e, auth_scheme=scheme)

            cnf_claim = access_token_claims.get("cnf")

            if not cnf_claim:
                raise self._prepare_error(
                    InvalidDpopProofError("Operation indicated DPoP use but the JWT Access Token has no jkt confirmation claim"),
                    auth_scheme=scheme
                )

            if not isinstance(cnf_claim, dict):
                raise self._prepare_error(
                    InvalidDpopProofError("Operation indicated DPoP use but the JWT Access Token has invalid confirmation claim format"),
                    auth_scheme=scheme
                )
            try:
                await self.verify_dpop_proof(
                    access_token=token,
                    proof=dpop_proof,
                    http_method=http_method,
                    http_url=http_url
                )
            except InvalidDpopProofError as e:
                raise self._prepare_error(e, auth_scheme=scheme)

            # DPoP binding verification
            jwk_dict = (await get_unverified_header(dpop_proof))["jwk"]
            actual_jkt = calculate_jwk_thumbprint(jwk_dict)
            expected_jkt = cnf_claim.get("jkt")

            if not expected_jkt:
                raise self._prepare_error(
                    VerifyAccessTokenError("Access token 'cnf' claim missing 'jkt'"),
                    auth_scheme=scheme
                )

            if expected_jkt != actual_jkt:
                raise self._prepare_error(
                    VerifyAccessTokenError("JWT Access Token confirmation mismatch"),
                    auth_scheme=scheme
                )

            return access_token_claims

        if scheme == "bearer":
            if dpop_proof:
                if self.options.dpop_enabled:
                    raise self._prepare_error(
                        InvalidAuthSchemeError(
                            "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"
                        ),
                        auth_scheme=scheme
                    )

            try:
                claims = await self.verify_access_token(token)
                if claims.get("cnf") and claims["cnf"].get("jkt"):
                    if self.options.dpop_enabled:
                        raise self._prepare_error(
                            InvalidAuthSchemeError(
                                "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"
                            ),
                            auth_scheme=scheme
                        )


                return claims
            except VerifyAccessTokenError as e:
                raise self._prepare_error(e, auth_scheme=scheme)

        raise self._prepare_error(MissingAuthorizationError())

    async def verify_access_token(
        self,
        access_token: str,
        required_claims: Optional[list[str]] = None
    ) -> dict[str, Any]:
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

        # Additional required_claims
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
    ) -> dict[str, Any]:
        """
        1. Single well-formed compact JWS
        2. typ="dpop+jwt", alg∈allowed, alg≠none
        3. jwk header present & public only
        4. Signature verifies with jwk
        5. Validates all required claims
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
            raise InvalidDpopProofError("Unexpected JWT 'typ' header parameter value")

        alg = header.get("alg")
        if alg not in self._dpop_algorithms:
            raise InvalidDpopProofError(f"Unsupported alg: {alg}")

        jwk_dict = header.get("jwk")
        if not jwk_dict or not isinstance(jwk_dict, dict):
            raise InvalidDpopProofError("Missing or invalid jwk in header")

        if "d" in jwk_dict:
            raise InvalidDpopProofError("Private key material found in jwk header")

        if jwk_dict.get("kty") != "EC":
            raise InvalidDpopProofError("Only EC keys are supported for DPoP")

        if jwk_dict.get("crv") != "P-256":
            raise InvalidDpopProofError("Only P-256 curve is supported")

        public_key = JsonWebKey.import_key(jwk_dict)
        try:
            claims = self._dpop_jwt.decode(proof, public_key)
        except Exception as e:
            raise InvalidDpopProofError(f"JWT signature verification failed: {e}")

        # Checks all required claims are present
        self._validate_claims_presence(claims, ["iat", "ath", "htm", "htu", "jti"])

        jti = claims["jti"]

        if not isinstance(jti, str):
            raise InvalidDpopProofError("jti claim must be a string")

        if not jti.strip():
            raise InvalidDpopProofError("jti claim must not be empty")


        now = int(time.time())
        iat = claims["iat"]
        offset = getattr(self.options, "dpop_iat_offset", 300)    # default 5 minutes
        leeway = getattr(self.options, "dpop_iat_leeway", 30)     # default 30 seconds

        if not isinstance(iat, int):
            raise InvalidDpopProofError("Invalid iat claim (must be integer)")

        if iat < now - offset or iat > now + leeway:
            raise InvalidDpopProofError("DPoP Proof iat is not recent enough")

        if claims["htm"] != http_method:
            raise InvalidDpopProofError("DPoP Proof htm mismatch")

        if normalize_url_for_htu(claims["htu"]) != normalize_url_for_htu(http_url):
            raise InvalidDpopProofError("DPoP Proof htu mismatch")

        if claims["ath"] != sha256_base64url(access_token):
            raise InvalidDpopProofError("DPoP Proof ath mismatch")

        return claims

    # ===== Private Methods =====

    async def _discover(self) -> dict[str, Any]:
        """Lazy-load OIDC discovery metadata."""
        if self._metadata is None:
            self._metadata = await fetch_oidc_metadata(
                domain=self.options.domain,
                custom_fetch=self.options.custom_fetch
            )
        return self._metadata

    async def _load_jwks(self) -> dict[str, Any]:
        """Fetches and caches JWKS data from the OIDC metadata."""
        if self._jwks_data is None:
            metadata = await self._discover()
            jwks_uri = metadata["jwks_uri"]
            self._jwks_data = await fetch_jwks(
                jwks_uri=jwks_uri,
                custom_fetch=self.options.custom_fetch
            )
        return self._jwks_data

    def _validate_claims_presence(
        self,
        claims: dict[str, Any],
        required_claims: list[str]
    ) -> None:
        """
        Validates that all required claims are present in the claims dict.

        Args:
            claims: The claims dictionary to validate
            required_claims: List of claim names that must be present

        Raises:
            InvalidDpopProofError: If any required claim is missing
        """
        missing_claims = []

        for claim in required_claims:
            if claim not in claims:
                missing_claims.append(claim)

        if missing_claims:
            if len(missing_claims) == 1:
                error_message = f"Missing required claim: {missing_claims[0]}"
            else:
                error_message = f"Missing required claims: {', '.join(missing_claims)}"

            raise InvalidDpopProofError(error_message)

    def _prepare_error(self, error: BaseAuthError, auth_scheme: Optional[str] = None) -> BaseAuthError:
        """
        Prepare an error with WWW-Authenticate headers based on error type and context.

        Args:
            error: The error to prepare
            auth_scheme: The authentication scheme that was used ("bearer" or "dpop")
        """
        error_code = error.get_error_code()
        error_description = error.get_error_description()

        www_auth_headers = self._build_www_authenticate(
            error_code=error_code if error_code != "unauthorized" else None,
            error_description=error_description if error_code != "unauthorized" else None,
            auth_scheme=auth_scheme
        )

        headers = {}
        www_auth_values = []
        for header_name, header_value in www_auth_headers:
            if header_name == "WWW-Authenticate":
                www_auth_values.append(header_value)

        if www_auth_values:
            headers["WWW-Authenticate"] = ", ".join(www_auth_values)

        error._headers = headers

        return error

    def _build_www_authenticate(
        self,
        *,
        error_code: Optional[str] = None,
        error_description: Optional[str] = None,
        auth_scheme: Optional[str] = None
    ) -> list[tuple[str, str]]:
        """
        Returns one or two ('WWW-Authenticate', ...) tuples based on context.
        If dpop_required mode → single DPoP challenge (with optional error params).
        Otherwise → Bearer and/or DPoP challenges based on auth_scheme and error.

        Args:
            error_code: Error code (e.g., "invalid_token", "invalid_request")
            error_description: Error description if any
            auth_scheme: The authentication scheme that was used ("bearer" or "dpop")
        """
        # If DPoP is disabled, only return Bearer challenges
        if not self.options.dpop_enabled:
            if error_code and error_code != "unauthorized":
                bearer_parts = []
                bearer_parts.append(f'error="{error_code}"')
                if error_description:
                    bearer_parts.append(f'error_description="{error_description}"')
                return [("WWW-Authenticate", "Bearer " + ", ".join(bearer_parts))]
            return [("WWW-Authenticate", "Bearer")]

        algs = " ".join(self._dpop_algorithms)
        dpop_required = getattr(self.options, "dpop_required", False)

        # No error details
        if error_code == "unauthorized" or not error_code:
            if dpop_required:
                return [("WWW-Authenticate", f'DPoP algs="{algs}"')]
            return [("WWW-Authenticate", f'Bearer, DPoP algs="{algs}"')]

        if dpop_required:
            # DPoP-required mode: Single DPoP challenge with error
            dpop_parts = []
            if error_code:
                dpop_parts.append(f'error="{error_code}"')
            if error_description:
                dpop_parts.append(f'error_description="{error_description}"')
            dpop_parts.append(f'algs="{algs}"')
            dpop_header = "DPoP " + ", ".join(dpop_parts)
            return [("WWW-Authenticate", dpop_header)]

        # DPoP-allowed mode: For DPoP errors, always include both challenges
        if auth_scheme == "dpop" and error_code:
            bearer_header = "Bearer"
            dpop_parts = []
            if error_code:
                dpop_parts.append(f'error="{error_code}"')
            if error_description:
                dpop_parts.append(f'error_description="{error_description}"')
            dpop_parts.append(f'algs="{algs}"')
            dpop_header = "DPoP " + ", ".join(dpop_parts)
            return [
                ("WWW-Authenticate", bearer_header),
                ("WWW-Authenticate", dpop_header),
            ]

        # If auth_scheme is "bearer", include error on Bearer challenge
        if auth_scheme == "bearer" and error_code:
            bearer_parts = []
            bearer_parts.append(f'error="{error_code}"')
            if error_description:
                bearer_parts.append(f'error_description="{error_description}"')
            bearer_header = "Bearer " + ", ".join(bearer_parts)
            dpop_header = f'DPoP algs="{algs}"'
            return [("WWW-Authenticate", f'{bearer_header}, {dpop_header}')]

        # Default: no error or unknown context
        return [
            ("WWW-Authenticate", "Bearer"),
            ("WWW-Authenticate", f'DPoP algs="{algs}"'),
        ]
