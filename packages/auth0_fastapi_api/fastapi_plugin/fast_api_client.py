from typing import Optional, List, Union, Dict
from fastapi import Request, HTTPException
from starlette.responses import Response

from .utils import get_bearer_token, validate_scopes, http_exception

from src.api_client import ApiClient, ApiClientOptions, VerifyAccessTokenError


class Auth0FastAPI:
    """
    A class that configures and exposes a method to protect routes in FastAPI,
    mirroring the concept from TypeScript's Fastify plugin.
    """

    def __init__(self, domain: str, audience: str, custom_fetch=None):
        """
        domain: Your Auth0 domain (like 'my-tenant.us.auth0.com')
        audience: API identifier from the Auth0 Dashboard
        custom_fetch: optional HTTP fetch override for the underlying SDK
        """
        if not domain:
            raise ValueError("domain is required.")
        if not audience:
            raise ValueError("audience is required.")

        self.api_client = ApiClient(
            ApiClientOptions(domain=domain, audience=audience, custom_fetch=custom_fetch)
        )

    def require_auth(
        self,
        scopes: Optional[Union[str, List[str]]] = None
    ):
        """
        Returns an async FastAPI dependency that:
         1) Extracts a 'Bearer' token from the Authorization header
         2) Verifies it with auth0-api-python
         3) If 'scopes' is provided, checks for them in the token's 'scope' claim
         4) Raises HTTPException on error
         5) On success, returns the decoded claims
        """
        async def _dependency(request: Request) -> Dict:
            token = get_bearer_token(request)
            if not token:
                # No Authorization provided
                raise http_exception(
                    400,
                    "invalid_request",
                    "No Authorization provided"
                )
            try:
                claims = await self.api_client.verify_access_token(access_token=token)
            except VerifyAccessTokenError as e:
                raise http_exception(
                    status_code=401,
                    error="invalid_token",
                    error_desc=str(e)
                )

            # If scopes needed, validate
            if scopes:
                required_scopes = [scopes] if isinstance(scopes, str) else scopes
                if not validate_scopes(claims, required_scopes):
                    raise http_exception(
                        status_code=403,
                        error="insufficient_scope",
                        error_desc="Insufficient scopes"
                    )

            # Return the claims as the "user" info
            return claims

        return _dependency
