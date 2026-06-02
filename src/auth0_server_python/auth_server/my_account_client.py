import json
from typing import TYPE_CHECKING, Optional
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_schemes.dpop_auth import DPoPAuth
from auth0_server_python.auth_types import (
    AuthenticationMethod,
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    EnrollAuthenticationMethodRequest,
    EnrollmentChallengeResponse,
    GetFactorsResponse,
    ListAuthenticationMethodsResponse,
    ListConnectedAccountConnectionsResponse,
    ListConnectedAccountsResponse,
    UpdateAuthenticationMethodRequest,
    VerifyAuthenticationMethodRequest,
)
from auth0_server_python.error import (
    ApiError,
    InvalidArgumentError,
    MissingRequiredArgumentError,
    MyAccountApiError,
)

if TYPE_CHECKING:
    from jwcrypto import jwk


def _make_auth(
    access_token: str,
    dpop_key: Optional["jwk.JWK"] = None,
) -> httpx.Auth:
    if dpop_key is not None:
        return DPoPAuth(access_token, dpop_key)
    return BearerAuth(access_token)


class MyAccountClient:
    """
    Client for interacting with the Auth0 MyAccount API.
    """

    def __init__(self, domain: str, headers: Optional[dict[str, str]] = None):
        """
        Initialize the MyAccount API client.

        Args:
            domain: Auth0 domain (e.g., '<tenant>.<locality>.auth0.com')
            headers: Optional default headers to include on every request
        """
        self._domain = domain
        self._headers = headers or {}

    def _get_http_client(self, **kwargs) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient with default headers injected."""
        headers = {**kwargs.pop("headers", {}), **self._headers}
        return httpx.AsyncClient(headers=headers, **kwargs)

    @property
    def audience(self):
        """
        Get the MyAccount API audience URL.

        Returns:
            The audience URL for the MyAccount API
        """
        return f"https://{self._domain}/me/"

    async def connect_account(
        self,
        access_token: str,
        request: ConnectAccountRequest
    ) -> ConnectAccountResponse:
        """
        Initiate the connected account flow.

        Args:
            access_token: User's access token for authentication
            request: Request containing connection details and configuration

        Returns:
            Response containing the connect URI and authentication session details

        Raises:
            MyAccountApiError: If the API returns an error response
            ApiError: If the request fails due to network or other issues
        """
        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url=f"{self.audience}v1/connected-accounts/connect",
                    json=request.model_dump(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None)
                    )

                data = response.json()

                return ConnectAccountResponse.model_validate(data)

        except Exception as e:
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts connect request failed: {str(e) or 'Unknown error'}",
                e
            )

    async def complete_connect_account(
        self,
        access_token: str,
        request: CompleteConnectAccountRequest
    ) -> CompleteConnectAccountResponse:
        """
        Complete the connected account flow after user authorization.

        Args:
            access_token: User's access token for authentication
            request: Request containing the auth session, connect code, and redirect URI

        Returns:
            Response containing the connected account details including ID, connection, and scopes

        Raises:
            MyAccountApiError: If the API returns an error response
            ApiError: If the request fails due to network or other issues
        """
        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url=f"{self.audience}v1/connected-accounts/complete",
                    json=request.model_dump(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None)
                    )

                data = response.json()

                return CompleteConnectAccountResponse.model_validate(data)

        except Exception as e:
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts complete request failed: {str(e) or 'Unknown error'}",
                e
            )

    async def list_connected_accounts(
        self,
        access_token: str,
        connection: Optional[str] = None,
        from_param: Optional[str] = None,
        take: Optional[int] = None
    ) -> ListConnectedAccountsResponse:
        """
        List connected accounts for the authenticated user.

        Args:
            access_token: User's access token for authentication
            connection: Optional filter to list accounts for a specific connection
            from_param: Optional pagination cursor for fetching next page of results
            take: Optional number of results to return (must be a positive integer)

        Returns:
            Response containing the list of connected accounts and pagination details

        Raises:
            MissingRequiredArgumentError: If access_token is not provided
            InvalidArgumentError: If take parameter is not a positive integer
            MyAccountApiError: If the API returns an error response
            ApiError: If the request fails due to network or other issues
        """
        if access_token is None:
            raise MissingRequiredArgumentError("access_token")

        if take is not None and (not isinstance(take, int) or take < 1):
            raise InvalidArgumentError("take", "The 'take' parameter must be a positive integer.")

        try:
            async with self._get_http_client() as client:
                params = {}
                if connection:
                    params["connection"] = connection
                if from_param:
                    params["from"] = from_param
                if take:
                    params["take"] = take

                response = await client.get(
                    url=f"{self.audience}v1/connected-accounts/accounts",
                    params=params,
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None)
                    )

                data = response.json()

                return ListConnectedAccountsResponse.model_validate(data)

        except Exception as e:
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts list request failed: {str(e) or 'Unknown error'}",
                e
            )


    async def delete_connected_account(
        self,
        access_token: str,
        connected_account_id: str
    ) -> None:
        """
        Delete a connected account for the authenticated user.

        Args:
            access_token: User's access token for authentication
            connected_account_id: ID of the connected account to delete

        Returns:
            None

        Raises:
            MissingRequiredArgumentError: If access_token or connected_account_id is not provided
            MyAccountApiError: If the API returns an error response
            ApiError: If the request fails due to network or other issues
        """

        if access_token is None:
            raise MissingRequiredArgumentError("access_token")

        if connected_account_id is None:
            raise MissingRequiredArgumentError("connected_account_id")

        try:
            async with self._get_http_client() as client:
                response = await client.delete(
                    url=f"{self.audience}v1/connected-accounts/accounts/{connected_account_id}",
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 204:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None)
                    )

        except Exception as e:
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts delete request failed: {str(e) or 'Unknown error'}",
                e
            )

    async def list_connected_account_connections(
        self,
        access_token: str,
        from_param: Optional[str] = None,
        take: Optional[int] = None
    ) -> ListConnectedAccountConnectionsResponse:
        """
        List available connections that support connected accounts.

        Args:
            access_token: User's access token for authentication
            from_param: Optional pagination cursor for fetching next page of results
            take: Optional number of results to return (must be a positive integer)

        Returns:
            Response containing the list of available connections and pagination details

        Raises:
            MissingRequiredArgumentError: If access_token is not provided
            InvalidArgumentError: If take parameter is not a positive integer
            MyAccountApiError: If the API returns an error response
            ApiError: If the request fails due to network or other issues
        """
        if access_token is None:
            raise MissingRequiredArgumentError("access_token")

        if take is not None and (not isinstance(take, int) or take < 1):
            raise InvalidArgumentError("take", "The 'take' parameter must be a positive integer.")

        try:
            async with self._get_http_client() as client:
                params = {}
                if from_param:
                    params["from"] = from_param
                if take:
                    params["take"] = take

                response = await client.get(
                    url=f"{self.audience}v1/connected-accounts/connections",
                    params=params,
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None)
                    )

                data = response.json()

                return ListConnectedAccountConnectionsResponse.model_validate(data)

        except Exception as e:
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts list connections request failed: {str(e) or 'Unknown error'}",
                e
            )

    # ============================================================================
    # AUTHENTICATION METHODS & FACTORS (Passkey / MyAccount API)
    # ============================================================================

    async def get_factors(
        self,
        access_token: str,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> GetFactorsResponse:
        """
        Retrieve the list of factors available for enrollment.

        Args:
            access_token: User's access token (scope: read:me:factors).
            dpop_key: Optional EC P-256 key for DPoP-bound token presentation.

        Returns:
            GetFactorsResponse containing the available factors.

        Raises:
            MissingRequiredArgumentError: If access_token is not provided.
            MyAccountApiError: If the API returns an error response.
            ApiError: If the request fails due to network or other issues.
        """
        if not access_token:
            raise MissingRequiredArgumentError("access_token")

        try:
            async with self._get_http_client() as client:
                response = await client.get(
                    url=f"{self.audience}v1/factors",
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "get_factors_error",
                            f"Get factors failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                return GetFactorsResponse.model_validate(response.json())

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "get_factors_error",
                "Get factors request failed",
                e,
            )

    async def list_authentication_methods(
        self,
        access_token: str,
        type_filter: Optional[str] = None,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> ListAuthenticationMethodsResponse:
        if not access_token:
            raise MissingRequiredArgumentError("access_token")

        try:
            async with self._get_http_client() as client:
                params = {}
                if type_filter:
                    params["type"] = type_filter

                response = await client.get(
                    url=f"{self.audience}v1/authentication-methods",
                    params=params,
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "list_authentication_methods_error",
                            f"List authentication methods failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                return ListAuthenticationMethodsResponse.model_validate(response.json())

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "list_authentication_methods_error",
                "List authentication methods request failed",
                e,
            )

    async def get_authentication_method(
        self,
        access_token: str,
        authentication_method_id: str,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> AuthenticationMethod:
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if not authentication_method_id:
            raise MissingRequiredArgumentError("authentication_method_id")

        try:
            async with self._get_http_client() as client:
                response = await client.get(
                    url=f"{self.audience}v1/authentication-methods/{quote(authentication_method_id, safe='')}",
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "get_authentication_method_error",
                            f"Get authentication method failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                return AuthenticationMethod.model_validate(response.json())

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "get_authentication_method_error",
                "Get authentication method request failed",
                e,
            )

    async def delete_authentication_method(
        self,
        access_token: str,
        authentication_method_id: str,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> None:
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if not authentication_method_id:
            raise MissingRequiredArgumentError("authentication_method_id")

        try:
            async with self._get_http_client() as client:
                response = await client.delete(
                    url=f"{self.audience}v1/authentication-methods/{quote(authentication_method_id, safe='')}",
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 204:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "delete_authentication_method_error",
                            f"Delete authentication method failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "delete_authentication_method_error",
                "Delete authentication method request failed",
                e,
            )

    async def update_authentication_method(
        self,
        access_token: str,
        authentication_method_id: str,
        request: UpdateAuthenticationMethodRequest,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> AuthenticationMethod:
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if not authentication_method_id:
            raise MissingRequiredArgumentError("authentication_method_id")
        if request is None:
            raise MissingRequiredArgumentError("request")

        try:
            async with self._get_http_client() as client:
                response = await client.patch(
                    url=f"{self.audience}v1/authentication-methods/{quote(authentication_method_id, safe='')}",
                    json=request.model_dump(exclude_none=True),
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "update_authentication_method_error",
                            f"Update authentication method failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                return AuthenticationMethod.model_validate(response.json())

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "update_authentication_method_error",
                "Update authentication method request failed",
                e,
            )

    async def enroll_authentication_method(
        self,
        access_token: str,
        request: EnrollAuthenticationMethodRequest,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> EnrollmentChallengeResponse:
        """Step 1 of 2: Start enrollment (POST /me/v1/authentication-methods).

        For passkey enrollment, pass the returned authn_params_public_key to
        navigator.credentials.create(), then call verify_authentication_method()
        with the auth_session and credential result.

        Requires scope: create:me:authentication_methods
        """
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if request is None:
            raise MissingRequiredArgumentError("request")

        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url=f"{self.audience}v1/authentication-methods",
                    json=request.model_dump(exclude_none=True),
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 201:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "enroll_authentication_method_error",
                            f"Enroll authentication method failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                location = response.headers.get("location")
                if not location:
                    raise ApiError(
                        "enroll_authentication_method_error",
                        "Enrollment succeeded (201) but Location header is missing",
                    )

                path = location.split("?")[0].split("#")[0].rstrip("/")
                segments = path.split("/")
                authentication_method_id = segments[-1] if len(segments) > 1 else ""
                if not authentication_method_id or authentication_method_id in (
                    "authentication-methods",
                    "v1",
                    "me",
                ):
                    raise ApiError(
                        "enroll_authentication_method_error",
                        "Enrollment succeeded (201) but could not extract ID from Location header",
                    )

                try:
                    data = response.json()
                except (json.JSONDecodeError, ValueError):
                    raise ApiError(
                        "enroll_authentication_method_error",
                        "Enrollment succeeded (201) but response body is not valid JSON",
                    )

                auth_session = data.get("auth_session")
                if not auth_session:
                    raise ApiError(
                        "enroll_authentication_method_error",
                        "Enrollment succeeded (201) but auth_session is missing from response",
                    )

                return EnrollmentChallengeResponse.model_validate(
                    {
                        "authentication_method_id": authentication_method_id,
                        "auth_session": auth_session,
                        "authn_params_public_key": data.get("authn_params_public_key"),
                    }
                )

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "enroll_authentication_method_error",
                "Enroll authentication method request failed",
                e,
            )

    async def verify_authentication_method(
        self,
        access_token: str,
        authentication_method_id: str,
        request: VerifyAuthenticationMethodRequest,
        dpop_key: Optional["jwk.JWK"] = None,
    ) -> AuthenticationMethod:
        """Step 2 of 2: Verify enrollment (POST /me/v1/authentication-methods/{id}/verify).

        Requires scope: create:me:authentication_methods
        """
        if not access_token:
            raise MissingRequiredArgumentError("access_token")
        if not authentication_method_id:
            raise MissingRequiredArgumentError("authentication_method_id")
        if request is None:
            raise MissingRequiredArgumentError("request")

        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url=f"{self.audience}v1/authentication-methods/{quote(authentication_method_id, safe='')}/verify",
                    json=request.model_dump(by_alias=True, exclude_none=True),
                    auth=_make_auth(access_token, dpop_key),
                )

                if response.status_code != 200:
                    try:
                        error_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ApiError(
                            "verify_authentication_method_error",
                            f"Verify authentication method failed with status {response.status_code}",
                        )
                    raise MyAccountApiError(
                        title=error_data.get("title", None),
                        type=error_data.get("type", None),
                        detail=error_data.get("detail", None),
                        status=error_data.get("status", None),
                        validation_errors=error_data.get("validation_errors", None),
                    )

                return AuthenticationMethod.model_validate(response.json())

        except Exception as e:
            if isinstance(e, (MyAccountApiError, ApiError, ValidationError)):
                raise
            raise ApiError(
                "verify_authentication_method_error",
                "Verify authentication method request failed",
                e,
            )
