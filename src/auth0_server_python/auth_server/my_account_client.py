
from typing import Optional

import httpx
from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ListConnectedAccountConnectionsResponse,
    ListConnectedAccountsResponse,
)
from auth0_server_python.error import (
    ApiError,
    InvalidArgumentError,
    MissingRequiredArgumentError,
    MyAccountApiError,
)


class MyAccountClient:
    """
    Client for interacting with the Auth0 MyAccount API.
    """

    def __init__(self, domain: str):
        """
        Initialize the MyAccount API client.

        Args:
            domain: Auth0 domain (e.g., '<tenant>.<locality>.auth0.com')
        """
        self._domain = domain

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
            async with httpx.AsyncClient() as client:
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
            async with httpx.AsyncClient() as client:
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
            async with httpx.AsyncClient() as client:
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
            async with httpx.AsyncClient() as client:
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
            async with httpx.AsyncClient() as client:
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
