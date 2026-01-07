
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
    def __init__(self, domain: str):
        self._domain = domain

    @property
    def audience(self):
        return f"https://{self._domain}/me/"

    async def connect_account(
        self,
        access_token: str,
        request: ConnectAccountRequest
    ) -> ConnectAccountResponse:
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
