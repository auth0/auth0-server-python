
import httpx

from auth0_server_python.auth_types import (
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectParams,
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
)

from auth0_server_python.error import (
    ApiError,
)

class MyAccountClient:
    def __init__(self, domain: str):
        self._domain = domain
        self._base_url = f"https://{domain}/me/v1/"

    async def connect_account(
        self,
        access_token: str,
        request: ConnectAccountRequest
    ) -> ConnectAccountResponse:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=f"{self._base_url}connected-accounts/connect",
                    data=request.model_dump_json(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise ApiError(
                        error_data.get("error", "connect_account_error"),
                        error_data.get(
                            "error_description", "Connected Accounts connect request failed")
                    )

                data = response.json()

                return ConnectAccountResponse(
                    auth_session=data["auth_session"],
                    connect_uri=data["connect_uri"],
                    connect_params=ConnectParams(
                        ticket=data["connect_params"]["ticket"]
                    ),
                    expires_in=data["expires_in"]
                )

        except Exception as e:
            if isinstance(e, ApiError):
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
                    url=f"{self._base_url}connected-accounts/complete",
                    data=request.model_dump_json(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise ApiError(
                        error_data.get("error", "connect_account_error"),
                        error_data.get(
                            "error_description", "Connected Accounts complete request failed")
                    )

                data = response.json()

                return CompleteConnectAccountResponse(
                    id=data["id"],
                    connection=data["connection"],
                    access_type=data["access_type"],
                    scopes=data["scopes"],
                    created_at=data["created_at"]
                )

        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts complete request failed: {str(e) or 'Unknown error'}",
                e
            )

class BearerAuth(httpx.Auth):
    def __init__(self, token: str):
        self.token = token

    def auth_flow(self, request):
        request.headers['Authorization'] = f"Bearer {self.token}"
        yield request