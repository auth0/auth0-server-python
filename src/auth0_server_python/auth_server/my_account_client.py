
import httpx
from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectParams,
)
from auth0_server_python.error import (
    ApiError,
    MyAccountApiError,
)


class MyAccountClient:
    def __init__(self, domain: str):
        self._domain = domain

    @property
    def audienceIdentifier(self):
        return f"https://{self._domain}/me/"

    async def connect_account(
        self,
        access_token: str,
        request: ConnectAccountRequest
    ) -> ConnectAccountResponse:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=f"{self.audienceIdentifier}v1/connected-accounts/connect",
                    json=request.model_dump(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title"),
                        type=error_data.get("type"),
                        detail=error_data.get("detail"),
                        status=error_data.get("status"),
                        validation_errors=error_data.get("validation_errors", None)
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
                    url=f"{self.audienceIdentifier}v1/connected-accounts/complete",
                    json=request.model_dump(exclude_none=True),
                    auth=BearerAuth(access_token)
                )

                if response.status_code != 201:
                    error_data = response.json()
                    raise MyAccountApiError(
                        title=error_data.get("title"),
                        type=error_data.get("type"),
                        detail=error_data.get("detail"),
                        status=error_data.get("status"),
                        validation_errors=error_data.get("validation_errors")
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
            if isinstance(e, MyAccountApiError):
                raise
            raise ApiError(
                "connect_account_error",
                f"Connected Accounts complete request failed: {str(e) or 'Unknown error'}",
                e
            )
