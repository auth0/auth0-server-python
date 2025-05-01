
from fastapi import Request, Response, HTTPException, status

from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore
from auth0_fastapi.stores.stateless_state_store import StatelessStateStore

from auth0_fastapi.config import Auth0Config

# Imported from auth0-server-python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    StartInteractiveLoginOptions,
    LogoutOptions
)


class AuthClient:
    """
    FastAPI SDK client that wraps auth0-server-python functionality.
    It configures the underlying client with the proper state and transaction stores,
    and exposes helper methods for starting login, completing the login callback,
    logging out, and handling backchannel logout.
    """

    def __init__(self, config: Auth0Config, state_store=None, transaction_store=None):
        self.config = config
        # Build the redirect URI based on the provided app_base_url
        redirect_uri = f"{str(config.app_base_url).rstrip('/')}/auth/callback"

        # Use provided state_store or default to cookie implementation
        if state_store is None:
            state_store = StatelessStateStore(
                config.secret, cookie_name="_a0_session", expiration=config.session_expiration)
        # Use provided transaction_store or default to an cookie implementation
        if transaction_store is None:
            transaction_store = CookieTransactionStore(
                config.secret, cookie_name="_a0_tx")

        self.client = ServerClient(
            domain=config.domain,
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri,
            secret=config.secret,
            transaction_store=transaction_store,
            state_store=state_store,
            pushed_authorization_requests=config.pushed_authorization_requests,
            authorization_params={
                "audience": config.audience,
                "redirect_uri": redirect_uri,
                **(config.authorization_params or {})
            },
        )

    async def start_login(self, app_state: dict = None, authorization_params: dict = None, store_options: dict = None) -> str:
        """
        Initiates the interactive login process.
        Optionally, an app_state dictionary can be passed to persist additional state.
        Returns the authorization URL to redirect the user.
        """
        pushed_authorization_requests = self.config.pushed_authorization_requests
        options = StartInteractiveLoginOptions(
            pushed_authorization_requests=pushed_authorization_requests,
            app_state=app_state,
            authorization_params=authorization_params if not pushed_authorization_requests else None
        )
        return await self.client.start_interactive_login(options, store_options=store_options)

    async def complete_login(self, callback_url: str, store_options: dict = None) -> dict:
        """
        Completes the interactive login process using the callback URL.
        Returns a dictionary with the session state data.
        """
        return await self.client.complete_interactive_login(callback_url, store_options=store_options)

    async def logout(self, return_to: str = None, store_options: dict = None) -> str:
        """
        Initiates logout by clearing the session and generating a logout URL.
        Optionally accepts a return_to URL for redirection after logout.
        """
        options = LogoutOptions(return_to=return_to)
        return await self.client.logout(options, store_options=store_options)

    async def handle_backchannel_logout(self, logout_token: str) -> None:
        """
        Processes a backchannel logout using the provided logout token.
        """
        return await self.client.handle_backchannel_logout(logout_token)

    async def start_link_user(self, options: dict, store_options: dict = None) -> str:
        """
        Initiates the user linking process.
        Options should include:
          - connection: connection identifier (e.g. 'google-oauth2')
          - connectionScope: (optional) the scope for the connection
          - authorizationParams: additional parameters for the /authorize call
          - appState: any custom state to track (e.g., a returnTo URL)
        Returns a URL to redirect the user to for linking.
        """
        return await self.client.start_link_user(options, store_options=store_options)

    async def complete_link_user(self, url: str, store_options: dict = None) -> dict:
        """
        Completes the user linking process.
        The provided URL should be the callback URL from Auth0.
        Returns a dictionary containing the original appState.
        """
        return await self.client.complete_link_user(url, store_options=store_options)

    async def start_unlink_user(self, options: dict, store_options: dict = None) -> str:
        """
        Initiates the user unlinking process.
        Options should include:
          - connection: connection identifier (e.g. 'google-oauth2')
          - authorizationParams: additional parameters for the /authorize call
          - appState: any custom state to track (e.g., a returnTo URL)
        Returns a URL to redirect the user to for unlinking.
        """
        return await self.client.start_unlink_user(options, store_options=store_options)

    async def complete_unlink_user(self, url: str, store_options: dict = None) -> dict:
        """
        Completes the user unlinking process.
        The provided URL should be the callback URL from Auth0.
        Returns a dictionary containing the original appState.
        """
        return await self.client.complete_unlink_user(url, store_options=store_options)

    async def require_session(self, request: Request, response: Response) -> dict:
        """
        Dependency method to ensure a session exists.
        Retrieves the session from the state store using the underlying client.
        If no session is found, raises an HTTP 401 error.
        """
        store_options = {"request": request, "response": response}
        session = await self.client.get_session(store_options=store_options)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Please log in")
        return session
