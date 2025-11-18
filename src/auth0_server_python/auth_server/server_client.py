"""
Main client for auth0-server-python SDK.
Handles authentication flows, token management, and user sessions.
"""

import asyncio
import json
import time
from typing import Any, Generic, Optional, TypeVar
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import jwt
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountOptions,
    ConnectAccountRequest,
    LogoutOptions,
    LogoutTokenClaims,
    StartInteractiveLoginOptions,
    StateData,
    TokenSet,
    TransactionData,
    UserClaims,
)
from auth0_server_python.error import (
    AccessTokenError,
    AccessTokenErrorCode,
    AccessTokenForConnectionError,
    AccessTokenForConnectionErrorCode,
    ApiError,
    BackchannelLogoutError,
    MissingRequiredArgumentError,
    MissingTransactionError,
    PollingApiError,
    StartLinkUserError,
)
from auth0_server_python.utils import PKCE, URL, State
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from pydantic import ValidationError

# Generic type for store options
TStoreOptions = TypeVar('TStoreOptions')
INTERNAL_AUTHORIZE_PARAMS = ["client_id", "redirect_uri", "response_type",
                             "code_challenge", "code_challenge_method", "state", "nonce", "scope"]


class ServerClient(Generic[TStoreOptions]):
    """
    Main client for Auth0 server SDK. Handles authentication flows, session management,
    and token operations using Authlib for OIDC functionality.
    """
    DEFAULT_AUDIENCE_STATE_KEY = "default"

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        redirect_uri: Optional[str] = None,
        secret: str = None,
        transaction_store=None,
        state_store=None,
        transaction_identifier: str = "_a0_tx",
        state_identifier: str = "_a0_session",
        authorization_params: Optional[dict[str, Any]] = None,
        pushed_authorization_requests: bool = False
    ):
        """
        Initialize the Auth0 server client.

        Args:
            domain: Auth0 domain (e.g., 'your-tenant.auth0.com')
            client_id: Auth0 client ID
            client_secret: Auth0 client secret
            redirect_uri: Default redirect URI for authentication
            secret: Secret used for encryption
            transaction_store: Custom transaction store (defaults to MemoryTransactionStore)
            state_store: Custom state store (defaults to MemoryStateStore)
            transaction_identifier: Identifier for transaction data
            state_identifier: Identifier for state data
            authorization_params: Default parameters for authorization requests
        """
        if not secret:
            raise MissingRequiredArgumentError("secret")

        # Store configuration
        self._domain = domain
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._default_authorization_params = authorization_params or {}
        self._pushed_authorization_requests = pushed_authorization_requests  # store the flag

        # Initialize stores
        self._transaction_store = transaction_store
        self._state_store = state_store
        self._transaction_identifier = transaction_identifier
        self._state_identifier = state_identifier

        # Initialize OAuth client
        self._oauth = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
        )

        self._my_account_client = MyAccountClient(domain=domain)

    async def _fetch_oidc_metadata(self, domain: str) -> dict:
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url)
            response.raise_for_status()
            return response.json()

    async def start_interactive_login(
        self,
        options: Optional[StartInteractiveLoginOptions] = None,
        store_options: dict = None
    ) -> str:
        """
        Starts the interactive login process and returns a URL to redirect to.

        Args:
            options: Configuration options for the login process

        Returns:
            Authorization URL to redirect the user to
        """
        options = options or StartInteractiveLoginOptions()

        # Get effective authorization params (merge defaults with provided ones)
        auth_params = dict(self._default_authorization_params)
        if options.authorization_params:
            auth_params.update(
                {k: v for k, v in options.authorization_params.items(
                ) if k not in INTERNAL_AUTHORIZE_PARAMS}
            )

        # Ensure we have a redirect_uri
        if "redirect_uri" not in auth_params and not self._redirect_uri:
            raise MissingRequiredArgumentError("redirect_uri")

        # Use the default redirect_uri if none is specified
        if "redirect_uri" not in auth_params and self._redirect_uri:
            auth_params["redirect_uri"] = self._redirect_uri

        # Generate PKCE code verifier and challenge
        code_verifier = PKCE.generate_code_verifier()
        code_challenge = PKCE.generate_code_challenge(code_verifier)

        # Add PKCE parameters to the authorization request
        auth_params["code_challenge"] = code_challenge
        auth_params["code_challenge_method"] = "S256"

        # State parameter to prevent CSRF
        state = PKCE.generate_random_string(32)
        auth_params["state"] = state

                #merge any requested scope with defaults
        requested_scope = options.authorization_params.get("scope", None) if options.authorization_params else None
        audience = auth_params.get("audience", None)
        merged_scope = self._merge_scope_with_defaults(requested_scope, audience)
        auth_params["scope"] = merged_scope

        # Build the transaction data to store
        transaction_data = TransactionData(
            code_verifier=code_verifier,
            app_state=options.app_state,
            audience=audience,
        )

        # Store the transaction data
        await self._transaction_store.set(
            f"{self._transaction_identifier}:{state}",
            transaction_data,
            options=store_options
        )
        try:
            self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)
        except Exception as e:
            raise ApiError("metadata_error",
                           "Failed to fetch OIDC metadata", e)
        # If PAR is enabled, use the PAR endpoint
        if self._pushed_authorization_requests:
            par_endpoint = self._oauth.metadata.get(
                "pushed_authorization_request_endpoint")
            if not par_endpoint:
                raise ApiError(
                    "configuration_error", "PAR is enabled but pushed_authorization_request_endpoint is missing in metadata")

            auth_params["client_id"] = self._client_id
            # Post the auth_params to the PAR endpoint
            async with httpx.AsyncClient() as client:
                par_response = await client.post(
                    par_endpoint,
                    data=auth_params,
                    auth=(self._client_id, self._client_secret)
                )
                if par_response.status_code not in (200, 201):
                    error_data = par_response.json()
                    raise ApiError(
                        error_data.get("error", "par_error"),
                        error_data.get(
                            "error_description", "Failed to obtain request_uri from PAR endpoint")
                    )
                par_data = par_response.json()
                request_uri = par_data.get("request_uri")
                if not request_uri:
                    raise ApiError(
                        "par_error", "No request_uri returned from PAR endpoint")

            auth_endpoint = self._oauth.metadata.get("authorization_endpoint")
            final_url = f"{auth_endpoint}?request_uri={request_uri}&response_type={auth_params['response_type']}&client_id={self._client_id}"
            return final_url
        else:
            if "authorization_endpoint" not in self._oauth.metadata:
                raise ApiError("configuration_error",
                               "Authorization endpoint missing in OIDC metadata")

            authorization_endpoint = self._oauth.metadata["authorization_endpoint"]

            try:
                auth_url, state = self._oauth.create_authorization_url(
                    authorization_endpoint, **auth_params)
            except Exception as e:
                raise ApiError("authorization_url_error",
                               "Failed to create authorization URL", e)

            return auth_url

    async def complete_interactive_login(
        self,
        url: str,
        store_options: dict = None
    ) -> dict[str, Any]:
        """
        Completes the login process after user is redirected back.

        Args:
            url: The full callback URL including query parameters
            store_options: Options to pass to the state store

        Returns:
            Dictionary containing session data and app state
        """
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Get state parameter from the URL
        state = query_params.get("state", [""])[0]
        if not state:
            raise MissingRequiredArgumentError("state")

        # Retrieve the transaction data using the state
        transaction_identifier = f"{self._transaction_identifier}:{state}"
        transaction_data = await self._transaction_store.get(transaction_identifier, options=store_options)

        if not transaction_data:
            raise MissingTransactionError()

        # Check for error response from Auth0
        if "error" in query_params:
            error = query_params.get("error", [""])[0]
            error_description = query_params.get("error_description", [""])[0]
            raise ApiError(error, error_description)

        # Get the authorization code from the URL
        code = query_params.get("code", [""])[0]
        if not code:
            raise MissingRequiredArgumentError("code")

        if not self._oauth.metadata or "token_endpoint" not in self._oauth.metadata:
            self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)

        # Exchange the code for tokens
        try:
            token_endpoint = self._oauth.metadata["token_endpoint"]
            token_response = await self._oauth.fetch_token(
                token_endpoint,
                code=code,
                code_verifier=transaction_data.code_verifier,
                redirect_uri=self._redirect_uri,
            )
        except OAuthError as e:
            # Raise a custom error (or handle it as appropriate)
            raise ApiError(
                "token_error", f"Token exchange failed: {str(e)}", e)

       # Use the userinfo field from the token_response for user claims
        user_info = token_response.get("userinfo")
        user_claims = None
        if user_info:
            user_claims = UserClaims.parse_obj(user_info)
        else:
            id_token = token_response.get("id_token")
            if id_token:
                claims = jwt.decode(id_token, options={
                                    "verify_signature": False})
                user_claims = UserClaims.parse_obj(claims)

        # Build a token set using the token response data
        token_set = TokenSet(
            audience=transaction_data.audience or self.DEFAULT_AUDIENCE_STATE_KEY,
            access_token=token_response.get("access_token", ""),
            scope=token_response.get("scope", ""),
            expires_at=int(time.time()) +
            token_response.get("expires_in", 3600)
        )

        # Generate a session id (sid) from token_response or transaction data, or create a new one
        sid = user_info.get(
            "sid") if user_info and "sid" in user_info else PKCE.generate_random_string(32)

        # Construct state data to represent the session
        state_data = StateData(
            user=user_claims,
            id_token=token_response.get("id_token"),
            # might be None if not provided
            refresh_token=token_response.get("refresh_token"),
            token_sets=[token_set],
            internal={
                "sid": sid,
                "created_at": int(time.time())
            }
        )

        # Store the state data in the state store using store_options (Response required)
        await self._state_store.set(self._state_identifier, state_data, options=store_options)

        # Clean up transaction data after successful login
        await self._transaction_store.delete(transaction_identifier, options=store_options)

        result = {"state_data": state_data.dict()}
        if transaction_data.app_state:
            result["app_state"] = transaction_data.app_state

        # For RAR
        authorization_details = token_response.get("authorization_details")
        if authorization_details:
            result["authorization_details"] = authorization_details

        return result

    async def start_link_user(
        self,
        options,
        store_options: Optional[dict[str, Any]] = None
    ):
        """
        Starts the user linking process, and returns a URL to redirect the user-agent to.

        Args:
            options: Options used to configure the user linking process.
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            URL to redirect the user to for authentication.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        if not state_data or not state_data.get("id_token"):
            raise StartLinkUserError(
                "Unable to start the user linking process without a logged in user. Ensure to login using the SDK before starting the user linking process."
            )

        # Generate PKCE and state for security
        code_verifier = PKCE.generate_code_verifier()
        state = PKCE.generate_random_string(32)

        # Build the URL for user linking
        link_user_url = await self._build_link_user_url(
            connection=options.get("connection"),
            connection_scope=options.get("connectionScope"),
            id_token=state_data["id_token"],
            code_verifier=code_verifier,
            state=state,
            authorization_params=options.get("authorization_params")
        )

        # Store transaction data
        transaction_data = TransactionData(
            code_verifier=code_verifier,
            app_state=options.get("app_state")
        )

        await self._transaction_store.set(
            f"{self._transaction_identifier}:{state}",
            transaction_data,
            options=store_options
        )

        return link_user_url

    async def complete_link_user(
        self,
        url: str,
        store_options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Completes the user linking process.

        Args:
            url: The URL from which the query params should be extracted
            store_options: Optional options for the stores

        Returns:
            Dictionary containing the original app state
        """

        # We can reuse the interactive login completion since the flow is similar
        result = await self.complete_interactive_login(url, store_options)

        # Return just the app state as specified
        return {
            "app_state": result.get("app_state")
        }

    async def start_unlink_user(
        self,
        options,
        store_options: Optional[dict[str, Any]] = None
    ):
        """
        Starts the user unlinking process, and returns a URL to redirect the user-agent to.

        Args:
            options: Options used to configure the user unlinking process.
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            URL to redirect the user to for authentication.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        if not state_data or not state_data.get("id_token"):
            raise StartLinkUserError(
                "Unable to start the user linking process without a logged in user. Ensure to login using the SDK before starting the user linking process."
            )

        # Generate PKCE and state for security
        code_verifier = PKCE.generate_code_verifier()
        state = PKCE.generate_random_string(32)

        # Build the URL for user linking
        link_user_url = await self._build_unlink_user_url(
            connection=options.get("connection"),
            id_token=state_data["id_token"],
            code_verifier=code_verifier,
            state=state,
            authorization_params=options.get("authorization_params")
        )

        # Store transaction data
        transaction_data = TransactionData(
            code_verifier=code_verifier,
            app_state=options.get("app_state")
        )

        await self._transaction_store.set(
            f"{self._transaction_identifier}:{state}",
            transaction_data,
            options=store_options
        )

        return link_user_url

    async def complete_unlink_user(
        self,
        url: str,
        store_options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Completes the user unlinking process.

        Args:
            url: The URL from which the query params should be extracted
            store_options: Optional options for the stores

        Returns:
            Dictionary containing the original app state
        """

        # We can reuse the interactive login completion since the flow is similar
        result = await self.complete_interactive_login(url, store_options)

        # Return just the app state as specified
        return {
            "app_state": result.get("app_state")
        }

    async def login_backchannel(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Logs in using Client-Initiated Backchannel Authentication.

        Note:
            Using Client-Initiated Backchannel Authentication requires the feature
            to be enabled in the Auth0 dashboard.

        See:
            https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow

        Args:
            options: Options used to configure the backchannel login process.
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            A dictionary containing the authorizationDetails (when RAR was used).
        """
        token_endpoint_response = await self.backchannel_authentication({
            "binding_message": options.get("binding_message"),
            "login_hint": options.get("login_hint"),
            "authorization_params": options.get("authorization_params"),
        })

        existing_state_data = await self._state_store.get(self._state_identifier, store_options)

        audience = self._default_authorization_params.get(
            "audience", self.DEFAULT_AUDIENCE_STATE_KEY)

        state_data = State.update_state_data(
            audience,
            existing_state_data,
            token_endpoint_response
        )

        await self._state_store.set(self._state_identifier, state_data, store_options)

        result = {
            "authorization_details": token_endpoint_response.get("authorization_details")
        }
        return result

    async def get_user(self, store_options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
        """
        Retrieves the user from the store, or None if no user found.

        Args:
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            The user, or None if no user found in the store.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        if state_data:
            if hasattr(state_data, "dict") and callable(state_data.dict):
                state_data = state_data.dict()
            return state_data.get("user")
        return None

    async def get_session(self, store_options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
        """
        Retrieve the user session from the store, or None if no session found.

        Args:
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            The session, or None if no session found in the store.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        if state_data:
            if hasattr(state_data, "dict") and callable(state_data.dict):
                state_data = state_data.dict()
            session_data = {k: v for k, v in state_data.items()
                            if k != "internal"}
            return session_data
        return None

    async def get_access_token(
        self,
        store_options: Optional[dict[str, Any]] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> str:
        """
        Retrieves the access token from the store, or calls Auth0 when the access token
        is expired and a refresh token is available in the store.
        Also updates the store when a new token was retrieved from Auth0.

        Args:
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            The access token, retrieved from the store or Auth0.

        Raises:
            AccessTokenError: If the token is expired and no refresh token is available.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        auth_params = self._default_authorization_params or {}

        # Get audience passed in on options or use defaults
        if not audience:
            audience = auth_params.get("audience", None)

        merged_scope = self._merge_scope_with_defaults(scope, audience)

        if state_data and hasattr(state_data, "dict") and callable(state_data.dict):
            state_data_dict = state_data.dict()
        else:
            state_data_dict = state_data or {}

        # Find matching token set
        token_set = None
        if state_data_dict and "token_sets" in state_data_dict:
            token_set = self._find_matching_token_set(state_data_dict["token_sets"], audience, merged_scope)

        # If token is valid, return it
        if token_set and token_set.get("expires_at", 0) > time.time():
            return token_set["access_token"]

        # Check for refresh token
        if not state_data_dict or not state_data_dict.get("refresh_token"):
            raise AccessTokenError(
                AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
                "The access token has expired and a refresh token was not provided. The user needs to re-authenticate."
            )

        # Get new token with refresh token
        try:
            get_refresh_token_options = {"refresh_token": state_data_dict["refresh_token"]}
            if audience:
                get_refresh_token_options["audience"] = audience

            if merged_scope:
                get_refresh_token_options["scope"] = merged_scope

            token_endpoint_response = await self.get_token_by_refresh_token(get_refresh_token_options)

            # Update state data with new token
            existing_state_data = await self._state_store.get(self._state_identifier, store_options)
            updated_state_data = State.update_state_data(
                audience, existing_state_data, token_endpoint_response)

            # Store updated state
            await self._state_store.set(self._state_identifier, updated_state_data, options=store_options)

            return token_endpoint_response["access_token"]
        except Exception as e:
            if isinstance(e, AccessTokenError):
                raise
            raise AccessTokenError(
                AccessTokenErrorCode.REFRESH_TOKEN_ERROR,
                f"Failed to get token with refresh token: {str(e)}"
            )

    def _merge_scope_with_defaults(
        self,
        request_scope: Optional[str],
        audience: Optional[str]
    ) -> Optional[str]:
        audience = audience or self.DEFAULT_AUDIENCE_STATE_KEY
        default_scopes = ""
        if self._default_authorization_params and "scope" in self._default_authorization_params:
            auth_param_scope = self._default_authorization_params.get("scope")
            # For backwards compatibility, allow scope to be a single string
            # or dictionary by audience for MRRT
            if isinstance(auth_param_scope, dict) and audience in auth_param_scope:
                default_scopes = auth_param_scope[audience]
            elif isinstance(auth_param_scope, str):
                default_scopes = auth_param_scope

        default_scopes_list = default_scopes.split()
        request_scopes_list = (request_scope or "").split()

        merged_scopes = list(dict.fromkeys(default_scopes_list + request_scopes_list))
        return " ".join(merged_scopes) if merged_scopes else None


    def _find_matching_token_set(
        self,
        token_sets: list[dict[str, Any]],
        audience: Optional[str],
        scope: Optional[str]
    ) -> Optional[dict[str, Any]]:
        audience = audience or self.DEFAULT_AUDIENCE_STATE_KEY
        requested_scopes = set(scope.split()) if scope else set()
        matches: list[tuple[int, dict]] = []
        for token_set in token_sets:
            token_set_audience = token_set.get("audience")
            token_set_scopes = set(token_set.get("scope", "").split())
            if token_set_audience == audience and token_set_scopes == requested_scopes:
                # short-circuit if exact match
                return token_set
            if token_set_audience == audience and token_set_scopes.issuperset(requested_scopes):
                # consider stored tokens with more scopes than requested by number of scopes
                matches.append((len(token_set_scopes), token_set))

        # Return the token set with the smallest superset of scopes that matches the requested audience and scopes
        return min(matches, key=lambda t: t[0])[1] if matches else None

    async def get_access_token_for_connection(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> str:
        """
        Retrieves an access token for a connection.

        This method attempts to obtain an access token for a specified connection.
        It first checks if a refresh token exists in the store.
        If no refresh token is found, it throws an `AccessTokenForConnectionError` indicating
        that the refresh token was not found.

        Args:
            options: Options for retrieving an access token for a connection.
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            The access token for the connection

        Raises:
            AccessTokenForConnectionError: If the access token was not found or
                there was an issue requesting the access token.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)

        if state_data and hasattr(state_data, "dict") and callable(state_data.dict):
            state_data_dict = state_data.dict()
        else:
            state_data_dict = state_data or {}

        # Find existing connection token
        connection_token_set = None
        if state_data_dict and len(state_data_dict["connection_token_sets"]) > 0:
            for ts in state_data_dict.get("connection_token_sets"):
                if ts.get("connection") == options["connection"]:
                    connection_token_set = ts
                    break

        # If token is valid, return it
        if connection_token_set and connection_token_set.get("expires_at", 0) > time.time():
            return connection_token_set["access_token"]

        # Check for refresh token
        if not state_data_dict or not state_data_dict.get("refresh_token"):
            raise AccessTokenForConnectionError(
                AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
                "A refresh token was not found but is required to be able to retrieve an access token for a connection."
            )
        # Get new token for connection
        token_endpoint_response = await self.get_token_for_connection({
            "connection": options.get("connection"),
            "login_hint": options.get("login_hint"),
            "refresh_token": state_data_dict["refresh_token"]
        })

        # Update state data with new token
        updated_state_data = State.update_state_data_for_connection_token_set(
            options, state_data_dict, token_endpoint_response)

        # Store updated state
        await self._state_store.set(self._state_identifier, updated_state_data, store_options)

        return token_endpoint_response["access_token"]

    async def logout(
        self,
        options: Optional[LogoutOptions] = None,
        store_options: Optional[dict[str, Any]] = None
    ) -> str:
        options = options or LogoutOptions()

        # Delete the session from the state store
        await self._state_store.delete(self._state_identifier, store_options)

        # Use the URL helper to create the logout URL.
        logout_url = URL.create_logout_url(
            self._domain, self._client_id, options.return_to)

        return logout_url

    async def handle_backchannel_logout(
        self,
        logout_token: str,
        store_options: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Handles backchannel logout requests.

        Args:
            logout_token: The logout token sent by Auth0
            store_options: Options to pass to the state store
        """
        if not logout_token:
            raise BackchannelLogoutError("Missing logout token")

        try:
            # Decode the token without verification
            claims = jwt.decode(logout_token, options={
                                "verify_signature": False})

            # Validate the token is a logout token
            events = claims.get("events", {})
            if "http://schemas.openid.net/event/backchannel-logout" not in events:
                raise BackchannelLogoutError(
                    "Invalid logout token: not a backchannel logout event")

            # Delete sessions associated with this token
            logout_claims = LogoutTokenClaims(
                sub=claims.get("sub"),
                sid=claims.get("sid")
            )

            await self._state_store.delete_by_logout_token(logout_claims.dict(), store_options)

        except (jwt.JoseError, ValidationError) as e:
            raise BackchannelLogoutError(
                f"Error processing logout token: {str(e)}")

    # Authlib Helpers

    async def _build_link_user_url(
        self,
        connection: str,
        id_token: str,
        code_verifier: str,
        state: str,
        connection_scope: Optional[str] = None,
        authorization_params: Optional[dict[str, Any]] = None
    ) -> str:
        """Build a URL for linking user accounts"""
        # Generate code challenge from verifier
        code_challenge = PKCE.generate_code_challenge(code_verifier)

        # Get metadata if not already fetched
        if not hasattr(self, '_oauth_metadata'):
            self._oauth_metadata = await self._fetch_oidc_metadata(self._domain)

        # Get authorization endpoint
        auth_endpoint = self._oauth_metadata.get("authorization_endpoint",
                                                 f"https://{self._domain}/authorize")

        # Build params
        params = {
            "client_id": self._client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "requested_connection": connection,
            "requested_connection_scope": connection_scope,
            "response_type": "code",
            "id_token_hint": id_token,
            "scope": "openid link_account",
            "audience": "my-account"
        }

        # Add connection scope if provided
        if connection_scope:
            params["requested_connection_scope"] = connection_scope

        # Add any additional parameters
        if authorization_params:
            params.update(authorization_params)
        return URL.build_url(auth_endpoint, params)

    async def _build_unlink_user_url(
        self,
        connection: str,
        id_token: str,
        code_verifier: str,
        state: str,
        authorization_params: Optional[dict[str, Any]] = None
    ) -> str:
        """Build a URL for unlinking user accounts"""
        # Generate code challenge from verifier
        code_challenge = PKCE.generate_code_challenge(code_verifier)

        # Get metadata if not already fetched
        if not hasattr(self, '_oauth_metadata'):
            self._oauth_metadata = await self._fetch_oidc_metadata(self._domain)

        # Get authorization endpoint
        auth_endpoint = self._oauth_metadata.get("authorization_endpoint",
                                                 f"https://{self._domain}/authorize")

        # Build params
        params = {
            "client_id": self._client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "requested_connection": connection,
            "response_type": "code",
            "id_token_hint": id_token,
            "scope": "openid unlink_account",
            "audience": "my-account"
        }
        # Add any additional parameters
        if authorization_params:
            params.update(authorization_params)

        return URL.build_url(auth_endpoint, params)

    async def backchannel_authentication(
        self,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Performs backchannel authentication with Auth0.

        This method starts a Client-Initiated Backchannel Authentication (CIBA) flow,
        which allows an application to request authentication from a user via a separate
        device or channel.

        Then polls the token endpoint until the user has authenticated or the request times out.

        Args:
            options (dict): Configuration options for backchannel authentication
                - login_hint (dict): Must contain a 'sub' field (e.g., {'sub': 'user_id'}).
                - binding_message (str, optional): Message to display to the user.
                - authorization_params (dict, optional): Additional authorization parameters.
                    - requested_expiry (int, optional): Requested expiry time in seconds, default is 30 secs.
                    - authorization_details (str, optional): JSON string for RAR.

        Returns:
            Token response data from the backchannel authentication

        Raises:
            ApiError: If the backchannel authentication fails
        """
        backchannel_data = await self.initiate_backchannel_authentication(options)
        auth_req_id = backchannel_data.get("auth_req_id")
        expires_in = backchannel_data.get(
            "expires_in", 120)  # Default to 2 minutes
        interval = backchannel_data.get(
            "interval", 5)  # Default to 5 seconds

        # Calculate when to stop polling
        end_time = time.time() + expires_in

        # Poll until we get a response or timeout
        while time.time() < end_time:
            # Make token request
            try:
                token_response = await self.backchannel_authentication_grant(auth_req_id)
                return token_response

            except Exception as e:
                if isinstance(e, PollingApiError):
                    if e.code == "authorization_pending":
                        # Wait for the specified interval before polling again
                        await asyncio.sleep(interval)
                        continue
                    if e.code == "slow_down":
                        # Wait for the specified interval before polling again
                        await asyncio.sleep(e.interval or interval)
                        continue
                raise ApiError(
                    "backchannel_error",
                    f"Backchannel authentication failed: {str(e) or 'Unknown error'}",
                    e
                )

        # If we get here, we've timed out
        raise ApiError(
            "timeout", "Backchannel authentication timed out")

    async def initiate_backchannel_authentication(
            self,
            options: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Start backchannel authentication with Auth0.

        This method starts a Client-Initiated Backchannel Authentication (CIBA) flow,
        which allows an application to request authentication from a user via a separate
        device or channel.

        Args:
            options (dict): Configuration options for backchannel authentication
                - login_hint (dict): Must contain a 'sub' field (e.g., {'sub': 'user_id'}).
                - binding_message (str, optional): Message to display to the user.
                - authorization_params (dict, optional): Additional authorization parameters.
                    - requested_expiry (int, optional): Requested expiry time in seconds, default is 30 secs.
                    - authorization_details (str, optional): JSON string for RAR.

        Returns:
            dict: Response data from the bc-authorize backchannel authentication
                - auth_req_id (str): The authentication request ID.
                - expires_in (int): Time in seconds until the request expires.
                - interval (int, optional): Polling interval in seconds.

        Raises:
            ApiError: If the backchannel authentication fails

        See:
            https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
        """

        sub = options.get('login_hint', {}).get("sub")
        if not sub:
            raise MissingRequiredArgumentError(
                "login_hint.sub"
            )

        authorization_params = options.get('authorization_params')
        if authorization_params is not None and not isinstance(authorization_params, dict):
            raise ApiError(
                "invalid_argument",
                "authorization_params must be a dict"
            )

        if authorization_params:
            requested_expiry = authorization_params.get("requested_expiry")
            if requested_expiry is not None:
                if not isinstance(requested_expiry, int) or requested_expiry <= 0:
                    raise ApiError(
                        "invalid_argument",
                        "authorization_params.requested_expiry must be a positive integer"
                    )

        try:
            # Fetch OpenID Connect metadata if not already fetched
            if not hasattr(self, '_oauth_metadata'):
                self._oauth_metadata = await self._fetch_oidc_metadata(self._domain)

            # Get the issuer from metadata
            issuer = self._oauth_metadata.get(
                "issuer") or f"https://{self._domain}/"

            # Get backchannel authentication endpoint
            backchannel_endpoint = self._oauth_metadata.get(
                "backchannel_authentication_endpoint")
            if not backchannel_endpoint:
                raise ApiError(
                    "configuration_error",
                    "Backchannel authentication is not supported by the authorization server"
                )

            # Prepare login hint in the required format
            login_hint = json.dumps({
                "format": "iss_sub",
                "iss": issuer,
                "sub": sub
            })

            # The Request Parameters
            params = {
                "client_id": self._client_id,
                "scope": "openid profile email",  # DEFAULT_SCOPES
                "login_hint": login_hint,
            }

            # Add binding message if provided
            if options.get('binding_message'):
                params["binding_message"] = options.get('binding_message')

            # Add any additional authorization parameters
            if self._default_authorization_params:
                params.update(self._default_authorization_params)

            if authorization_params:
                params.update(authorization_params)

            # Make the backchannel authentication request
            async with httpx.AsyncClient() as client:
                backchannel_response = await client.post(
                    backchannel_endpoint,
                    data=params,
                    auth=(self._client_id, self._client_secret)
                )

                if backchannel_response.status_code != 200:
                    error_data = backchannel_response.json()
                    raise ApiError(
                        error_data.get("error", "backchannel_error"),
                        error_data.get(
                            "error_description", "Backchannel authentication request failed")
                    )

                backchannel_data = backchannel_response.json()
                auth_req_id = backchannel_data.get("auth_req_id")

                if not auth_req_id:
                    raise ApiError(
                        "invalid_response",
                        "Missing auth_req_id in backchannel authentication response"
                    )

                return backchannel_data

        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(
                "backchannel_error",
                f"Backchannel authentication failed: {str(e) or 'Unknown error'}",
                e
            )

    async def backchannel_authentication_grant(self, auth_req_id: str) -> dict[str, Any]:
        """
        Retrieves a token by exchanging an auth_req_id.

        Args:
            auth_req_id (str): The authentication request ID obtained from bc-authorize

        Raises:
            AccessTokenError: If there was an issue requesting the access token.

        Returns:
            A dictionary containing the token response from Auth0.
        """
        if not auth_req_id:
            raise MissingRequiredArgumentError("auth_req_id")

        try:
            # Ensure we have the OIDC metadata
            if not hasattr(self._oauth, "metadata") or not self._oauth.metadata:
                self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)

            token_endpoint = self._oauth.metadata.get("token_endpoint")
            if not token_endpoint:
                raise ApiError("configuration_error",
                               "Token endpoint missing in OIDC metadata")

            # Prepare the token request parameters
            token_params = {
                "grant_type": "urn:openid:params:grant-type:ciba",
                "auth_req_id": auth_req_id,
                "client_id": self._client_id,
                "client_secret": self._client_secret
            }

            # Exchange the auth_req_id for an access token
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_endpoint,
                    data=token_params,
                    auth=(self._client_id, self._client_secret)
                )

                if response.status_code != 200:
                    error_data = response.json()
                    retry_after = response.headers.get("Retry-After")
                    interval = int(retry_after) if retry_after is not None else None
                    raise PollingApiError(
                        error_data.get("error", "auth_req_id_error"),
                        error_data.get("error_description",
                                       "Failed to exchange auth_req_id"),
                        interval
                    )

                try:
                    token_response = response.json()
                except json.JSONDecodeError:
                    raise ApiError(
                        "invalid_response",
                        "Failed to parse token response as JSON"
                    )

                # Add required fields if they are missing
                if "expires_in" in token_response and "expires_at" not in token_response:
                    token_response["expires_at"] = int(
                        time.time()) + token_response["expires_in"]

                return token_response

        except Exception as e:
            if isinstance(e, (ApiError, PollingApiError)):
                raise
            raise AccessTokenError(
                AccessTokenErrorCode.AUTH_REQ_ID_ERROR,
                "There was an error while trying to exchange the auth_req_id for an access token.",
                e
            )

    async def get_token_by_refresh_token(self, options: dict[str, Any]) -> dict[str, Any]:
        """
        Retrieves a token by exchanging a refresh token.

        Args:
            options: Dictionary containing the refresh token and any additional options.
                Must include a 'refresh_token' key.

        Raises:
            AccessTokenError: If there was an issue requesting the access token.

        Returns:
            A dictionary containing the token response from Auth0.
        """
        refresh_token = options.get("refresh_token")
        if not refresh_token:
            raise MissingRequiredArgumentError("refresh_token")

        try:
            # Ensure we have the OIDC metadata
            if not hasattr(self._oauth, "metadata") or not self._oauth.metadata:
                self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)

            token_endpoint = self._oauth.metadata.get("token_endpoint")
            if not token_endpoint:
                raise ApiError("configuration_error",
                               "Token endpoint missing in OIDC metadata")

            # Prepare the token request parameters
            token_params = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self._client_id,
            }

            audience = options.get("audience")
            if audience:
                token_params["audience"] = audience

            # Merge scope if present in options with any in the original authorization params
            merged_scope = self._merge_scope_with_defaults(
                request_scope=options.get("scope"),
                audience=audience
            )

            if merged_scope:
                token_params["scope"] = merged_scope

            # Exchange the refresh token for an access token
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_endpoint,
                    data=token_params,
                    auth=(self._client_id, self._client_secret)
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise ApiError(
                        error_data.get("error", "refresh_token_error"),
                        error_data.get("error_description",
                                       "Failed to exchange refresh token")
                    )

                token_response = response.json()

                # Add required fields if they are missing
                if "expires_in" in token_response and "expires_at" not in token_response:
                    token_response["expires_at"] = int(
                        time.time()) + token_response["expires_in"]

                return token_response

        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise AccessTokenError(
                AccessTokenErrorCode.REFRESH_TOKEN_ERROR,
                "The access token has expired and there was an error while trying to refresh it.",
                e
            )

    async def get_token_for_connection(self, options: dict[str, Any]) -> dict[str, Any]:
        """
        Retrieves a token for a connection.

        Args:
            options: Options for retrieving an access token for a connection.
                Must include 'connection' and 'refresh_token' keys.
                May optionally include 'login_hint'.

        Raises:
            AccessTokenForConnectionError: If there was an issue requesting the access token.

        Returns:
            Dictionary containing the token response with accessToken, expiresAt, and scope.
        """
        # Constants
        SUBJECT_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
        REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "http://auth0.com/oauth/token-type/federated-connection-access-token"
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
        try:
            # Ensure we have OIDC metadata
            if not hasattr(self._oauth, "metadata") or not self._oauth.metadata:
                self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)

            token_endpoint = self._oauth.metadata.get("token_endpoint")
            if not token_endpoint:
                raise ApiError("configuration_error",
                               "Token endpoint missing in OIDC metadata")

            # Prepare parameters
            params = {
                "connection": options["connection"],
                "subject_token_type": SUBJECT_TYPE_REFRESH_TOKEN,
                "subject_token": options["refresh_token"],
                "requested_token_type": REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
                "grant_type": GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
                "client_id": self._client_id
            }

            # Add login_hint if provided
            if "login_hint" in options and options["login_hint"]:
                params["login_hint"] = options["login_hint"]

            # Make the request
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_endpoint,
                    data=params,
                    auth=(self._client_id, self._client_secret)
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

        except Exception as e:
            if isinstance(e, ApiError):
                raise AccessTokenForConnectionError(
                    AccessTokenForConnectionErrorCode.API_ERROR,
                    str(e)
                )
            raise AccessTokenForConnectionError(
                AccessTokenForConnectionErrorCode.FETCH_ERROR,
                "There was an error while trying to retrieve an access token for a connection.",
                e
            )

    async def start_connect_account(
        self,
        options: ConnectAccountOptions,
        store_options: dict = None
    ) -> str:
        """
        Initiates the connect account flow for linking a third-party account to the user's profile.

        This method generates PKCE parameters, creates a transaction and calls the My Account API
        to create a connect account request, returning /connect url containing a ticket.

        Args:
            options: Options for retrieving an access token for a connection.
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            The a connect URL containing a ticket to redirect the user to.
        """
        # Use the default redirect_uri if none is specified
        redirect_uri = options.redirect_uri or self._redirect_uri
        # Ensure we have a redirect_uri
        if not redirect_uri:
            raise MissingRequiredArgumentError("redirect_uri")

        # Generate PKCE code verifier and challenge
        code_verifier = PKCE.generate_code_verifier()
        code_challenge = PKCE.generate_code_challenge(code_verifier)

        state= PKCE.generate_random_string(32)

        connect_request = ConnectAccountRequest(
            connection=options.connection,
            scopes=options.scopes,
            redirect_uri = redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            state=state,
            authorization_params=options.authorization_params
        )

        access_token = await self.get_access_token(
            audience=self._my_account_client.audience,
            scope="create:me:connected_accounts",
            store_options=store_options
        )
        connect_response = await self._my_account_client.connect_account(
            access_token=access_token,
            request=connect_request
        )

        # Build the transaction data to store
        transaction_data = TransactionData(
            code_verifier=code_verifier,
            app_state=options.app_state,
            auth_session=connect_response.auth_session,
            redirect_uri=redirect_uri
        )

        # Store the transaction data
        await self._transaction_store.set(
            f"{self._transaction_identifier}:{state}",
            transaction_data,
            options=store_options
        )

        parsedUrl = urlparse(connect_response.connect_uri)
        query = urlencode({"ticket": connect_response.connect_params.ticket})
        return urlunparse((parsedUrl.scheme, parsedUrl.netloc, parsedUrl.path, parsedUrl.params, query, parsedUrl.fragment))

    async def complete_connect_account(
        self,
        url: str,
        store_options: dict = None
    ) -> CompleteConnectAccountResponse:
        """
        Handles the redirect callback to complete the connect account flow for linking a third-party
        account to the user's profile.

        This works similar to the redirect from the login flow except it verifies the `connect_code`
        with the My Account API rather than the `code` with the Authorization Server.

        Args:
            url: The full callback URL including query parameters
            store_options: Optional options used to pass to the Transaction and State Store.

        Returns:
            A response from the connect account flow.
        """
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Get state parameter from the URL
        state = query_params.get("state", [""])[0]
        if not state:
            raise MissingRequiredArgumentError("state")

        # Get the authorization code from the URL
        connect_code = query_params.get("connect_code", [""])[0]
        if not connect_code:
            raise MissingRequiredArgumentError("connect_code")

        # Retrieve the transaction data using the state
        transaction_identifier = f"{self._transaction_identifier}:{state}"
        transaction_data = await self._transaction_store.get(transaction_identifier, options=store_options)

        if not transaction_data:
            raise MissingTransactionError()

        access_token = await self.get_access_token(
            audience=self._my_account_client.audience,
            scope="create:me:connected_accounts",
            store_options=store_options
        )

        request = CompleteConnectAccountRequest(
            auth_session=transaction_data.auth_session,
            connect_code=connect_code,
            redirect_uri=transaction_data.redirect_uri,
            code_verifier=transaction_data.code_verifier
        )
        try:
            response = await self._my_account_client.complete_connect_account(
                access_token=access_token, request=request)
            if transaction_data.app_state is not None:
                response.app_state = transaction_data.app_state
        finally:
            # Clean up transaction data
            await self._transaction_store.delete(transaction_identifier, options=store_options)

        return response
