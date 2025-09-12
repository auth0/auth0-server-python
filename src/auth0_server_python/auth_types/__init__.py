"""
Type definitions for auth0-server-python SDK.
These Pydantic models provide type safety and validation for all SDK data structures.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class UserClaims(BaseModel):
    """
    User profile information as returned by Auth0.
    Contains standard OIDC claims about the authenticated user.
    """
    sub: str
    name: Optional[str] = None
    nickname: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    picture: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    org_id: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class TokenSet(BaseModel):
    """
    Represents a set of tokens issued by Auth0.
    Contains the access token and related metadata.
    """
    audience: str
    access_token: str
    scope: Optional[str] = None
    expires_at: int


class ConnectionTokenSet(TokenSet):
    """
    Token set specific to a connection.
    Extends TokenSet with connection-specific information.
    """
    connection: str
    login_hint: str


class InternalStateData(BaseModel):
    """
    Internal data used for managing state.
    Not meant to be accessed directly by SDK users.
    """
    sid: str
    created_at: int


class SessionData(BaseModel):
    """
    Represents a user session with Auth0.
    Contains user information and tokens.
    """
    user: Optional[UserClaims] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_sets: list[TokenSet] = Field(default_factory=list)
    connection_token_sets: list[ConnectionTokenSet] = Field(default_factory=list)

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class StateData(SessionData):
    """
    Complete state data stored in the state store.
    Extends SessionData with internal management information.
    """
    internal: InternalStateData


class TransactionData(BaseModel):
    """
    Represents data for an in-progress authentication transaction.
    Used during the authorization code flow to correlate requests.
    """
    audience: Optional[str] = None
    code_verifier: str
    app_state: Optional[Any] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class LogoutTokenClaims(BaseModel):
    """
    Claims expected in a logout token.
    Used for backchannel logout processing.
    """
    sub: str
    sid: str


class EncryptedStoreOptions(BaseModel):
    """
    Options for encrypted stores.
    Contains the secret used for encryption.
    """
    secret: str


class ServerClientOptionsBase(BaseModel):
    """
    Base options for configuring the Auth0 server client.
    Contains core settings required for all clients.
    """
    domain: str
    client_id: str
    client_secret: str
    client_assertion_signing_key: Optional[str] = None
    client_assertion_signing_alg: Optional[str] = None
    authorization_params: Optional[dict[str, Any]] = Field(default_factory=dict)
    transaction_identifier: Optional[str] = "_a0_tx"
    state_identifier: Optional[str] = "_a0_session"
    custom_fetch: Optional[Any] = None  # Function type hint would be more complex


class ServerClientOptionsWithSecret(ServerClientOptionsBase):
    """
    Client options using a secret for encryption.
    Extends base options with secret and duration settings.
    """
    secret: str
    state_absolute_duration: Optional[int] = 259200  # 3 days in seconds


class StartInteractiveLoginOptions(BaseModel):
    """
    Options for starting the interactive login process.
    Configures how the authorization request is constructed.
    """
    pushed_authorization_requests: Optional[bool] = False
    app_state: Optional[Any] = None
    authorization_params: Optional[dict[str, Any]] = None


class LogoutOptions(BaseModel):
    """
    Options for logout operations.
    Configures how the logout request is constructed.
    """
    return_to: Optional[str] = None


class AuthorizationParameters(BaseModel):
    """
    Parameters used in authorization requests.
    Based on standard OAuth2/OIDC parameters.
    """
    scope: Optional[str] = None
    audience: Optional[str] = None
    redirect_uri: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional OAuth parameters

class AuthorizationDetails(BaseModel):
    """
    Authorization details returned from Auth0.
    Used for Resource Access Rights (RAR).
    """
    type: str
    actions: Optional[list[str]] = None
    locations: Optional[list[str]] = None
    datatypes: Optional[list[str]] = None
    identifier: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class LoginBackchannelOptions(BaseModel):
    """
    Options for Client-Initiated Backchannel Authentication.
    """
    binding_message: str
    login_hint: dict[str, str]  # Should contain a 'sub' field
    authorization_params: Optional[dict[str, Any]] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class LoginBackchannelResult(BaseModel):
    """
    Result from Client-Initiated Backchannel Authentication.
    """
    authorization_details: Optional[list[AuthorizationDetails]] = None


class AccessTokenForConnectionOptions(BaseModel):
    """
    Options for retrieving an access token for a specific connection.
    """
    connection: str
    login_hint: Optional[str] = None

class StartLinkUserOptions(BaseModel):
    connection: str
    connection_scope: Optional[str] = None
    authorization_params: Optional[dict[str, Any]] = None
    app_state: Optional[Any] = None
