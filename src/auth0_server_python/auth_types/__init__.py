"""
Type definitions for auth0-server-python SDK.
These Pydantic models provide type safety and validation for all SDK data structures.
"""

import warnings
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Upper bound (Unix seconds) for a plausible session_expiry
SESSION_EXPIRY_MAX_PLAUSIBLE = 10_000_000_000

# Type aliases using Literal types. Used to validate caller-supplied input.
# Server-controlled response fields use plain str instead, so a new factor or
# challenge type (e.g. a future webauthn second factor) does not fail closed.
OobChannel = Literal["sms", "voice", "auth0", "email"]
ChallengeType = Literal["otp", "oob"]
EnrollmentType = Literal["passkey", "email", "phone", "totp", "push-notification", "recovery-code", "password"]
PreferredAuthMethod = Literal["sms", "voice"]

# Deprecated public aliases resolved lazily (PEP 562) so access emits a warning
# while imports keep working. Remove in a future release.
_DEPRECATED_ALIASES = {
    "AuthenticatorType": (
        Literal["otp", "oob", "recovery-code"],
        "AuthenticatorType is deprecated and will be removed in a future release. "
        "AuthenticatorResponse.authenticator_type is now typed `str`; use `str` directly.",
    ),
}


def __getattr__(name: str):
    entry = _DEPRECATED_ALIASES.get(name)
    if entry is not None:
        value, message = entry
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    org_name: Optional[str] = None
    # IPSIE SL1 claim: upstream IdP-asserted RP session ceiling (Unix seconds).
    session_expiry: Optional[int] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model

    @field_validator('session_expiry', mode='before')
    @classmethod
    def _sanitize_session_expiry(cls, value: Any) -> Optional[int]:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        if value <= 0 or value >= SESSION_EXPIRY_MAX_PLAUSIBLE:
            return None
        return value


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
    # IPSIE session_expiry ceiling (Unix seconds), stamped at session creation
    # from the ID token's session_expiry claim. None when the upstream IdP did
    # not assert one — in which case existing session behavior is unchanged.
    session_expires_at: Optional[int] = None


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
    domain: Optional[str] = None

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
    auth_session: Optional[str] = None
    redirect_uri: Optional[str] = None
    domain: Optional[str] = None
    organization: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class LogoutTokenClaims(BaseModel):
    """
    Claims expected in a logout token.
    Used for backchannel logout processing.
    """

    sub: str
    sid: str
    iss: Optional[str] = None


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
    organization: Optional[str] = None


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
    organization: Optional[str] = None
    invitation: Optional[str] = None


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


# =============================================================================
# Multiple Custom Domain
# =============================================================================


class DomainResolverContext(BaseModel):
    """
    Context passed to domain resolver function for MCD support.

    Contains request information needed to determine the correct Auth0 domain
    based on the incoming request's hostname or headers.

    Attributes:
        request_url: The full request URL (e.g., "https://a.my-app.com/auth/login")
        request_headers: Dictionary of request headers (e.g., {"host": "a.my-app.com", "x-forwarded-host": "..."})

    Example:
        async def domain_resolver(context: DomainResolverContext) -> str:
            host = context.request_headers.get('host', '').split(':')[0]
            return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
    """

    request_url: Optional[str] = None
    request_headers: Optional[dict[str, str]] = None


# =============================================================================
# Custom Token Exchange Types
# =============================================================================


class CustomTokenExchangeOptions(BaseModel):
    """
    Options for custom token exchange (RFC 8693).

    Args:
        subject_token: The security token being exchanged
        subject_token_type: Identifier indicating the token format
        audience: Logical name of target service (optional)
        scope: Space-delimited list of scopes (optional)
        actor_token: Security token representing the acting party (optional)
        actor_token_type: Type of actor token (required if actor_token present)
        organization: Organization identifier for the token exchange (optional)
        authorization_params: Additional OAuth parameters (optional)
    """

    subject_token: str
    subject_token_type: str
    audience: Optional[str] = None
    scope: Optional[str] = None
    actor_token: Optional[str] = None
    actor_token_type: Optional[str] = None
    organization: Optional[str] = None
    authorization_params: Optional[dict[str, Any]] = None


class TokenExchangeResponse(BaseModel):
    """
    Response from token exchange operation.

    Attributes:
        access_token: The issued access token
        token_type: Token type (typically "Bearer")
        expires_in: Token lifetime in seconds
        scope: Granted scopes (if different from requested)
        issued_token_type: Format of issued token
        id_token: OpenID Connect ID token (optional)
        refresh_token: Refresh token (optional)
        act: Actor claim for delegation/impersonation exchanges (optional)
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None
    issued_token_type: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    act: Optional[dict[str, Any]] = None


class LoginWithCustomTokenExchangeOptions(BaseModel):
    """
    Options for logging in via custom token exchange.

    Combines token exchange parameters with session management.
    """

    subject_token: str
    subject_token_type: str
    audience: Optional[str] = None
    scope: Optional[str] = None
    actor_token: Optional[str] = None
    actor_token_type: Optional[str] = None
    organization: Optional[str] = None
    authorization_params: Optional[dict[str, Any]] = None


class LoginWithCustomTokenExchangeResult(BaseModel):
    """
    Result from login with custom token exchange.

    Contains session data established after token exchange.
    """

    state_data: dict[str, Any]
    authorization_details: Optional[list[AuthorizationDetails]] = None


class SessionTransferTokenResult(BaseModel):
    """
    Response from a session transfer token (STT) request.

    Attributes:
        session_transfer_token: The opaque, single-use session transfer token
        issued_token_type: Format of issued token (the session-transfer URN)
        expires_in: Token lifetime in seconds
        token_type: Token type as returned by the server (typically "N_A")
        scope: Granted scopes (if returned)
    """
    session_transfer_token: str
    issued_token_type: str
    expires_in: int
    token_type: Optional[str] = None
    scope: Optional[str] = None


# =============================================================================
# Connected Accounts Types
# =============================================================================


# BASE & SHARED
class ConnectedAccountBase(BaseModel):
    id: str
    connection: str
    access_type: str
    scopes: list[str]
    created_at: str
    expires_at: Optional[str] = None


# ENTITIES (What exists)
class ConnectedAccount(ConnectedAccountBase):
    id: str
    connection: str
    access_type: str
    scopes: list[str]
    created_at: str
    expires_at: Optional[str] = None


class ConnectedAccountConnection(BaseModel):
    name: str
    strategy: str
    scopes: Optional[list[str]] = None


# Connect Operations (How to connect)


class ConnectAccountOptions(BaseModel):
    connection: str
    redirect_uri: Optional[str] = None
    scopes: Optional[list[str]] = None
    app_state: Optional[Any] = None
    authorization_params: Optional[dict[str, Any]] = None


class ConnectAccountRequest(BaseModel):
    connection: str
    scopes: Optional[list[str]] = None
    redirect_uri: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = "S256"
    authorization_params: Optional[dict[str, Any]] = None


class ConnectParams(BaseModel):
    ticket: str


class ConnectAccountResponse(BaseModel):
    auth_session: str
    connect_uri: str
    connect_params: ConnectParams
    expires_in: int


class CompleteConnectAccountRequest(BaseModel):
    auth_session: str
    connect_code: str
    redirect_uri: str
    code_verifier: Optional[str] = None


class CompleteConnectAccountResponse(ConnectedAccountBase):
    app_state: Optional[Any] = None


# Manage operations
class ListConnectedAccountsResponse(BaseModel):
    accounts: list[ConnectedAccount]
    next: Optional[str] = None


class ListConnectedAccountConnectionsResponse(BaseModel):
    connections: list[ConnectedAccountConnection]
    next: Optional[str] = None


# =============================================================================
# MFA Types
# =============================================================================


class AuthenticatorResponse(BaseModel):
    """Represents an MFA authenticator enrolled by a user."""

    model_config = ConfigDict(extra="allow")
    id: str
    # Server-controlled value; kept as str so a new factor type (e.g. a future
    # webauthn second factor) does not fail closed when Auth0 adds it.
    authenticator_type: str
    active: bool
    name: Optional[str] = None
    oob_channel: Optional[OobChannel] = None
    type: Optional[str] = None
    phone_number: Optional[str] = None
    created_at: Optional[str] = None
    last_auth: Optional[str] = None


# Enrollment Options


class EnrollOtpOptions(BaseModel):
    """Options for enrolling an OTP authenticator."""

    authenticator_types: list[str]
    mfa_token: str


class EnrollOobOptions(BaseModel):
    """Options for enrolling an OOB authenticator (SMS, Voice, Push)."""

    authenticator_types: list[str]
    oob_channels: list[OobChannel]
    phone_number: Optional[str] = None
    mfa_token: str


class EnrollEmailOptions(BaseModel):
    """Options for enrolling an email authenticator."""

    authenticator_types: list[str]
    oob_channels: list[OobChannel]
    email: Optional[str] = None
    mfa_token: str


EnrollAuthenticatorOptions = Union[EnrollOtpOptions, EnrollOobOptions, EnrollEmailOptions]


# Enrollment Responses


class OtpEnrollmentResponse(BaseModel):
    """Response when enrolling an OTP authenticator."""

    authenticator_type: Literal["otp"]
    secret: str
    barcode_uri: str
    recovery_codes: Optional[list[str]] = None
    id: Optional[str] = None


class OobEnrollmentResponse(BaseModel):
    """Response when enrolling an OOB authenticator."""

    authenticator_type: Literal["oob"]
    oob_channel: OobChannel
    oob_code: Optional[str] = None
    barcode_uri: Optional[str] = None
    binding_method: Optional[str] = None
    recovery_codes: Optional[list[str]] = None
    id: Optional[str] = None


EnrollmentResponse = Union[OtpEnrollmentResponse, OobEnrollmentResponse]


# Challenge Types


class ChallengeOptions(BaseModel):
    """Options for initiating an MFA challenge."""

    challenge_type: ChallengeType
    authenticator_id: Optional[str] = None
    mfa_token: str


class ChallengeResponse(BaseModel):
    """Response from initiating an MFA challenge."""

    model_config = ConfigDict(extra="allow")
    # Server-controlled value; kept as str so a new challenge type does not fail
    # closed when Auth0 adds it.
    challenge_type: str
    oob_code: Optional[str] = None
    binding_method: Optional[str] = None
    expires_in: Optional[int] = None


# List Options


class ListAuthenticatorsOptions(BaseModel):
    """Options for listing MFA authenticators."""

    mfa_token: str


# Verify Types


class VerifyOtpOptions(BaseModel):
    """Verify with OTP code."""

    mfa_token: str
    otp: str


class VerifyOobOptions(BaseModel):
    """Verify with OOB code + binding code."""

    mfa_token: str
    oob_code: str
    binding_code: str


class VerifyRecoveryCodeOptions(BaseModel):
    """Verify with recovery code."""

    mfa_token: str
    recovery_code: str


VerifyMfaOptions = Union[VerifyOtpOptions, VerifyOobOptions, VerifyRecoveryCodeOptions]


class MfaVerifyResponse(BaseModel):
    """Response from MFA verification."""

    model_config = ConfigDict(extra="allow")
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    audience: Optional[str] = None
    recovery_code: Optional[str] = None


# MFA Requirements


class MfaRequirement(BaseModel):
    """A single MFA requirement entry."""

    type: str


class MfaRequirements(BaseModel):
    """MFA requirements from an mfa_required error response."""

    enroll: Optional[list[MfaRequirement]] = None
    challenge: Optional[list[MfaRequirement]] = None


# MFA Token Context (for encrypted storage)


class MfaTokenContext(BaseModel):
    """Internal context stored inside encrypted mfa_token."""

    mfa_token: str
    audience: str
    scope: str
    mfa_requirements: Optional[MfaRequirements] = None
    created_at: int


# =============================================================================
# Passkey & MyAccount Authentication Methods Types
# =============================================================================


class PasskeyLoginResult(BaseModel):
    """
    Result from signin_with_passkey.

    Contains the session data established after the webauthn token exchange.
    Mirrors LoginWithCustomTokenExchangeResult — passkey sign-in is a complete
    login ceremony and creates a server-side session like every other login path.
    """

    state_data: dict[str, Any]


class PasskeyRpInfo(BaseModel):
    id: str
    name: str


class PasskeyUserInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    name: str
    display_name: Optional[str] = Field(None, alias="displayName")


class PasskeyPubKeyCredParam(BaseModel):
    type: str
    alg: int


class PasskeyAuthenticatorSelection(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    resident_key: Optional[str] = Field(None, alias="residentKey")
    user_verification: Optional[str] = Field(None, alias="userVerification")


class PasskeyPublicKeyOptions(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    challenge: str
    rp: Optional[PasskeyRpInfo] = None
    rp_id: Optional[str] = Field(None, alias="rpId")
    user: Optional[PasskeyUserInfo] = None
    pub_key_cred_params: Optional[list[PasskeyPubKeyCredParam]] = Field(
        None, alias="pubKeyCredParams"
    )
    authenticator_selection: Optional[PasskeyAuthenticatorSelection] = Field(
        None, alias="authenticatorSelection"
    )
    timeout: Optional[int] = None
    user_verification: Optional[str] = Field(None, alias="userVerification")


class EnrollAuthenticationMethodRequest(BaseModel):
    type: EnrollmentType
    email: Optional[str] = None
    phone_number: Optional[str] = None
    preferred_authentication_method: Optional[PreferredAuthMethod] = None
    identity_user_id: Optional[str] = None  # OAS: IdentityAuthenticationMethodBase.identity_user_id
    connection: Optional[str] = None


class EnrollmentChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    authentication_method_id: str
    auth_session: str
    authn_params_public_key: Optional[PasskeyPublicKeyOptions] = None


class PasskeyAuthResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    raw_id: str = Field(alias="rawId")
    type: str
    authenticator_attachment: Optional[str] = Field(None, alias="authenticatorAttachment")
    response: dict[str, str]
    client_extension_results: Optional[dict[str, Any]] = Field(None, alias="clientExtensionResults")


class VerifyAuthenticationMethodRequest(BaseModel):
    auth_session: str
    authn_response: Optional[PasskeyAuthResponse] = None
    otp_code: Optional[str] = None
    recovery_code: Optional[str] = None
    password: Optional[str] = None


class AuthenticationMethod(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    created_at: str
    confirmed: Optional[bool] = None
    usage: Optional[list[str]] = None
    identity_user_id: Optional[str] = None
    credential_device_type: Optional[str] = None
    credential_backed_up: Optional[bool] = None
    key_id: Optional[str] = None
    public_key: Optional[str] = None
    transports: Optional[list[str]] = None
    user_agent: Optional[str] = None
    user_handle: Optional[str] = None
    aaguid: Optional[str] = None
    relying_party_id: Optional[str] = None
    phone_number: Optional[str] = None
    preferred_authentication_method: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    last_password_reset: Optional[str] = None


class UpdateAuthenticationMethodRequest(BaseModel):
    name: Optional[str] = None
    preferred_authentication_method: Optional[str] = None


class ListAuthenticationMethodsResponse(BaseModel):
    authentication_methods: list[AuthenticationMethod]


class Factor(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    usage: Optional[list[str]] = None


class GetFactorsResponse(BaseModel):
    factors: list[Factor]


class PasskeyUserProfile(BaseModel):
    model_config = ConfigDict(extra="allow")
    email: Optional[str] = None
    name: Optional[str] = None
    username: Optional[str] = None
    phone_number: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    nickname: Optional[str] = None
    picture: Optional[str] = None


class _PasskeyChallengeResponseBase(BaseModel):
    auth_session: str
    authn_params_public_key: PasskeyPublicKeyOptions


class PasskeySignupChallengeResponse(_PasskeyChallengeResponseBase):
    pass


class PasskeyLoginChallengeResponse(_PasskeyChallengeResponseBase):
    pass


class PasskeyTokenResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    expires_at: int
    scope: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
