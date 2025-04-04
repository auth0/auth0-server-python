from pydantic import BaseModel, AnyUrl, Field
from typing import Optional, Dict, Any

class Auth0Config(BaseModel):
    """
    Configuration settings for the FastAPI SDK integrating auth0-server-python.
    """
    domain: str
    client_id: str = Field(..., alias="clientId")
    client_secret: str = Field(..., alias="clientSecret")
    app_base_url: AnyUrl = Field(..., alias="appBaseUrl", description="Base URL of your application (e.g., https://example.com)")
    secret: str = Field(..., description="Secret used for encryption and signing cookies")
    audience: Optional[str] = Field(None, description="Target audience for tokens (if applicable)")
    authorization_params: Optional[Dict[str, Any]] = Field(None, description="Additional parameters to include in the authorization request")
    pushed_authorization_requests: bool = Field(False, description="Whether to use pushed authorization requests")
    # Route-mounting flags with desired defaults
    mount_routes: bool = Field(True, description="Controls /auth/* routes: login, logout, callback, backchannel-logout")
    mount_connect_routes: bool = Field(False, description="Controls /auth/connect routes (account-linking)")
    #Cookie Settings
    cookie_name: str = Field("_a0_session", description="Name of the cookie storing session data")
    session_expiration: int = Field(259200, description="Session expiration time in seconds (default: 3 days)")

    class Config:
        populate_by_name = True
