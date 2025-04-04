from fastapi import APIRouter, Request, Response, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse
from typing import Optional
from ..auth.auth_client import AuthClient
from ..config import Auth0Config  
from ..util import to_safe_redirect, create_route_url, merge_set_cookie_headers

router = APIRouter()

def get_auth_client(request: Request) -> AuthClient:
    """
    Dependency function to retrieve the AuthClient instance.
    Assumes the client is set on the FastAPI application state.
    """
    auth_client = request.app.state.auth_client
    if not auth_client:
        raise HTTPException(status_code=500, detail="Authentication client not configured.")
    return auth_client

def register_auth_routes(router: APIRouter, config: Auth0Config):
    """
    Conditionally register auth routes based on config.mount_routes and config.mount_connect_routes.
    """
    if config.mount_routes:
        @router.get("/auth/login")
        async def login(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            """
            Endpoint to initiate the login process.
            Optionally accepts a 'return_to' query parameter and passes it as part of the app state.
            Redirects the user to the Auth0 authorization URL.
            """
        
            return_to: Optional[str] = request.query_params.get("returnTo")
            auth_url = await auth_client.start_login( 
                app_state={"returnTo": return_to} if return_to else None,
                store_options={"response": response}
            )

            redirect_response = RedirectResponse(url=auth_url)

            return merge_set_cookie_headers(response, redirect_response)

        @router.get("/auth/callback")
        async def callback(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            """
            Endpoint to handle the callback after Auth0 authentication.
            Processes the callback URL and completes the login flow.
            Redirects the user to a post-login URL based on appState or a default.
            """
            full_callback_url = str(request.url)
            try:
                session_data = await auth_client.complete_login(full_callback_url, store_options={"request": request, "response": response})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            
            # Extract the returnTo URL from the appState if available.
            return_to = session_data.get("app_state", {}).get("returnTo")
            
            default_redirect = auth_client.config.app_base_url  # Assuming config is stored on app.state
            
            redirect_response = RedirectResponse(url=return_to or default_redirect)

            return merge_set_cookie_headers(response, redirect_response)

        @router.get("/auth/logout")
        async def logout(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            """
            Endpoint to handle logout.
            Clears the session cookie (if applicable) and generates a logout URL,
            then redirects the user to Auth0's logout endpoint.
            """
            return_to: Optional[str] = request.query_params.get("returnTo")
            try:
                default_redirect = str(auth_client.config.app_base_url)
                logout_url = await auth_client.logout(return_to=return_to or default_redirect, store_options={"response": response})
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
            
            redirect_response = RedirectResponse(url=logout_url)
                    
            return merge_set_cookie_headers(response, redirect_response)

        @router.post("/auth/backchannel-logout")
        async def backchannel_logout(request: Request, auth_client: AuthClient = Depends(get_auth_client)):
            """
            Endpoint to process backchannel logout notifications.
            Expects a JSON body with a 'logout_token'.
            Returns 204 No Content on success.
            """
            body = await request.json()
            logout_token = body.get("logout_token")
            if not logout_token:
                raise HTTPException(status_code=400, detail="Missing 'logout_token' in request body.")
            
            try:
                await auth_client.handle_backchannel_logout(logout_token)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            return Response(status_code=204)
        
        #################### Testing Route (Won't be there in the Fastify SDKs) ###################################
        @router.get("/auth/profile")
        async def profile(request: Request, response:Response, auth_client: AuthClient = Depends(get_auth_client)):
            # Prepare store_options with the Request object (used by the state store to read cookies)
            store_options = {"request": request, "response": response}
            try:
                # Retrieve user information and session data from the state store
                user = await auth_client.client.get_user(store_options=store_options)
                session = await auth_client.client.get_session(store_options=store_options)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            
            return {
                "user": user,
                "session": session
            }


        @router.get("/auth/token")
        async def get_token(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            # Prepare store_options with the Request object (used by the state store to read cookies)
            store_options = {"request": request, "response": response}
            try:
                # Retrieve access token from the client
                access_token = await auth_client.client.get_access_token(store_options=store_options)
                
                return {
                    "access_token_available": bool(access_token),
                    "access_token_preview": access_token[:10] + "..." if access_token else None,
                    "status": "success"
                }
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))


        @router.get("/auth/connection/{connection_name}")
        async def get_connection_token(
            connection_name: str,
            request: Request, 
            response: Response, 
            auth_client: AuthClient = Depends(get_auth_client),
            login_hint: Optional[str] = None
        ):
            store_options = {"request": request, "response": response}
            
            try:
                # Create connection options as a dictionary
                connection_options = {
                    "connection": connection_name
                }
                
                # Add login_hint if provided
                if login_hint:
                    connection_options["login_hint"] = login_hint
                    
                # Retrieve connection-specific access token
                access_token = await auth_client.client.get_access_token_for_connection(
                    connection_options, 
                    store_options=store_options
                )
                
                # Return a response with token information
                return {
                    "connection": connection_name,
                    "access_token_available": bool(access_token),
                    "access_token_preview": access_token[:10] + "..." if access_token else None,
                    "status": "success"
                }
            except Exception as e:
                # Handle all errors with a single exception handler
                raise HTTPException(status_code=400, detail=str(e))
        #################### ********Testing Routes End ****** ###################################
        
    if config.mount_connect_routes:

        @router.get("/auth/connect")
        async def connect(request: Request, response: Response,  
            connection: Optional[str] = Query(None),
            connectionScope: Optional[str] = Query(None),
            returnTo: Optional[str] = Query(None),
            auth_client: AuthClient = Depends(get_auth_client)):

            # Extract query parameters (connection, connectionScope, returnTo)
            connection = connection or request.query_params.get("connection")
            connection_scope = connectionScope or request.query_params.get("connectionScope")
            dangerous_return_to = returnTo or request.query_params.get("returnTo")


            if not connection:
                raise HTTPException(
                    status_code=400,
                    detail="connection is not set"
                )
            
            sanitized_return_to = to_safe_redirect(dangerous_return_to or "/", auth_client.config.app_base_url)
            
            # Create the callback URL for linking
            callback_path = "/auth/connect/callback"
            redirect_uri = create_route_url(callback_path, auth_client.config.app_base_url)
            
            # Call the startLinkUser method on our AuthClient. This method should accept parameters similar to:
            # connection, connectionScope, authorizationParams (with redirect_uri), and app_state.
            link_user_url = await auth_client.start_link_user({
                "connection": connection,
                "connectionScope": connection_scope,
                "authorization_params": {
                    "redirect_uri": str(redirect_uri)
                },
                "app_state": {
                    "returnTo": sanitized_return_to
                }
            }, store_options={"request": request, "response": response})

            redirect_response = RedirectResponse(url=link_user_url)
            
            return merge_set_cookie_headers(response, redirect_response)

        @router.get("/auth/connect/callback")
        async def connect_callback(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            # Use the full URL from the callback
            callback_url = str(request.url)
            try:
                result = await auth_client.complete_link_user(callback_url, store_options={"request": request, "response": response})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            
            # Retrieve the returnTo parameter from app_state if available
            return_to = result.get("app_state", {}).get("returnTo")

            app_base_url = auth_client.config.app_base_url

            redirect_response = RedirectResponse(url=return_to or app_base_url)
            if "set-cookie" in response.headers:
                cookies = response.headers.getlist("set-cookie") if hasattr(response.headers, "getlist") else [response.headers["set-cookie"]]
                for cookie in cookies:
                    redirect_response.headers.append("set-cookie", cookie)
            return redirect_response
        
        @router.get("/auth/unconnect")
        async def connect(request: Request, response: Response,  
            connection: Optional[str] = Query(None),
            connectionScope: Optional[str] = Query(None),
            returnTo: Optional[str] = Query(None),
            auth_client: AuthClient = Depends(get_auth_client)):

            # Extract query parameters (connection, connectionScope, returnTo)
            connection = connection or request.query_params.get("connection")
            dangerous_return_to = returnTo or request.query_params.get("returnTo")


            if not connection:
                raise HTTPException(
                    status_code=400,
                    detail="connection is not set"
                )
            
            sanitized_return_to = to_safe_redirect(dangerous_return_to or "/", auth_client.config.app_base_url)
            
            # Create the callback URL for linking
            callback_path = "/auth/unconnect/callback"
            redirect_uri = create_route_url(callback_path, auth_client.config.app_base_url)
            
            # Call the startLinkUser method on our AuthClient. This method should accept parameters similar to:
            # connection, connectionScope, authorizationParams (with redirect_uri), and app_state.
            link_user_url = await auth_client.start_unlink_user({
                "connection": connection,
                "authorization_params": {
                    "redirect_uri": str(redirect_uri)
                },
                "app_state": {
                    "returnTo": sanitized_return_to
                }
            }, store_options={"request": request, "response": response})

            redirect_response = RedirectResponse(url=link_user_url)
            
            return merge_set_cookie_headers(response, redirect_response)

        @router.get("/auth/unconnect/callback")
        async def unconnect_callback(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
            # Use the full URL from the callback
            callback_url = str(request.url)
            try:
                result = await auth_client.complete_unlink_user(callback_url, store_options={"request": request, "response": response})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            
            # Retrieve the returnTo parameter from appState if available
            return_to = result.get("app_state", {}).get("returnTo")

            app_base_url = auth_client.config.app_base_url

            redirect_response = RedirectResponse(url=return_to or app_base_url)

            return merge_set_cookie_headers(response, redirect_response)

