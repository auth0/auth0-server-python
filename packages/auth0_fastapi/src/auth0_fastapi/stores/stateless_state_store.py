from typing import Any, Dict, Optional, Union
from fastapi import Request, Response

#Imported from auth0-server-python
from auth0_server_python.store.abstract import StateStore
from auth0_server_python.auth_types import StateData

class StatelessStateStore(StateStore):
    """
    A stateless state store that encodes session data entirely in a cookie.
    The data is expected to be encrypted and tamper-proof.
    """
    def __init__(self, secret: str, cookie_name: str = "_a0_session", expiration: int = 259200):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.expiration = expiration
        self.max_cookie_size = 4096

        # Default cookie options similar to Fastify's cookie options
        self.cookie_options = {
            "httponly": True,
            "samesite": "lax",
            "path": "/",
            "secure": True,  # or set to "auto" if preferred
            "max_age": expiration,
        }

    async def set(
        self, 
        identifier: str, 
        state: Union[StateData, Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Stores state data in an encrypted cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateless storage.")
        
        response: Response = options["response"]
        if hasattr(state, 'dict') and callable(state.dict):
            state_dict = state.dict()
        else:
            state_dict = state  
        # Encrypt the transaction data using the abstract store method:
        encrypted_data = self.encrypt(identifier, state_dict)
        # Calculate chunk size, ensuring space for the key name and additional characters
        chunk_size = self.max_cookie_size - len(self.cookie_name) - 10
        cookies = {}
        # Split data into chunks and store in the response cookies
        for i in range(0, len(encrypted_data), chunk_size):
            chunk_name = f"{self.cookie_name}_{i // chunk_size}"
            chunk_value = encrypted_data[i:i + chunk_size]
            cookies[chunk_name] = chunk_value
            response.set_cookie(
                key=chunk_name, 
                value=chunk_value, 
                path="/", 
                httponly=True,
                secure=True, 
                samesite="Lax", 
                max_age= self.expiration
            )

    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Union[StateData, Dict[str, Any]]]:
        """
        Retrieves state data from the encrypted cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for stateless storage.")
        
        request = options["request"]

        session_parts = []
        # Extract all cookies that match cookie_prefix
        for key, value in request.cookies.items():
            if key.startswith(self.cookie_name):
                index = int(key.split("_")[-1])
                session_parts.append((index, value))
        if not session_parts:
            return ""
 
        session_parts.sort()  # Sort by index

        full_encoded_data = "".join(part[1] for part in session_parts)
        if not full_encoded_data:
            return None
        try:
            # Decrypt the stored value using the abstract store's decrypt method:
            decrypted_data = self.decrypt(identifier, full_encoded_data)
            return decrypted_data
        except Exception:
            return None
        
    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Deletes the state cookie and its chunks.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateless storage.")
        
        response: Response = options["response"]
        # Delete the base cookie if it exists
        response.delete_cookie(key=self.cookie_name)
        
        # Delete potential cookie chunks (assume a max number of chunks, e.g., 20)
        for i in range(20):
            chunk_key = f"{self.cookie_name}_{i}"
            response.delete_cookie(key=chunk_key)
