from typing import Any, Dict, Optional
from fastapi import Request, Response

#Imported from auth0-server-python
from store.abstract import StateStore
from auth_types import StateData

class StatefulStateStore(StateStore):
    """
    A state store implementation that persists session data in a backend store
    (for example, Redis or a database). It uses a cookie to keep track of the session ID.
    
    The underlying session store must implement asynchronous get, set, delete, and keys methods.
    """
    def __init__(self, secret: str, store: Any, cookie_name: str = "_a0_session", expiration: int = 259200):
        """
        :param secret: Secret for encryption (if needed)
        :param store: The persistent session store (e.g., a Redis client wrapper)
        :param cookie_name: Name of the cookie holding the session identifier
        :param expiration: Session expiration time in seconds
        """
        self.secret = secret
        self.store = store
        self.cookie_name = cookie_name
        self.expiration = expiration

    async def set(
        self, 
        identifier: str, 
        state: StateData, 
        remove_if_exists: bool = False, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Stores state data in the underlying session store and sets a cookie with the session ID.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateful storage.")
        
        response: Response = options["response"]
        # Store the JSON representation. In a real implementation, encrypt if needed.
        data = state.json()
        await self.store.set(identifier, data, expire=self.expiration)
        response.set_cookie(key=self.cookie_name, value=identifier, httponly=True, max_age=self.expiration)

    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[StateData]:
        """
        Retrieves state data from the underlying session store using the session cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for stateful storage.")
        
        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)
        if not session_id:
            return None
        
        data = await self.store.get(session_id)
        if not data:
            return None
        
        try:
            return StateData.parse_obj(data)
        except Exception:
            return None

    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Deletes state data from the session store and clears the session cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateful storage.")
        
        response: Response = options["response"]
        await self.store.delete(identifier)
        response.delete_cookie(key=self.cookie_name)
    
    async def delete_by_logout_token(
        self, 
        claims: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Iterates over the session store keys and deletes sessions matching the logout token claims.
        This method assumes the underlying store provides a 'keys' method.
        """
        # Example assumes the session store has an async keys() method.
        session_keys = await self.store.keys()
        for key in session_keys:
            data = await self.store.get(key)
            if data:
                try:
                    state = StateData.parse_raw(data)
                    internal = state.internal.dict() if state.internal else {}
                    user = state.user.dict() if state.user else {}
                    if internal.get("sid") == claims.get("sid") and user.get("sub") == claims.get("sub"):
                        await self.store.delete(key)
                except Exception:
                    await self.store.delete(key)
