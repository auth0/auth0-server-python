from fastapi import Request, Response
from typing import Any, Dict, Optional

#Imported from auth0-server-python
from store.abstract import TransactionStore
from auth_types import TransactionData

class CookieTransactionStore(TransactionStore):
    """
    Transaction store implementation that uses a cookie to store transaction data.
    This store expects the FastAPI Request and Response objects to be provided in the
    store_options parameter.
    """
    def __init__(self, secret: str, cookie_name: str = "_a0_tx"):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name

    async def set(
        self, 
        identifier: str, 
        value: TransactionData, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Encrypts and stores the transaction data in a cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for cookie storage.")
        
        response: Response = options["response"]
    
        # Encrypt the transaction data using the abstract store method:
        encrypted_value = self.encrypt(identifier, value.dict())
        # Set cookie with a short max_age (e.g., 60 seconds for transactions)
        response.set_cookie(key=self.cookie_name, value=encrypted_value, path="/",samesite="Lax", secure=True, httponly=True, max_age=60)

    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Retrieves and parses the transaction data from the cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for cookie storage.")
        
        request: Request = options["request"]
        encrypted_value = request.cookies.get(self.cookie_name)
        if not encrypted_value:
            return None
        
        try:
            # Decrypt the stored value using the abstract store's decrypt method:
            decrypted_data = self.decrypt(identifier, encrypted_value)
            return TransactionData.parse_obj(decrypted_data)
        except Exception:
            return None

    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Deletes the transaction cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for cookie storage.")
        
        response: Response = options["response"]
        response.delete_cookie(key=self.cookie_name)
