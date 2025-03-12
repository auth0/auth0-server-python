import time
from typing import Dict, Any, Optional, Union

from .abstract import AbstractDataStore
from .abstract import StateStore
from .abstract import TransactionStore
from auth_types import StateData, TransactionData

class MemoryStore(AbstractDataStore):
    """Base class for in-memory data stores using a Python dictionary."""
    
    def __init__(self, options: Dict[str, Any]):
        """
        Initialize the memory store.
        
        Args:
            options: Configuration options including the encryption secret
        """
        super().__init__(options)
        self._data: Dict[str, str] = {}  # identifier -> encrypted data
    
    async def delete(self, identifier: str, options: Optional[Dict[str, Any]] = None) -> None:
        """
        Delete data by identifier.
        
        Args:
            identifier: Unique key for the stored data
            options: Additional operation-specific options
        """
        if identifier in self._data:
            del self._data[identifier]


class MemoryStateStore(MemoryStore, StateStore):
    """
    In-memory implementation of StateStore.
    Stores encrypted session data with configurable expiration.
    """
    
    def __init__(self, secret: str, absolute_duration: int = 259200):
        """
        Initialize the memory state store.
        
        Args:
            secret: Secret used for encryption
            absolute_duration: Time in seconds before data expires (default: 3 days)
        """
        super().__init__({"secret": secret})
        self._absolute_duration = absolute_duration
    
    async def set(
        self, 
        identifier: str, 
        state: Union[StateData, Dict[str, Any]],  
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store state data with the given identifier.
        
        Args:
            identifier: Unique key for the stored data
            state: StateData object or dictionary to store
            options: Additional operation-specific options
        """
        if hasattr(state, 'dict') and callable(state.dict):
            state_dict = state.dict()
        else:
            state_dict = state  # assume it's already a dictionary
        # Encrypt the state data before storing
        encrypted_value = self.encrypt(identifier, state_dict)
        
        # Store the encrypted data
        self._data[identifier] = encrypted_value
    
    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Union[StateData, Dict[str, Any]]]:
        """
        Retrieve state data by identifier.
        
        Args:
            identifier: Unique key for the stored data
            options: Additional operation-specific options
            
        Returns:
            StateData object, dictionary, or None if not found
        """
        # Get encrypted data from dictionary
        encrypted_value = self._data.get(identifier)
        
        if not encrypted_value:
            return None
        
        try:
            # Decrypt and convert back to StateData object (if required)
            decrypted_data = self.decrypt(identifier, encrypted_value)
            return decrypted_data
        except Exception:
            # If decryption fails (e.g., expired), remove the entry
            await self.delete(identifier)
            return None
    
    async def delete_by_logout_token(
        self, 
        claims: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete sessions based on logout token claims.
        
        Args:
            claims: Claims from the logout token, including sub and sid
            options: Additional operation-specific options
        """
        # For memory store, this would need to iterate through all entries
        # and check which ones match the subject/session ID in the claims
        sub = claims.get("sub")
        sid = claims.get("sid")
        
        if not sub or not sid:
            return
        
        # This is inefficient for large datasets but works for in-memory storage
        # Real implementations would use more efficient lookups
        to_delete = []
        
        for identifier, encrypted_value in self._data.items():
            try:
                data = await self.decrypt(identifier, encrypted_value)
                internal = data.get("internal", {})
                user = data.get("user", {})
                
                # Check if this session matches the logout token
                if internal.get("sid") == sid and user.get("sub") == sub:
                    to_delete.append(identifier)
            except Exception:
                # If we can't decrypt, we should remove it anyway
                to_delete.append(identifier)
        
        # Delete all matched sessions
        for identifier in to_delete:
            await self.delete(identifier)


class MemoryTransactionStore(MemoryStore, TransactionStore):
    """
    In-memory implementation of TransactionStore.
    Stores encrypted transaction data with a fixed short expiration time.
    """
    
    def __init__(self, secret: str):
        """
        Initialize the memory transaction store.
        
        Args:
            secret: Secret used for encryption
        """
        super().__init__({"secret": secret})
    
    async def set(
        self, 
        identifier: str, 
        value: TransactionData, 
        remove_if_expires: bool = False, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store transaction data with the given identifier.
        
        Args:
            identifier: Unique key for the stored data
            value: TransactionData object to store
            remove_if_expires: Whether to automatically remove on expiration
            options: Additional operation-specific options
        """
        # Fixed 60-second duration for transactions
        absolute_duration = 60  
        expiration = int(time.time()) + absolute_duration
        
        # Encrypt the transaction data before storing
        encrypted_value = await self.encrypt(identifier, value.dict(), expiration)
        
        # Store the encrypted data
        self._data[identifier] = encrypted_value
    
    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[TransactionData]:
        """
        Retrieve transaction data by identifier.
        
        Args:
            identifier: Unique key for the stored data
            options: Additional operation-specific options
            
        Returns:
            TransactionData object or None if not found
        """
        # Get encrypted data from dictionary
        encrypted_value = self._data.get(identifier)
        
        if not encrypted_value:
            return None
        
        try:
            # Decrypt and convert back to TransactionData object
            decrypted_data = await self.decrypt(identifier, encrypted_value)
            return TransactionData.parse_obj(decrypted_data)
        except Exception:
            # If decryption fails (e.g., expired), remove the entry
            await self.delete(identifier)
            return None