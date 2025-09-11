from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, TypeVar

from auth0_server_python.encryption import decrypt, encrypt

T = TypeVar('T')  # Generic type for the data stored

class AbstractDataStore(Generic[T], ABC):
    """
    Abstract base class for data stores.
    Provides common functionality for different store implementations.
    """

    def __init__(self, options: dict[str, Any]):
        """
        Initialize the data store with options.

        Args:
            options: Configuration options including encryption secret
        """
        self._options = options

    @abstractmethod
    async def set(self, identifier: str, state: T, remove_if_expires: bool = False, options: Optional[dict[str, Any]] = None) -> None:
        """
        Store data with the given identifier.

        Args:
            identifier: Unique key for the stored data
            state: Data to store
            remove_if_expires: Whether to auto-remove expired data
            options: Additional operation-specific options
        """
        pass

    @abstractmethod
    async def get(self, identifier: str, options: Optional[dict[str, Any]] = None) -> Optional[T]:
        """
        Retrieve data by identifier.

        Args:
            identifier: Unique key for the stored data
            options: Additional operation-specific options

        Returns:
            The stored data or None if not found
        """
        pass

    @abstractmethod
    async def delete(self, identifier: str, options: Optional[dict[str, Any]] = None) -> None:
        """
        Delete data by identifier.

        Args:
            identifier: Unique key for the stored data
            options: Additional operation-specific options
        """
        pass

    def encrypt(self, identifier: str, state_data: dict[str, Any]) -> T:
        """
        Encrypt data before storing.

        Args:
            identifier: Unique key used as part of encryption salt
            state_data: Data to encrypt

        Returns:
            Encrypted string representation of the data
        """
        return encrypt(state_data, self._options.get("secret"), identifier)

    def decrypt(self, identifier: str, encrypted_data: str) -> T:
        """
        Decrypt data after retrieval.

        Args:
            identifier: Unique key used as part of encryption salt
            encrypted_data: Encrypted data to decrypt

        Returns:
            Decrypted data
        """
        return decrypt(encrypted_data, self._options.get("secret"), identifier)


class StateStore(AbstractDataStore[dict[str, Any]]):
    """
    Abstract store for persistent session data.
    Extends AbstractDataStore with logout token functionality.
    """

    async def delete_by_logout_token(self, claims: dict[str, Any], options: Optional[dict[str, Any]] = None) -> None:
        """
        Delete sessions based on logout token claims.

        Args:
            claims: Claims from the logout token
            options: Additional operation-specific options

        Note:
            Default implementation throws NotImplementedError.
            Concrete implementations should override this method.
        """
        raise NotImplementedError("Method not implemented.")


class TransactionStore(AbstractDataStore[dict[str, Any]]):
    """
    Abstract store for temporary transaction data during auth flows.
    """
    pass
