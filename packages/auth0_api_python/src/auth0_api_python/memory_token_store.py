from typing import Any, Optional


class MemoryTokenStore:
    """A simple async in-memory store for tokens, keyed by connection name."""
    def __init__(self):
        self._store: dict[str, dict[str, Any]] = {}

    async def get(self, key: str) -> Optional[dict[str, Any]]:
        return self._store.get(key)

    async def set(self, key: str, value: dict[str, Any]) -> None:
        self._store[key] = value

    async def delete(self, key: str) -> None:
        if key in self._store:
            del self._store[key]
