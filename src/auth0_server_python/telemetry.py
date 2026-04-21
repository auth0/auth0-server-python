"""
Telemetry support for auth0-server-python SDK.

Builds and caches the Auth0-Client and User-Agent headers sent
on every HTTP request to Auth0 endpoints.
"""

import base64
import importlib.metadata
import json
import platform
from typing import Optional


class Telemetry:
    """Builds and caches telemetry headers for Auth0 HTTP requests."""

    _PACKAGE_NAME = "auth0-server-python"

    def __init__(self, name: str, version: str, env: Optional[dict[str, str]] = None):
        self.name = name
        self.version = version
        self.env = env if env is not None else {"python": platform.python_version()}
        self._cached_headers: Optional[dict[str, str]] = None

    def get_headers(self) -> dict[str, str]:
        """Return the telemetry headers, building and caching on first call."""
        if self._cached_headers is None:
            payload = {
                "name": self.name,
                "version": self.version,
                "env": self.env,
            }
            self._cached_headers = {
                "Auth0-Client": base64.b64encode(
                    json.dumps(payload).encode("utf-8")
                ).decode("utf-8"),
                "User-Agent": f"Python/{platform.python_version()}",
            }
        return self._cached_headers

    @staticmethod
    def default() -> "Telemetry":
        """Create a Telemetry instance with this SDK's package metadata."""
        try:
            version = importlib.metadata.version(Telemetry._PACKAGE_NAME)
        except Exception:
            version = "unknown"
        return Telemetry(name=Telemetry._PACKAGE_NAME, version=version)
