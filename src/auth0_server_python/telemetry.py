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
    """Builds telemetry headers for Auth0 HTTP requests."""

    _PACKAGE_NAME = "auth0-server-python"

    def __init__(self, name: str, version: str, env: Optional[dict[str, str]] = None):
        self.name = name
        self.version = version
        self.env = env if env is not None else {"python": platform.python_version()}
        payload = {"name": self.name, "version": self.version, "env": self.env}
        self.headers: dict[str, str] = {
            "Auth0-Client": base64.b64encode(
                json.dumps(payload).encode("utf-8")
            ).decode("utf-8"),
            "User-Agent": f"Python/{platform.python_version()}",
        }

    @staticmethod
    def default() -> "Telemetry":
        """Create a Telemetry instance with this SDK's package metadata."""
        try:
            version = importlib.metadata.version(Telemetry._PACKAGE_NAME)
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
        return Telemetry(name=Telemetry._PACKAGE_NAME, version=version)
