import base64
import importlib.metadata
import json
import platform
from unittest.mock import AsyncMock, patch

import pytest

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.telemetry import Telemetry


class TestTelemetry:
    """Tests for the Telemetry class."""

    def test_headers_contains_expected_keys(self):
        telemetry = Telemetry(name="test-sdk", version="1.0.0")
        assert "Auth0-Client" in telemetry.headers
        assert "User-Agent" in telemetry.headers

    def test_auth0_client_header_format(self):
        telemetry = Telemetry(
            name="auth0-server-python",
            version="1.0.0b9",
            env={"python": "3.10.16"},
        )
        decoded = json.loads(base64.b64decode(telemetry.headers["Auth0-Client"]))
        assert decoded == {
            "name": "auth0-server-python",
            "version": "1.0.0b9",
            "env": {"python": "3.10.16"},
        }

    def test_user_agent_header(self):
        telemetry = Telemetry(name="test-sdk", version="1.0.0")
        assert telemetry.headers["User-Agent"] == f"Python/{platform.python_version()}"

    def test_default_env_uses_python_version(self):
        telemetry = Telemetry(name="test-sdk", version="1.0.0")
        assert telemetry.env == {"python": platform.python_version()}

    def test_custom_env_override(self):
        telemetry = Telemetry(
            name="test-sdk", version="1.0.0", env={"python": "3.9.0", "framework": "fastapi"}
        )
        decoded = json.loads(base64.b64decode(telemetry.headers["Auth0-Client"]))
        assert decoded["env"] == {"python": "3.9.0", "framework": "fastapi"}

    def test_default_factory(self):
        telemetry = Telemetry.default()
        assert telemetry.name == "auth0-server-python"
        assert telemetry.version != ""
        assert "python" in telemetry.env

    @patch(
        "auth0_server_python.telemetry.importlib.metadata.version",
        side_effect=importlib.metadata.PackageNotFoundError("not installed"),
    )
    def test_default_factory_unknown_version_on_error(self, _mock):
        telemetry = Telemetry.default()
        assert telemetry.version == "unknown"


class TestServerClientTelemetry:
    """Tests that ServerClient injects telemetry headers into HTTP requests."""

    def _make_client(self):
        return ServerClient(
            domain="auth0.local",
            client_id="client_id",
            client_secret="client_secret",
            secret="test-secret",
            state_store=AsyncMock(),
            transaction_store=AsyncMock(),
        )

    def test_server_client_has_telemetry_headers(self):
        client = self._make_client()
        assert client._telemetry_headers is not None
        assert "Auth0-Client" in client._telemetry_headers
        assert "User-Agent" in client._telemetry_headers

    def test_server_client_telemetry_payload_structure(self):
        client = self._make_client()
        decoded = json.loads(base64.b64decode(client._telemetry_headers["Auth0-Client"]))
        assert decoded["name"] == "auth0-server-python"
        assert "version" in decoded
        assert "python" in decoded["env"]

    @pytest.mark.asyncio
    async def test_get_http_client_includes_telemetry_headers(self):
        client = self._make_client()
        http_client = client._get_http_client()
        for key, value in client._telemetry_headers.items():
            assert http_client.headers.get(key) == value
        await http_client.aclose()

    @pytest.mark.asyncio
    async def test_get_http_client_per_request_headers_do_not_override_telemetry(self):
        client = self._make_client()
        http_client = client._get_http_client(headers={"User-Agent": "custom", "X-Custom": "val"})
        # Telemetry headers must win over caller-provided duplicates
        assert http_client.headers.get("User-Agent") == client._telemetry_headers["User-Agent"]
        assert http_client.headers.get("Auth0-Client") == client._telemetry_headers["Auth0-Client"]
        # Non-conflicting caller headers are preserved
        assert http_client.headers.get("X-Custom") == "val"
        await http_client.aclose()

    def test_my_account_client_receives_telemetry_headers(self):
        client = self._make_client()
        assert client._my_account_client._headers == client._telemetry_headers

    def test_mfa_client_receives_telemetry_headers(self):
        client = self._make_client()
        assert client._mfa_client._headers == client._telemetry_headers

    @pytest.mark.asyncio
    async def test_fetch_oidc_metadata_sends_telemetry(self):
        client = self._make_client()
        http_client = client._get_http_client()
        # Verify the client that _fetch_oidc_metadata would use has telemetry headers
        for key, value in client._telemetry_headers.items():
            assert http_client.headers.get(key) == value
        await http_client.aclose()

    def test_oauth_client_receives_telemetry_headers(self):
        client = self._make_client()
        # AsyncOAuth2Client stores headers passed at construction on its session
        oauth_headers = client._oauth.headers
        for key, value in client._telemetry_headers.items():
            assert oauth_headers.get(key) == value
