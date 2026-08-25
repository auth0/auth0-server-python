"""Tests for the error module's typed exceptions."""

from auth0_server_python.error import (
    Auth0Error,
    EnterpriseConnectError,
    EnterpriseConnectErrorCode,
)

# === Enterprise Connect ===


def test_enterprise_connect_error_is_auth0_error():
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.SESSION_UNAVAILABLE, "no session in enterprise connect mode"
    )
    assert isinstance(err, Auth0Error)


def test_enterprise_connect_error_sets_code_name_and_message():
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.ACCESS_TOKEN_UNAVAILABLE, "no access token"
    )
    assert err.code == EnterpriseConnectErrorCode.ACCESS_TOKEN_UNAVAILABLE
    assert err.name == "EnterpriseConnectError"
    assert err.message == "no access token"
    assert err.cause is None


def test_enterprise_connect_error_preserves_cause():
    cause = ValueError("boom")
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.SESSION_UNAVAILABLE, "wrapped", cause=cause
    )
    assert err.cause is cause


def test_enterprise_connect_error_codes_are_stable():
    assert EnterpriseConnectErrorCode.SESSION_UNAVAILABLE == "enterprise_connect_session_unavailable"
    assert (
        EnterpriseConnectErrorCode.ACCESS_TOKEN_UNAVAILABLE
        == "enterprise_connect_access_token_unavailable"
    )
