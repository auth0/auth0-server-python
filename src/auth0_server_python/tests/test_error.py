"""Tests for the error module's typed exceptions."""

from auth0_server_python.error import (
    Auth0Error,
    EnterpriseConnectError,
    EnterpriseConnectErrorCode,
)

# === Enterprise Connect ===


def test_enterprise_connect_error_is_auth0_error():
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.NOT_SUPPORTED, "no session in enterprise connect mode"
    )
    assert isinstance(err, Auth0Error)


def test_enterprise_connect_error_sets_code_name_and_message():
    err = EnterpriseConnectError(EnterpriseConnectErrorCode.NOT_SUPPORTED, "not supported")
    assert err.code == EnterpriseConnectErrorCode.NOT_SUPPORTED
    assert err.name == "EnterpriseConnectError"
    assert err.message == "not supported"
    assert err.cause is None


def test_enterprise_connect_error_preserves_cause():
    cause = ValueError("boom")
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.NOT_SUPPORTED, "wrapped", cause=cause
    )
    assert err.cause is cause


def test_enterprise_connect_error_code_is_stable():
    assert EnterpriseConnectErrorCode.NOT_SUPPORTED == "enterprise_connect_not_supported"
